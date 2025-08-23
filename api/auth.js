// api/auth.js - Updated Authentication Handler with Persistent Database
import crypto from 'crypto';
import { getDatabase } from '../lib/database.js';

// RSA Public Key for admin validation (replace with your actual key)
const ADMIN_RSA_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Dojkpn9uLlpJGfMnKJ/
G8DNP0F4uq78lrbCnZvKWFQmf3Mj3LoRWZPga9MYmSvfIbLJmaL/PMslxbDyXvI7
CIGCwPtZVqeE6S6UJ/EeD0EpJCNetWUOPOZ/Vqo+WrY/TaXQix/IzFNKXMj0Ul43
shU/BWM5lnPoxGtu2g0Z3hmhqDeHFQKG23V68K7d1xHhJkmlCVkSgQs+Oe/rkAHL
4g7vd1ViJ33dF4wKiWLKTmvcYOJXbNPE/RXwvb48qtPWoy2R1E0Jg52KNEUG2hDx
wmWRcyAv2bALB5G0EANaYQCieOethyykts2o7rV7fy6jtxE+HoiGE0kLAmlbsoHc
wQIDAQAB
-----END PUBLIC KEY-----`;

// Allowed MAC addresses for admin access (replace with actual MAC addresses)
const ALLOWED_ADMIN_MAC_ADDRESSES = [
    '00:11:22:33:44:55', // Replace with your actual admin MAC addresses
    '66:77:88:99:aa:bb'
];

// Helper Functions
const generateApiKey = () => {
    return 'ak_' + crypto.randomBytes(32).toString('hex');
};

const hashPassword = (password) => {
    return crypto.createHash('sha256').update(password).digest('hex');
};

const generateSessionId = () => {
    return crypto.randomBytes(24).toString('hex');
};

const isUserExpired = (user) => {
    // CRITICAL: If user is permanent (or permanent field is undefined/null), NEVER expire
    if (user.permanent !== false) {
        return false;
    }
    
    // Only check expiration for explicitly non-permanent users
    if (user.expiresAt && new Date() > new Date(user.expiresAt)) {
        return true;
    }
    
    return false;
};

// Verify RSA signature for admin access
const verifyRSASignature = (challenge, signature) => {
    try {
        const publicKey = crypto.createPublicKey({
            key: ADMIN_RSA_PUBLIC_KEY,
            format: 'pem',
            type: 'spki'
        });
        
        const isValid = crypto.verify(
            'sha256',
            Buffer.from(challenge),
            publicKey,
            Buffer.from(signature, 'base64')
        );
        
        return isValid;
    } catch (error) {
        console.error('RSA verification error:', error);
        return false;
    }
};

export default async function handler(req, res) {
    const db = getDatabase();
    
    // Clean expired users periodically (only non-permanent ones)
    db.cleanExpiredUsers();
    
    const { method } = req;
    const { action } = req.query;
    
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
    if (method === 'OPTIONS') {
        return res.status(200).end();
    }
    
    try {
        switch (action) {
            case 'login':
                return await handleLogin(req, res, db);
            case 'validate-api-key':
                return await handleValidateApiKey(req, res, db);
            case 'admin-validate':
                return await handleAdminValidate(req, res, db);
            case 'admin-data':
                return await handleAdminData(req, res, db);
            case 'admin-add-user':
                return await handleAdminAddUser(req, res, db);
            case 'admin-remove-user':
                return await handleAdminRemoveUser(req, res, db);
            case 'admin-approve-user':
                return await handleAdminApproveUser(req, res, db);
            case 'admin-set-permanent':
                return await handleAdminSetPermanent(req, res, db);
            case 'admin-refresh-user':
                return await handleAdminRefreshUser(req, res, db);
            default:
                return res.status(404).json({
                    success: false,
                    message: 'Action not found'
                });
        }
    } catch (error) {
        console.error('API Error:', error);
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
}

async function handleLogin(req, res, db) {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }
    
    const { username, password, deviceInfo } = req.body;
    
    if (!username || !password || !deviceInfo) {
        return res.status(400).json({
            success: false,
            message: 'Missing required fields'
        });
    }
    
    const hashedPassword = hashPassword(password);
    const user = db.findUser(username);
    
    if (!user || user.password !== hashedPassword) {
        // Log failed login attempt
        db.addLoginHistory({
            username,
            deviceInfo,
            success: false,
            reason: 'Invalid credentials'
        });
        
        return res.status(401).json({
            success: false,
            message: 'Invalid credentials'
        });
    }
    
    // CRITICAL: Check if user is expired (only for non-permanent users)
    if (isUserExpired(user)) {
        db.addLoginHistory({
            username,
            deviceInfo,
            success: false,
            reason: 'Account expired'
        });
        
        return res.status(401).json({
            success: false,
            message: 'User account has expired. Contact administrator.'
        });
    }
    
    if (!user.approved) {
        db.addLoginHistory({
            username,
            deviceInfo,
            success: false,
            reason: 'Account not approved'
        });
        
        return res.status(403).json({
            success: false,
            message: 'Account not approved. Contact administrator.'
        });
    }
    
    // For trial accounts that are NOT permanent, enforce device limit
    if (user.accessType === 'trial' && user.permanent === false) {
        const trialSessions = Array.from(db.activeSessions.values())
            .filter(session => session.username === username);
        
        if (trialSessions.length >= 1) {
            db.addLoginHistory({
                username,
                deviceInfo,
                success: false,
                reason: 'Trial device limit reached'
            });
            
            return res.status(403).json({
                success: false,
                message: 'Trial account limit reached. Only one device allowed.'
            });
        }
    }
    
    // Create session
    const sessionId = generateSessionId();
    db.activeSessions.set(sessionId, {
        username: user.username,
        accessType: user.accessType,
        permanent: user.permanent !== false,
        deviceInfo: deviceInfo,
        loginTime: new Date().toISOString(),
        lastActivity: new Date().toISOString()
    });
    
    // Log successful login
    db.addLoginHistory({
        username: user.username,
        deviceInfo: deviceInfo,
        success: true
    });
    
    return res.status(200).json({
        success: true,
        message: 'Login successful',
        data: {
            username: user.username,
            accessType: user.accessType,
            permanent: user.permanent !== false,
            sessionId: sessionId
        }
    });
}

async function handleValidateApiKey(req, res, db) {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }
    
    const { apiKey } = req.body;
    
    if (!apiKey) {
        return res.status(400).json({
            success: false,
            message: 'API key required'
        });
    }
    
    const keyData = db.findApiKey(apiKey);
    
    if (!keyData) {
        return res.status(401).json({
            success: false,
            message: 'Invalid API key'
        });
    }
    
    const user = db.findUser(keyData.username);
    
    if (!user) {
        return res.status(401).json({
            success: false,
            message: 'User not found'
        });
    }
    
    // CRITICAL: Check if user is expired (only for non-permanent users)
    if (isUserExpired(user)) {
        return res.status(401).json({
            success: false,
            message: 'User account has expired'
        });
    }
    
    if (!user.approved) {
        return res.status(403).json({
            success: false,
            message: 'Account not approved'
        });
    }
    
    return res.status(200).json({
        success: true,
        message: 'API key valid',
        data: {
            username: user.username,
            accessType: user.accessType,
            permanent: user.permanent !== false
        }
    });
}

async function handleAdminValidate(req, res, db) {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }
    
    const { challenge, signature, macAddresses } = req.body;
    
    if (!challenge || !signature || !macAddresses) {
        return res.status(400).json({
            success: false,
            message: 'Missing required fields'
        });
    }
    
    // Verify RSA signature
    if (!verifyRSASignature(challenge, signature)) {
        return res.status(403).json({
            success: false,
            message: 'Invalid RSA signature'
        });
    }
    
    // Check if device MAC addresses are authorized
    const hasAuthorizedMac = macAddresses.some(mac => 
        ALLOWED_ADMIN_MAC_ADDRESSES.includes(mac.toLowerCase())
    );
    
    if (!hasAuthorizedMac) {
        return res.status(403).json({
            success: false,
            message: 'Unauthorized device. MAC address not in allowed list.'
        });
    }
    
    return res.status(200).json({
        success: true,
        message: 'Admin access granted'
    });
}

async function handleAdminData(req, res, db) {
    if (req.method !== 'GET') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }
    
    return res.status(200).json({
        success: true,
        data: db.getAllData()
    });
}

async function handleAdminAddUser(req, res, db) {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }
    
    const { username, password, accessType, permanent = true, expiresAt = null } = req.body;
    
    if (!username || !password || !accessType) {
        return res.status(400).json({
            success: false,
            message: 'Missing required fields'
        });
    }
    
    if (!['trial', 'unlimited', 'admin'].includes(accessType)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid access type'
        });
    }
    
    const existingUser = db.findUser(username);
    if (existingUser) {
        return res.status(409).json({
            success: false,
            message: 'User already exists'
        });
    }
    
    const hashedPassword = hashPassword(password);
    
    const newUser = {
        username,
        password: hashedPassword,
        accessType,
        approved: false,
        permanent: permanent !== false, // CRITICAL: Default to true unless explicitly false
        expiresAt: permanent !== false ? null : expiresAt, // Only set expiration for non-permanent users
        createdAt: new Date().toISOString()
    };
    
    db.addUser(newUser);
    
    return res.status(201).json({
        success: true,
        message: `User "${username}" created successfully ${permanent !== false ? '(permanent)' : '(temporary)'}`
    });
}

async function handleAdminRemoveUser(req, res, db) {
    if (req.method !== 'DELETE') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }
    
    const { username } = req.body;
    
    if (!username) {
        return res.status(400).json({
            success: false,
            message: 'Username required'
        });
    }
    
    const removed = db.removeUser(username);
    
    if (!removed) {
        return res.status(404).json({
            success: false,
            message: 'User not found'
        });
    }
    
    // Remove active sessions
    for (const [sessionId, session] of db.activeSessions.entries()) {
        if (session.username === username) {
            db.activeSessions.delete(sessionId);
        }
    }
    
    return res.status(200).json({
        success: true,
        message: `User "${username}" removed successfully`
    });
}

async function handleAdminApproveUser(req, res, db) {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }
    
    const { username } = req.body;
    
    if (!username) {
        return res.status(400).json({
            success: false,
            message: 'Username required'
        });
    }
    
    const user = db.findUser(username);
    
    if (!user) {
        return res.status(404).json({
            success: false,
            message: 'User not found'
        });
    }
    
    // Update user approval status
    db.updateUser(username, { approved: true });
    
    // Generate API key
    const apiKey = generateApiKey();
    const apiKeyData = {
        apiKey,
        username: user.username
    };
    
    db.addApiKey(apiKeyData);
    
    return res.status(200).json({
        success: true,
        message: `User "${username}" approved successfully`,
        data: {
            apiKey: apiKey
        }
    });
}

async function handleAdminSetPermanent(req, res, db) {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }
    
    const { username } = req.body;
    
    if (!username) {
        return res.status(400).json({
            success: false,
            message: 'Username required'
        });
    }
    
    const user = db.findUser(username);
    
    if (!user) {
        return res.status(404).json({
            success: false,
            message: 'User not found'
        });
    }
    
    // CRITICAL: Set user as permanent and remove expiration
    db.updateUser(username, { 
        permanent: true, 
        expiresAt: null 
    });
    
    return res.status(200).json({
        success: true,
        message: `User "${username}" set as permanent and will never expire`
    });
}

async function handleAdminRefreshUser(req, res, db) {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }
    
    const { username } = req.body;
    
    if (!username) {
        return res.status(400).json({
            success: false,
            message: 'Username required'
        });
    }
    
    const user = db.findUser(username);
    
    if (!user) {
        return res.status(404).json({
            success: false,
            message: 'User not found'
        });
    }
    
    // For non-permanent users, extend expiration by 30 days
    if (user.permanent === false && user.expiresAt) {
        const newExpiration = new Date();
        newExpiration.setDate(newExpiration.getDate() + 30);
        db.updateUser(username, { expiresAt: newExpiration.toISOString() });
    }
    
    // Update session activity
    for (const [sessionId, session] of db.activeSessions.entries()) {
        if (session.username === username) {
            session.lastActivity = new Date().toISOString();
        }
    }
    
    return res.status(200).json({
        success: true,
        message: `User "${username}" session refreshed successfully`
    });
}
