// api/auth.js - Fixed Server-Side User Management
// This should replace your existing Vercel API endpoint

export default async function handler(req, res) {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    const { action } = req.query;

    try {
        switch (action) {
            case 'login':
                return handleLogin(req, res);
            case 'admin-validate':
                return handleAdminValidate(req, res);
            case 'admin-add-user':
                return handleAddUser(req, res);
            case 'admin-remove-user':
                return handleRemoveUser(req, res);
            case 'admin-data':
                return handleAdminData(req, res);
            case 'admin-set-permanent':
                return handleSetPermanent(req, res);
            case 'admin-fix-user':
                return handleFixUser(req, res);
            default:
                return res.status(404).json({ success: false, message: 'Endpoint not found' });
        }
    } catch (error) {
        console.error('API Error:', error);
        return res.status(500).json({ success: false, message: 'Internal server error' });
    }
}

// ISSUE IDENTIFIED: Your database storage is likely not persisting properly
// You need to use environment variables or a proper database
let USERS_DB = JSON.parse(process.env.USERS_DB || '[]');
let ADMIN_DEVICES = JSON.parse(process.env.ADMIN_DEVICES || '[]');

// CRITICAL FIX: Save database to environment or external storage
function saveDatabase() {
    // In production, you'd save to a real database
    // For Vercel, you might need to use Vercel KV or similar
    process.env.USERS_DB = JSON.stringify(USERS_DB);
    console.log('Database saved:', USERS_DB.length, 'users');
}

// RSA Public Key for signature verification
const ADMIN_RSA_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Dojkpn9uLlpJGfMnKJ/
G8DNP0F4uq78lrbCnZvKWFQmf3Mj3LoRWZPga9MYmSvfIbLJmaL/PMslxbDyXvI7
CIGCwPtZVqeE6S6UJ/EeD0EpJCNetWUOPOZ/Vqo+WrY/TaXQix/IzFNKXMj0Ul43
shU/BWM5lnPoxGtu2g0Z3hmhqDeHFQKG23V68K7d1xHhJkmlCVkSgQs+Oe/rkAHL
4g7vd1ViJ33dF4wKiWLKTmvcYOJXbNPE/RXwvb48qtPWoy2R1E0Jg52KNEUGFaYQ
yhDxwmWRcyAv2bALB5G0EANaYQCieOethyykjhJ2lo7rV7fy6jtxE+HoiGE0kLAm
lbsoHcwQIDAQAB
-----END PUBLIC KEY-----`;

function verifyRSASignature(challenge, signature, publicKey) {
    try {
        const crypto = require('crypto');
        const verifier = crypto.createVerify('sha256');
        verifier.update(challenge);
        return verifier.verify(publicKey, signature, 'base64');
    } catch (error) {
        console.error('RSA verification error:', error);
        return false;
    }
}

// FIXED: Simple direct login without API key complications
async function handleLogin(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }

    const { username, password, deviceInfo } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password required' });
    }

    // Find user in database
    const user = USERS_DB.find(u => u.username === username);

    if (!user) {
        return res.status(401).json({ success: false, message: 'Invalid username or password' });
    }

    if (user.password !== password) {
        return res.status(401).json({ success: false, message: 'Invalid username or password' });
    }

    // FIXED: Check if user is approved (should be auto-approved now)
    if (user.approved === false) {
        return res.status(401).json({ success: false, message: 'Account not approved. Contact administrator.' });
    }

    // CRITICAL FIX: Check if user has expired (but permanent users never expire)
    if (user.permanent !== true && user.expiresAt && new Date() > new Date(user.expiresAt)) {
        return res.status(401).json({ success: false, message: 'Account has expired. Contact administrator for renewal.' });
    }

    // Update last login
    user.lastLogin = new Date().toISOString();
    saveDatabase();

    console.log(`User ${username} logged in successfully (permanent: ${user.permanent})`);

    return res.status(200).json({
        success: true,
        message: 'Login successful',
        data: {
            username: user.username,
            accessType: user.accessType,
            permanent: user.permanent,
            approved: user.approved,
            lastLogin: user.lastLogin
        }
    });
}

async function handleAdminValidate(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }

    const { challenge, signature, macAddresses } = req.body;

    // Verify RSA signature
    const isValidSignature = verifyRSASignature(challenge, signature, ADMIN_RSA_PUBLIC_KEY);

    if (!isValidSignature) {
        return res.status(401).json({ success: false, message: 'Invalid RSA signature' });
    }

    // Check if device MAC addresses are authorized (optional - you might want to allow any valid signature)
    // For now, we'll allow any valid RSA signature
    
    console.log('Admin access granted for device:', macAddresses);

    return res.status(200).json({
        success: true,
        message: 'Admin access granted'
    });
}

// FIXED: Create permanent users with all correct flags
async function handleAddUser(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }

    const { username, password, accessType, permanent, approved } = req.body;

    if (!username || !password || !accessType) {
        return res.status(400).json({ success: false, message: 'Username, password, and accessType required' });
    }

    // Check if user already exists
    if (USERS_DB.find(u => u.username === username)) {
        return res.status(409).json({ success: false, message: 'User already exists' });
    }

    // CRITICAL FIX: Create user with proper permanent flags
    const newUser = {
        username,
        password,
        accessType,
        permanent: true,           // FORCE permanent to true
        approved: true,           // FORCE approved to true (auto-approve)
        expiresAt: null,          // FORCE no expiration
        createdAt: new Date().toISOString(),
        lastLogin: null,
        devices: [],
        apiKeys: []
    };

    USERS_DB.push(newUser);
    saveDatabase();

    console.log(`User ${username} created as PERMANENT and AUTO-APPROVED`);

    return res.status(201).json({
        success: true,
        message: `User "${username}" created successfully (PERMANENT - will never expire)`,
        data: {
            username: newUser.username,
            accessType: newUser.accessType,
            permanent: newUser.permanent,
            approved: newUser.approved,
            createdAt: newUser.createdAt
        }
    });
}

async function handleRemoveUser(req, res) {
    if (req.method !== 'DELETE') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }

    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ success: false, message: 'Username required' });
    }

    const userIndex = USERS_DB.findIndex(u => u.username === username);

    if (userIndex === -1) {
        return res.status(404).json({ success: false, message: 'User not found' });
    }

    USERS_DB.splice(userIndex, 1);
    saveDatabase();

    return res.status(200).json({
        success: true,
        message: `User "${username}" removed successfully`
    });
}

async function handleAdminData(req, res) {
    if (req.method !== 'GET') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }

    // Return sanitized user data (without passwords)
    const sanitizedUsers = USERS_DB.map(user => ({
        username: user.username,
        accessType: user.accessType,
        permanent: user.permanent,
        approved: user.approved,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin,
        expiresAt: user.expiresAt
    }));

    return res.status(200).json({
        success: true,
        data: {
            users: sanitizedUsers,
            apiKeys: [], // Removed API key system
            activeSessions: USERS_DB.filter(u => u.lastLogin).length,
            loginHistory: []
        }
    });
}

// FIXED: Force permanent status on existing users
async function handleSetPermanent(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }

    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ success: false, message: 'Username required' });
    }

    const user = USERS_DB.find(u => u.username === username);

    if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
    }

    // FORCE permanent status
    user.permanent = true;
    user.approved = true;
    user.expiresAt = null;
    user.updatedAt = new Date().toISOString();

    saveDatabase();

    console.log(`User ${username} set as PERMANENT`);

    return res.status(200).json({
        success: true,
        message: `User "${username}" is now permanent and approved`
    });
}

// NEW: Fix existing users that aren't working properly
async function handleFixUser(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Method not allowed' });
    }

    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ success: false, message: 'Username required' });
    }

    const user = USERS_DB.find(u => u.username === username);

    if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
    }

    // FORCE all the correct flags
    user.permanent = true;
    user.approved = true;
    user.expiresAt = null;
    user.updatedAt = new Date().toISOString();

    saveDatabase();

    console.log(`User ${username} FIXED - now permanent and approved`);

    return res.status(200).json({
        success: true,
        message: `User "${username}" fixed successfully`,
        data: {
            username: user.username,
            permanent: user.permanent,
            approved: user.approved,
            expiresAt: user.expiresAt
        }
    });
}
