// api/auth.js - Vercel serverless function for authentication
import crypto from 'crypto';

// Enhanced Security Configuration
const ADMIN_SECURITY = {
    ALLOWED_MAC_ADDRESSES: ['88:66:5a:46:b0:d0'], // Replace with your actual MAC address
    
    // RSA Public Key for admin verification
    ADMIN_RSA_PUBLIC_KEY: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Dojkpn9uLlpJGfMnKJ/
G8DNP0F4uq78lrbCnZvKWFQmf3Mj3LoRWZPga9MYmSvfIbLJmaL/PMslxbDyXvI7
CIGCwPtZVqeE6S6UJ/EeD0EpJCNetWUOPOZ/Vqo+WrY/TaXQix/IzFNKXMj0Ul43
shU/BWM5lnPoxGtu2g0Z3hmhqDeHFQKG23V68K7d1xHhJkmlCVkSgQs+Oe/rkAHL
4g7vd1ViJ33dF4wKiWLKTmvcYOJXbNPE/RXwvb48qtPWoy2R1E0Jg52KNEUG2hDx
wmWRcyAv2bALB5G0EANaYQCieOethyykt2lo7rV7fy6jtxE+HoiGE0kLAmlbsoHc
wQIDAQAB
-----END PUBLIC KEY-----`
};

// Device and network restrictions
const DEVICE_RESTRICTIONS = {
    MAX_TRIAL_DEVICES: 1,
    BLOCKED_IPS: [],
    BLOCKED_MACS: []
};

// In-memory storage (you might want to use a database for production)
let users = {
    // Trial users (30 minute limit)
    'trial_user': {
        passwordHash: hashPassword('demo123'),
        approved: true,
        accessType: 'trial',
        createdAt: new Date().toISOString()
    },
    'demo1': {
        passwordHash: hashPassword('trial2024'),
        approved: true,
        accessType: 'trial',
        createdAt: new Date().toISOString()
    },
    'student1': {
        passwordHash: hashPassword('sat_demo'),
        approved: true,
        accessType: 'trial',
        createdAt: new Date().toISOString()
    },
    
    // Premium users (unlimited access)
    'premium1': {
        passwordHash: hashPassword('fullaccess2024'),
        approved: true,
        accessType: 'unlimited',
        createdAt: new Date().toISOString()
    },
    'vip_user': {
        passwordHash: hashPassword('unlimited_sat'),
        approved: true,
        accessType: 'unlimited',
        createdAt: new Date().toISOString()
    },
    'client_alpha': {
        passwordHash: hashPassword('premium_key_2024'),
        approved: true,
        accessType: 'unlimited',
        createdAt: new Date().toISOString()
    },
    
    // Admin users (unlimited + admin privileges)
    'admin': {
        passwordHash: hashPassword('admin_secure_2024'),
        approved: true,
        accessType: 'admin',
        createdAt: new Date().toISOString()
    },
    'sathelper_admin': {
        passwordHash: hashPassword('master_control_2024'),
        approved: true,
        accessType: 'admin',
        createdAt: new Date().toISOString()
    }
};

let apiKeys = {};
let loginHistory = [];
let deviceRegistry = {};
let activeSessions = {};

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

function validateRSASignature(challenge, signature) {
    try {
        const publicKey = crypto.createPublicKey(ADMIN_SECURITY.ADMIN_RSA_PUBLIC_KEY);
        return crypto.verify('sha256', Buffer.from(challenge), publicKey, Buffer.from(signature, 'base64'));
    } catch (error) {
        console.error('RSA validation error:', error);
        return false;
    }
}

function generateApiKey() {
    return 'ak_' + crypto.randomBytes(32).toString('base64url');
}

function logSecurityEvent(event, details = '') {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${event}: ${details}`);
    // In production, you'd want to store this in a database or logging service
}

function isDeviceBlocked(deviceInfo) {
    // Check if IP is blocked
    if (DEVICE_RESTRICTIONS.BLOCKED_IPS.includes(deviceInfo.publicIP) ||
        DEVICE_RESTRICTIONS.BLOCKED_IPS.includes(deviceInfo.localIP)) {
        return { blocked: true, reason: 'IP address blocked' };
    }
    
    // Check if MAC is blocked
    const blockedMac = deviceInfo.macAddresses.some(mac => 
        DEVICE_RESTRICTIONS.BLOCKED_MACS.includes(mac.toLowerCase())
    );
    
    if (blockedMac) {
        return { blocked: true, reason: 'Device blocked' };
    }
    
    return { blocked: false };
}

function validateTrialDeviceLimit(username, accessType, deviceInfo) {
    if (accessType !== 'trial') {
        return { allowed: true };
    }
    
    // Check if current device is admin device (skip restrictions)
    const isAdminDevice = ADMIN_SECURITY.ALLOWED_MAC_ADDRESSES.some(allowedMac => 
        deviceInfo.macAddresses.includes(allowedMac.toLowerCase())
    );
    
    if (isAdminDevice) {
        return { allowed: true, reason: 'Admin device bypass' };
    }
    
    // For simplicity, allow trial access for now
    // In production, implement proper device tracking
    return { allowed: true };
}

export default async function handler(req, res) {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }
    
    try {
        const { method } = req;
        const { action } = req.query;
        
        if (method === 'POST' && action === 'login') {
            const { username, password, deviceInfo } = req.body;
            
            if (!username || !password || !deviceInfo) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Missing required fields: username, password, deviceInfo' 
                });
            }
            
            const user = users[username];
            
            // Check if user exists
            if (!user) {
                logSecurityEvent('AUTH_FAILED', `User not found: ${username}`);
                return res.status(401).json({ 
                    success: false, 
                    message: 'Invalid credentials' 
                });
            }
            
            // Check password
            if (user.passwordHash !== hashPassword(password)) {
                logSecurityEvent('AUTH_FAILED', `Invalid password for: ${username}`);
                return res.status(401).json({ 
                    success: false, 
                    message: 'Invalid credentials' 
                });
            }
            
            // Check if user is approved
            if (!user.approved) {
                logSecurityEvent('AUTH_FAILED', `User not approved: ${username}`);
                return res.status(403).json({ 
                    success: false, 
                    message: 'Account not approved yet' 
                });
            }
            
            // Check device restrictions
            const deviceBlocked = isDeviceBlocked(deviceInfo);
            if (deviceBlocked.blocked) {
                logSecurityEvent('AUTH_FAILED', `Device blocked: ${deviceBlocked.reason}`);
                return res.status(403).json({ 
                    success: false, 
                    message: deviceBlocked.reason 
                });
            }
            
            // Check trial device limits
            const deviceValidation = validateTrialDeviceLimit(username, user.accessType, deviceInfo);
            if (!deviceValidation.allowed) {
                logSecurityEvent('AUTH_FAILED', `Device restriction: ${deviceValidation.reason}`);
                return res.status(403).json({ 
                    success: false, 
                    message: deviceValidation.reason 
                });
            }
            
            // Log successful login
            const loginEntry = {
                timestamp: new Date().toISOString(),
                username,
                accessType: user.accessType,
                success: true,
                device: deviceInfo
            };
            loginHistory.push(loginEntry);
            
            // Generate session ID
            const sessionId = crypto.randomBytes(16).toString('hex');
            activeSessions[sessionId] = {
                username,
                accessType: user.accessType,
                loginTime: new Date().toISOString(),
                deviceInfo
            };
            
            logSecurityEvent('AUTH_SUCCESS', `Username: ${username}, AccessType: ${user.accessType}`);
            
            return res.status(200).json({ 
                success: true, 
                message: 'Authentication successful',
                data: {
                    username,
                    accessType: user.accessType,
                    sessionId
                }
            });
        }
        
        if (method === 'POST' && action === 'validate-api-key') {
            const { apiKey } = req.body;
            
            if (!apiKey) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'API key required' 
                });
            }
            
            const keyData = apiKeys[apiKey];
            
            if (!keyData) {
                logSecurityEvent('API_INVALID', `Invalid key: ${apiKey.substring(0, 10)}...`);
                return res.status(401).json({ 
                    success: false, 
                    message: 'Invalid API key' 
                });
            }
            
            // Check if expired
            const expiresAt = new Date(keyData.expiresAt);
            if (new Date() > expiresAt) {
                logSecurityEvent('API_EXPIRED', `Expired key for: ${keyData.username}`);
                return res.status(401).json({ 
                    success: false, 
                    message: 'API key expired' 
                });
            }
            
            logSecurityEvent('API_VALID', `Username: ${keyData.username}`);
            return res.status(200).json({ 
                success: true,
                data: {
                    username: keyData.username,
                    accessType: keyData.accessType
                }
            });
        }
        
        if (method === 'POST' && action === 'admin-validate') {
            const { challenge, signature, macAddresses } = req.body;
            
            if (!challenge || !signature || !macAddresses) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Missing required fields: challenge, signature, macAddresses' 
                });
            }
            
            // Validate MAC address
            const macValid = ADMIN_SECURITY.ALLOWED_MAC_ADDRESSES.some(allowedMac => 
                macAddresses.includes(allowedMac.toLowerCase())
            );
            
            if (!macValid) {
                logSecurityEvent('ADMIN_ACCESS_DENIED', `Unauthorized MAC: ${macAddresses.join(', ')}`);
                return res.status(403).json({ 
                    success: false, 
                    message: 'Unauthorized device' 
                });
            }
            
            // Validate RSA signature
            const rsaValid = validateRSASignature(challenge, signature);
            
            if (!rsaValid) {
                logSecurityEvent('ADMIN_ACCESS_DENIED', 'Invalid RSA signature');
                return res.status(401).json({ 
                    success: false, 
                    message: 'Invalid RSA signature' 
                });
            }
            
            logSecurityEvent('ADMIN_ACCESS_GRANTED', 'Full validation passed');
            return res.status(200).json({ 
                success: true, 
                message: 'Admin access granted' 
            });
        }
        
        if (method === 'GET' && action === 'admin-data') {
            // This endpoint would require admin authentication in production
            // For now, returning basic data
            return res.status(200).json({
                success: true,
                data: {
                    users: Object.keys(users).map(username => ({
                        username,
                        accessType: users[username].accessType,
                        approved: users[username].approved,
                        createdAt: users[username].createdAt
                    })),
                    apiKeys: Object.keys(apiKeys).map(key => ({
                        key: key.substring(0, 20) + '...',
                        username: apiKeys[key].username,
                        accessType: apiKeys[key].accessType,
                        expiresAt: apiKeys[key].expiresAt
                    })),
                    loginHistory: loginHistory.slice(-50), // Last 50 logins
                    activeSessions: Object.keys(activeSessions).length
                }
            });
        }
        
        if (method === 'POST' && action === 'admin-add-user') {
            const { username, password, accessType } = req.body;
            
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
            
            if (users[username]) {
                return res.status(409).json({ 
                    success: false, 
                    message: 'User already exists' 
                });
            }
            
            users[username] = {
                passwordHash: hashPassword(password),
                approved: true,
                accessType: accessType,
                createdAt: new Date().toISOString()
            };
            
            logSecurityEvent('USER_ADDED', `Username: ${username}, Access: ${accessType}`);
            
            return res.status(201).json({ 
                success: true, 
                message: `User ${username} added successfully` 
            });
        }
        
        if (method === 'DELETE' && action === 'admin-remove-user') {
            const { username } = req.body;
            
            if (!username) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Username required' 
                });
            }
            
            if (!users[username]) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'User not found' 
                });
            }
            
            delete users[username];
            
            // Remove associated API keys
            const keysToRemove = [];
            for (const [apiKey, data] of Object.entries(apiKeys)) {
                if (data.username === username) {
                    keysToRemove.push(apiKey);
                }
            }
            
            keysToRemove.forEach(key => delete apiKeys[key]);
            
            logSecurityEvent('USER_REMOVED', `Username: ${username}`);
            
            return res.status(200).json({ 
                success: true, 
                message: `User ${username} removed successfully` 
            });
        }
        
        if (method === 'POST' && action === 'admin-approve-user') {
            const { username } = req.body;
            
            if (!username) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Username required' 
                });
            }
            
            if (!users[username]) {
                return res.status(404).json({ 
                    success: false, 
                    message: 'User not found' 
                });
            }
            
            users[username].approved = true;
            users[username].approvedAt = new Date().toISOString();
            
            // Generate API key
            const apiKey = generateApiKey();
            const expiresAt = new Date();
            expiresAt.setFullYear(expiresAt.getFullYear() + 1); // 1 year from now
            
            apiKeys[apiKey] = {
                username: username,
                accessType: users[username].accessType,
                createdAt: new Date().toISOString(),
                expiresAt: expiresAt.toISOString()
            };
            
            logSecurityEvent('USER_APPROVED', `Username: ${username}`);
            
            return res.status(200).json({ 
                success: true, 
                message: 'User approved successfully',
                data: {
                    apiKey: apiKey
                }
            });
        }
        
        return res.status(404).json({ 
            success: false, 
            message: 'Endpoint not found' 
        });
        
    } catch (error) {
        console.error('API Error:', error);
        return res.status(500).json({ 
            success: false, 
            message: 'Internal server error',
            error: error.message 
        });
    }
}
