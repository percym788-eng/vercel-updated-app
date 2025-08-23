// lib/database.js - Simple JSON file-based storage for Vercel
import fs from 'fs';
import path from 'path';

const DATA_DIR = '/tmp';
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const API_KEYS_FILE = path.join(DATA_DIR, 'apikeys.json');
const LOGIN_HISTORY_FILE = path.join(DATA_DIR, 'loginhistory.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

class Database {
    constructor() {
        this.users = this.loadUsers();
        this.apiKeys = this.loadApiKeys();
        this.loginHistory = this.loadLoginHistory();
        this.activeSessions = new Map();
    }

    loadUsers() {
        try {
            if (fs.existsSync(USERS_FILE)) {
                const data = fs.readFileSync(USERS_FILE, 'utf8');
                const users = JSON.parse(data);
                
                // Migrate existing users to have permanent flag
                return users.map(user => ({
                    ...user,
                    permanent: user.permanent !== false // Default to true
                }));
            }
        } catch (error) {
            console.error('Error loading users:', error);
        }
        return [];
    }

    saveUsers() {
        try {
            fs.writeFileSync(USERS_FILE, JSON.stringify(this.users, null, 2));
        } catch (error) {
            console.error('Error saving users:', error);
        }
    }

    loadApiKeys() {
        try {
            if (fs.existsSync(API_KEYS_FILE)) {
                const data = fs.readFileSync(API_KEYS_FILE, 'utf8');
                return JSON.parse(data);
            }
        } catch (error) {
            console.error('Error loading API keys:', error);
        }
        return [];
    }

    saveApiKeys() {
        try {
            fs.writeFileSync(API_KEYS_FILE, JSON.stringify(this.apiKeys, null, 2));
        } catch (error) {
            console.error('Error saving API keys:', error);
        }
    }

    loadLoginHistory() {
        try {
            if (fs.existsSync(LOGIN_HISTORY_FILE)) {
                const data = fs.readFileSync(LOGIN_HISTORY_FILE, 'utf8');
                return JSON.parse(data);
            }
        } catch (error) {
            console.error('Error loading login history:', error);
        }
        return [];
    }

    saveLoginHistory() {
        try {
            // Keep only last 1000 entries
            const trimmedHistory = this.loginHistory.slice(-1000);
            fs.writeFileSync(LOGIN_HISTORY_FILE, JSON.stringify(trimmedHistory, null, 2));
        } catch (error) {
            console.error('Error saving login history:', error);
        }
    }

    // User management methods
    addUser(user) {
        this.users.push({
            ...user,
            permanent: user.permanent !== false, // Default to true
            createdAt: new Date().toISOString()
        });
        this.saveUsers();
    }

    findUser(username) {
        return this.users.find(u => u.username === username);
    }

    updateUser(username, updates) {
        const userIndex = this.users.findIndex(u => u.username === username);
        if (userIndex !== -1) {
            this.users[userIndex] = { ...this.users[userIndex], ...updates };
            this.saveUsers();
            return this.users[userIndex];
        }
        return null;
    }

    removeUser(username) {
        const userIndex = this.users.findIndex(u => u.username === username);
        if (userIndex !== -1) {
            this.users.splice(userIndex, 1);
            this.saveUsers();
            
            // Remove associated API keys
            this.apiKeys = this.apiKeys.filter(k => k.username !== username);
            this.saveApiKeys();
            
            return true;
        }
        return false;
    }

    // API Key management
    addApiKey(apiKeyData) {
        this.apiKeys.push({
            ...apiKeyData,
            createdAt: new Date().toISOString()
        });
        this.saveApiKeys();
    }

    findApiKey(apiKey) {
        return this.apiKeys.find(k => k.apiKey === apiKey);
    }

    removeApiKeysForUser(username) {
        this.apiKeys = this.apiKeys.filter(k => k.username !== username);
        this.saveApiKeys();
    }

    // Login history
    addLoginHistory(entry) {
        this.loginHistory.push({
            ...entry,
            timestamp: new Date().toISOString()
        });
        
        // Keep only last 1000 entries in memory
        if (this.loginHistory.length > 1000) {
            this.loginHistory = this.loginHistory.slice(-1000);
        }
        
        this.saveLoginHistory();
    }

    // Clean expired users (only non-permanent ones)
    cleanExpiredUsers() {
        const now = new Date();
        const originalCount = this.users.length;
        
        // Only remove users that are explicitly non-permanent AND expired
        this.users = this.users.filter(user => {
            if (user.permanent !== false) {
                return true; // Keep permanent users
            }
            
            if (user.expiresAt && now > new Date(user.expiresAt)) {
                console.log(`Removing expired non-permanent user: ${user.username}`);
                return false; // Remove expired non-permanent user
            }
            
            return true; // Keep non-expired users
        });
        
        if (this.users.length !== originalCount) {
            this.saveUsers();
            console.log(`Cleaned ${originalCount - this.users.length} expired users`);
        }

        // Clean associated API keys for removed users
        const validUsernames = this.users.map(u => u.username);
        const originalApiKeyCount = this.apiKeys.length;
        
        this.apiKeys = this.apiKeys.filter(k => validUsernames.includes(k.username));
        
        if (this.apiKeys.length !== originalApiKeyCount) {
            this.saveApiKeys();
        }
    }

    // Get all data for admin dashboard
    getAllData() {
        return {
            users: this.users.map(user => ({
                username: user.username,
                accessType: user.accessType,
                approved: user.approved,
                permanent: user.permanent !== false,
                createdAt: user.createdAt,
                expiresAt: user.expiresAt
            })),
            apiKeys: this.apiKeys.map(key => ({
                username: key.username,
                createdAt: key.createdAt
            })),
            activeSessions: this.activeSessions.size,
            loginHistory: this.loginHistory.slice(-50) // Last 50 entries
        };
    }
}

// Export singleton instance
let dbInstance = null;

export function getDatabase() {
    if (!dbInstance) {
        dbInstance = new Database();
    }
    return dbInstance;
}
