// scripts/migrate-users.js - Migration script to set all existing users as permanent
import { getDatabase } from '../lib/database.js';

async function migrateUsers() {
    console.log('🔄 Starting user migration to permanent status...');
    
    const db = getDatabase();
    let migratedCount = 0;
    
    // Get all users
    const users = db.users;
    console.log(`📊 Found ${users.length} users to check`);
    
    // Update each user to be permanent if not already set
    for (const user of users) {
        if (user.permanent === undefined || user.permanent === null) {
            console.log(`✅ Setting user "${user.username}" as permanent`);
            db.updateUser(user.username, { 
                permanent: true, 
                expiresAt: null 
            });
            migratedCount++;
        } else if (user.permanent === false) {
            console.log(`⚠️  User "${user.username}" is explicitly set as temporary - keeping as is`);
        } else {
            console.log(`✓ User "${user.username}" already permanent`);
        }
    }
    
    console.log(`\n🎉 Migration completed!`);
    console.log(`📈 ${migratedCount} users migrated to permanent status`);
    console.log(`📊 ${users.filter(u => u.permanent !== false).length} total permanent users`);
    console.log(`⏰ ${users.filter(u => u.permanent === false).length} temporary users remaining`);
}

// Run migration if this script is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    migrateUsers().catch(console.error);
}

export { migrateUsers };
