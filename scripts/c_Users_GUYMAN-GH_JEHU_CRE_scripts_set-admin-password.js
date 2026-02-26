const bcrypt = require('bcryptjs');
const mysql = require('mysql2');
const dotenv = require('dotenv');
const path = require('path');
const readline = require('readline');

// Load environment variables from the root .env file
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

// --- MySQL Connection ---
// Use the same credentials as your main app
const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'user_portal_db'
});

const saltRounds = 10;
const adminUserId = 1; // Assuming admin user has ID 1

const askQuestion = (query, hidden = false) => {
    return new Promise(resolve => {
        // This part hides password input for security
        if (hidden) {
            const onData = (char) => {
                char = char.toString();
                if (char === '\r' || char === '\n') {
                    process.stdin.removeListener('data', onData);
                    resolve();
                }
            };
            process.stdin.on('data', onData);
        }
        rl.question(query, resolve);
    });
};

const setPassword = async () => {
    try {
        const newPassword = await askQuestion('Enter new admin password: ');
        if (!newPassword) {
            console.error('Password cannot be empty.');
            return;
        }
        const confirmPassword = await askQuestion('Confirm new admin password: ');
        if (newPassword !== confirmPassword) {
            console.error('Passwords do not match.');
            return;
        }

        await db.promise().connect();
        console.log('Connected to MySQL database.');

        console.log('Hashing new password...');
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        console.log('Updating admin password in the database...');
        const query = 'UPDATE users SET password = ? WHERE id = ?';
        const [result] = await db.promise().query(query, [hashedPassword, adminUserId]);

        if (result.affectedRows === 0) {
            console.error(`Error: No user found with ID ${adminUserId}. Please ensure an admin user exists with ID 1.`);
        } else {
            console.log(`Successfully updated password for admin user ID ${adminUserId}.`);
        }
    } catch (err) {
        console.error('An error occurred:', err);
    } finally {
        rl.close();
        if (db) db.end();
    }
};

setPassword();