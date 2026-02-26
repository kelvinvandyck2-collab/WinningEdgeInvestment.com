const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const dotenv = require('dotenv');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

// Use the built-in console for logging to resolve the TypeError
const logger = console;
dotenv.config(); // Load environment variables from .env file
const nodemailer = require('nodemailer');

const app = express();
const port = process.env.PORT || 3003;

// --- Middleware ---
// Serve static files from the 'public' directory (MUST be high up)
app.use(express.static(path.join(__dirname, 'public')));

// Security Middleware: Helmet
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        "script-src": ["'self'", "cdn.jsdelivr.net", "'unsafe-inline'"],
        "style-src": ["'self'", "cdn.jsdelivr.net", "fonts.googleapis.com", "cdnjs.cloudflare.com", "'unsafe-inline'"],
        "font-src": ["'self'", "fonts.gstatic.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net"],
        "img-src": ["'self'", "data:"],
      },
    },
  })
);

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'a-default-secret-for-dev-only',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === 'production' }
}));
// Parse URL-encoded bodies (as sent by HTML forms)
app.use(bodyParser.urlencoded({ extended: true }));
// Parse JSON bodies (as sent by API clients)
app.use(bodyParser.json());

// --- MySQL Connection ---
const db = mysql.createPool({
    connectionLimit: 10, // A good default for managing multiple connections
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'user_portal_db'
});

logger.info('Connected to MySQL database pool.');

// --- Security: Rate Limiting ---
const loginLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 10, // Limit each IP to 10 login requests per `window` (here, per 15 minutes)
	standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    message: { success: false, message: 'Too many login attempts from this IP, please try again after 15 minutes' },
});


// --- Nodemailer Configuration ---
// Configure this with your own SMTP service details.
// For security, it's best to use environment variables for auth credentials.
const transporter = nodemailer.createTransport({
    host: 'smtp.hostinger.com',
    port: 465,
    secure: true, // true for 465, false for other ports
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
});
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@example.com'; // The email address where you want to receive notifications

// --- Helper function to create notifications ---
const createNotification = (userId, type, message) => {
    const query = 'INSERT INTO notifications (user_id, type, message) VALUES (?, ?, ?)';
    db.query(query, [userId, type, message], (err, result) => {
        if (err) {
            // Log the error but don't block the main operation
            logger.error(`Error creating notification for user ${userId}: ${err.message}`);
        }
    });
};


// --- Middleware for protecting admin routes ---
const requireAdmin = (req, res, next) => {
    if (req.session && req.session.isAdmin) {
        // If the user is an admin, proceed to the next middleware/route handler
        next();
    } else {
        // If not an admin, redirect them to the admin login page
        res.redirect('/admin-login.html');
    }
};

// Middleware for protecting user routes
const requireLogin = (req, res, next) => {
    if (req.session && req.session.userId) {
        next(); // User is logged in, proceed
    } else {
        // Check if the request is an API call (expects JSON)
        if (req.originalUrl.startsWith('/api/')) {
            // For API calls, send a 401 Unauthorized error
            res.status(401).json({ success: false, message: 'Authentication required. Please log in again.' });
        } else {
            // For page loads, redirect to the login page
            res.redirect('/login.html');
        }
    }
};

// Middleware to protect the signup page
const requireValidToken = (req, res, next) => {
    if (req.session && req.session.signupTokenVerified) {
        next(); // Token is valid, proceed to signup
    } else {
        res.redirect('/verify-token.html'); // No valid token, redirect to token entry page
    }
};

// --- API Routes ---

// Serve the signup page, but only if a token has been verified
app.get('/signup.html', requireValidToken, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

// Handle user signup
app.post('/signup', (req, res, next) => {
    const { name, email, phone_number, password } = req.body;

    // Double-check session for security
    if (!req.session.signupTokenVerified || !req.session.signupToken) {
        return res.status(403).send('Access denied. Please verify a token first.');
    }

    // Basic validation
    if (!name || !email || !phone_number || !password) {
        return res.status(400).send('All fields are required.');
    }

    // Hash the password before storing it
    const saltRounds = 10; // Recommended salt rounds for bcrypt
    bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
        if (err) { return next(err); }

        // Function to generate a unique username and insert the user
        const generateAndInsertUser = () => {
            // Generate 6 random digits to make an 8-character username (WE + 6 digits)
            const randomNumber = Math.floor(100000 + Math.random() * 900000);
            const username = `WE${randomNumber}`;

            // Check for uniqueness before inserting
            db.query('SELECT id FROM users WHERE username = ?', [username], (checkErr, checkResults) => {
                if (checkErr) {
                    return next(checkErr);
                }

                if (checkResults.length > 0) {
                    // Username exists, recursively call the function to try generating a new one
                    return generateAndInsertUser();
                }

                // Username is unique, proceed with insertion
                const userQuery = 'INSERT INTO users (name, email, phone_number, username, password) VALUES (?, ?, ?, ?, ?)';
                db.query(userQuery, [name, email, phone_number, username, hashedPassword], (insertErr, result) => {
                    if (insertErr) { return next(insertErr); }

                    // Mark the token as used
                    const tokenQuery = "UPDATE signup_tokens SET status = 'used', used_at = CURRENT_TIMESTAMP WHERE token = ?";
                    db.query(tokenQuery, [req.session.signupToken], (tokenErr) => {
                        if (tokenErr) {
                            logger.warn(`Non-critical error: Failed to update token status for ${req.session.signupToken}: ${tokenErr.message}`);
                        }

                        // Clear the token from the session
                        delete req.session.signupTokenVerified;
                        delete req.session.signupToken;

                        // Send a success message with the new username
                        res.send(`
                            <!DOCTYPE html>
                            <html lang="en">
                            <head>
                                <meta charset="UTF-8">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                <title>Registration Successful - WINNING EDGE</title>
                                <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap" rel="stylesheet">
                                <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
                                <style>
                                    :root {
                                        --primary-color: #1a2a6c;
                                        --secondary-color: #b21f1f;
                                        --success-color: #28a745;
                                        --accent-color: #fdbb2d;
                                    }
                                    body {
                                        font-family: 'Poppins', sans-serif;
                                        background-color: #f0f2f5;
                                        background-image: radial-gradient(circle at top left, rgba(26, 42, 108, 0.05), transparent 30%),
                                                          radial-gradient(circle at bottom right, rgba(178, 31, 31, 0.05), transparent 30%);
                                        display: flex;
                                        justify-content: center;
                                        align-items: center;
                                        height: 100vh;
                                        margin: 0;
                                        overflow: hidden;
                                    }
                                    .message-box {
                                        background: white;
                                        padding: 40px 50px;
                                        border-radius: 16px;
                                        box-shadow: 0 10px 40px rgba(0,0,0,0.1);
                                        text-align: center;
                                        max-width: 500px;
                                        width: 90%;
                                        border-top: 5px solid var(--success-color);
                                        animation: fadeInUp 0.8s ease-out;
                                    }
                                    .success-icon { margin-bottom: 20px; }
                                    .checkmark { width: 80px; height: 80px; border-radius: 50%; display: block; stroke-width: 3; stroke: var(--success-color); stroke-miterlimit: 10; margin: 0 auto; box-shadow: inset 0px 0px 0px var(--success-color); animation: fill .4s ease-in-out .4s forwards, scale .3s ease-in-out .9s both; }
                                    .checkmark-circle { stroke-dasharray: 166; stroke-dashoffset: 166; stroke-width: 3; stroke-miterlimit: 10; stroke: var(--success-color); fill: none; animation: stroke .6s cubic-bezier(0.65, 0, 0.45, 1) forwards; }
                                    .checkmark-check { transform-origin: 50% 50%; stroke-dasharray: 48; stroke-dashoffset: 48; animation: stroke .3s cubic-bezier(0.65, 0, 0.45, 1) .8s forwards; }
                                    h1 { color: var(--primary-color); font-weight: 700; margin-bottom: 15px; }
                                    p { font-size: 16px; color: #555; margin-bottom: 10px; }
                                    .username-display { display: flex; align-items: center; justify-content: center; background: #f0f2f5; border: 1px dashed #ccc; border-radius: 8px; padding: 12px 20px; margin: 20px 0; }
                                    #username-text { font-size: 22px; font-weight: 700; color: var(--secondary-color); letter-spacing: 1px; margin-right: 15px; }
                                    #copy-btn { background: none; border: none; font-size: 20px; color: #888; cursor: pointer; transition: color 0.3s ease; }
                                    #copy-btn:hover { color: var(--primary-color); }
                                    .instruction { font-size: 14px; color: #777; font-style: italic; }
                                    .login-button { display: inline-block; margin-top: 25px; padding: 12px 30px; background: linear-gradient(135deg, var(--primary-color), var(--secondary-color)); color: white; text-decoration: none; font-weight: 600; border-radius: 8px; transition: all 0.3s ease; }
                                    .login-button:hover { transform: translateY(-3px); box-shadow: 0 5px 15px rgba(0,0,0,0.15); }
                                    @keyframes stroke { 100% { stroke-dashoffset: 0; } }
                                    @keyframes scale { 0%, 100% { transform: none; } 50% { transform: scale3d(1.1, 1.1, 1); } }
                                    @keyframes fill { 100% { box-shadow: inset 0px 0px 0px 40px var(--success-color); } }
                                    @keyframes fadeInUp { from { opacity: 0; transform: translateY(30px); } to { opacity: 1; transform: translateY(0); } }
                                </style>
                            </head>
                            <body>
                                <div class="message-box">
                                    <div class="success-icon">
                                        <svg class="checkmark" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 52 52">
                                            <circle class="checkmark-circle" cx="26" cy="26" r="25" fill="none"/>
                                            <path class="checkmark-check" fill="none" d="M14.1 27.2l7.1 7.2 16.7-16.8"/>
                                        </svg>
                                    </div>
                                    <h1>Registration Successful!</h1>
                                    <p>Your account has been created. Your unique username is:</p>
                                    <div class="username-display">
                                        <span id="username-text">${username}</span>
                                        <button id="copy-btn" title="Copy to clipboard">
                                            <i class="far fa-copy"></i>
                                        </button>
                                    </div>
                                    <p class="instruction">Please save this username. You will need it to log in.</p>
                                    <a href="/login.html" class="login-button">Proceed to Login</a>
                                </div>

                                <script>
                                    const copyBtn = document.getElementById('copy-btn');
                                    const usernameText = document.getElementById('username-text').textContent;

                                    copyBtn.addEventListener('click', () => {
                                        navigator.clipboard.writeText(usernameText).then(() => {
                                            const originalIcon = copyBtn.innerHTML;
                                            copyBtn.innerHTML = '<i class="fas fa-check" style="color: var(--success-color);"></i>';
                                            copyBtn.title = 'Copied!';
                                            
                                            setTimeout(() => {
                                                copyBtn.innerHTML = originalIcon;
                                                copyBtn.title = 'Copy to clipboard';
                                            }, 2000);
                                        }).catch(err => {
                                            console.error('Failed to copy: ', err);
                                        });
                                    });
                                </script>
                            </body>
                            </html>
                        `);
                    });
                });
            });
        };
        generateAndInsertUser(); // Initial call to start the process
    });
});

// Handle user login
app.post('/login', loginLimiter, (req, res, next) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Username and password are required.');
    }

    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) { return next(err); }

        if (results.length > 0) {
            const user = results[0];
            // Compare submitted password with the hashed password in the database
            bcrypt.compare(password, user.password, (err, isMatch) => {
                if (err) { return next(err); }

                if (isMatch) {
                    // Passwords match. Regenerate session to prevent session fixation.
                    req.session.regenerate(function(err) {
                        if (err) { return next(err); }

                        // Set user session data on the new session
                        req.session.userId = user.id;
                        req.session.userName = user.name;
                        req.session.userUsername = user.username;
                        // Redirect to the user dashboard
                        logger.info(`User ${user.id} (${user.username}) logged in successfully.`);
                        res.redirect('/dashboard.html');
                    });
                } else {
                    // Passwords do not match
                    res.redirect('/login.html?error=1');
                }
            });
        } else {
            // User not found
            res.redirect('/login.html?error=1');
        }
    });
});

// Handle token verification
app.post('/verify-token', (req, res, next) => {
    const { token } = req.body;
    if (!token) {
        return res.status(400).json({ success: false, message: 'Token is required.' });
    }

    const query = "SELECT * FROM signup_tokens WHERE token = ? AND status = 'unused'";
    db.query(query, [token], (err, results) => {
        if (err) { return next(err); }

        if (results.length === 0) {
            return res.status(400).json({ success: false, message: 'Invalid or already used token.' });
        }

        // Token is valid, set a flag in the session
        req.session.signupTokenVerified = true;
        req.session.signupToken = token;
        res.json({ success: true, message: 'Token verified.' });
    });
});

// --- Admin Routes ---

// Handle Admin Login
app.post('/admin-login', loginLimiter, async (req, res, next) => {
    const { username, password } = req.body;
    const adminUserId = 1; // The admin user is always ID 1

    // Find the admin user by both ID and the provided username for security.
    db.query('SELECT * FROM users WHERE id = ? AND username = ?', [adminUserId, username], (err, results) => {
        if (err) { return next(err); }
        if (results.length === 0) {
            logger.warn(`Admin login attempt failed: Admin user (ID: ${adminUserId}) not found.`);
            return res.status(401).send('Invalid Admin Credentials.');
        }

        const adminUser = results[0];

        bcrypt.compare(password, adminUser.password, (compareErr, isMatch) => {
            if (compareErr) { return next(compareErr); }
            if (!isMatch) {
                logger.warn(`Admin login attempt failed for user: ${adminUser.username}. Incorrect password.`);
                return res.status(401).send('Invalid Admin Credentials.');
            }

            // Password is correct. Check if 2FA is enabled.
            if (adminUser.tfa_enabled) {
                // 2FA is enabled. Don't log in yet.
                // Set a temporary flag in the session to indicate password was correct.
                req.session.tfaPendingAdminId = adminUser.id;
                res.redirect('/admin-2fa-verify.html');
            } else {
                // 2FA is not enabled. Log in directly.
                req.session.regenerate(function(regenErr) {
                    if (regenErr) { return next(regenErr); }
                    req.session.isAdmin = true;
                    req.session.userId = adminUser.id;
                    logger.info(`Admin user ${adminUser.username} logged in successfully (2FA not enabled).`);
                    res.redirect('/admin.html');
                });
            }
        });
    });
});

// Handle Admin 2FA Verification
app.post('/admin-2fa-verify', (req, res, next) => {
    const { token } = req.body;
    const adminId = req.session.tfaPendingAdminId;

    if (!adminId) {
        // User is trying to access this endpoint without first entering a password.
        return res.status(403).json({ message: 'Authentication process not initiated.' });
    }

    db.query('SELECT tfa_secret FROM users WHERE id = ?', [adminId], (err, results) => {
        if (err) { return next(err); }
        if (results.length === 0) { return res.status(500).json({ message: 'Could not retrieve 2FA secret.' }); }

        const secret = results[0].tfa_secret;
        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: token,
            time: Math.floor(Date.now() / 1000), // Use server time for verification
            window: 1 // Allow for a 30-second window of tolerance
        });

        if (verified) {
            // Token is correct. Finalize login.
            req.session.regenerate(function(regenErr) {
                if (regenErr) { return next(regenErr); }
                delete req.session.tfaPendingAdminId; // Clean up temp session flag
                req.session.isAdmin = true;
                req.session.userId = adminId;
                logger.info(`Admin user ID ${adminId} logged in successfully via 2FA.`);
                res.redirect('/admin.html');
            });
        } else {
            // Token is incorrect.
            res.status(401).json({ message: 'Invalid authentication code.' });
        }
    });
});

// --- Password Reset Flow ---

// 1. Handle "Forgot Password" request
app.post('/forgot-password', (req, res, next) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ message: 'Email address is required.' });
    }

    db.query('SELECT * FROM users WHERE email = ?', [email], (err, users) => {
        if (err) {
            // Log the error but continue to send a generic response to avoid leaking info
            logger.error(`Password reset DB error for email ${email}: ${err.message}`);
        }

        if (users.length > 0) {
            const user = users[0];
            const token = crypto.randomBytes(32).toString('hex');
            const expires = new Date(Date.now() + 3600000); // Token expires in 1 hour

            const query = 'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)';
            db.query(query, [user.id, token, expires], (err, result) => {
                if (err) { // If we can't save the token, we can't send the email
                    logger.error(`Password reset: Failed to save token for user ${user.id}: ${err.message}`);
                    return next(err);
                }

                // Construct the reset link
                const resetLink = `${req.protocol}://${req.get('host')}/reset-password.html?token=${token}`;

                // Send the email
                const mailOptions = {
                    from: '"WINNING EDGE" <noreply@winningedgeinvestment.com>',
                    to: user.email,
                    subject: 'Password Reset Request',
                    html: `
                        <p>You requested a password reset for your WINNING EDGE account.</p>
                        <p>Please click the link below to set a new password. This link will expire in one hour.</p>
                        <p><a href="${resetLink}">Reset Your Password</a></p>
                        <p>If you did not request this, please ignore this email.</p>
                    `
                };

                transporter.sendMail(mailOptions, (emailErr) => {
                    if (emailErr) {
                        logger.error(`Password reset: Failed to send reset email to ${user.email}: ${emailErr.message}`);
                    } else {
                        logger.info(`Password reset email sent to ${user.email}`);
                    }
                });
            });
        } else {
            logger.warn(`Password reset attempt for non-existent email: ${email}`);
        }

        // Always send a generic success message to prevent email enumeration
        res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
    });
});

// 2. Handle the actual password reset
app.post('/reset-password', (req, res, next) => {
    const { token, password } = req.body;

    if (!token || !password) {
        return res.status(400).json({ message: 'Token and new password are required.' });
    }

    const findTokenQuery = 'SELECT * FROM password_reset_tokens WHERE token = ? AND expires_at > NOW()';
    db.query(findTokenQuery, [token], (err, tokens) => {
        if (err) { return next(err); }
        if (tokens.length === 0) {
            return res.status(400).json({ message: 'This password reset token is invalid or has expired.' });
        }

        const resetRequest = tokens[0];
        bcrypt.hash(password, 10, (hashErr, hashedPassword) => {
            if (hashErr) { return next(hashErr); }

            db.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, resetRequest.user_id]);
            db.query('DELETE FROM password_reset_tokens WHERE id = ?', [resetRequest.id]); // Clean up token
            logger.info(`User ${resetRequest.user_id} successfully reset their password.`);
            res.json({ message: 'Your password has been reset successfully! You will be redirected to the login page.' });
        });
    });
});

// --- Admin 2FA Management API Endpoints ---

// Generate a new 2FA secret and QR code for setup
app.post('/api/admin/tfa/setup', requireAdmin, (req, res, next) => {
    const secret = speakeasy.generateSecret({
        name: `WINNING EDGE (${process.env.ADMIN_USERNAME || 'Admin'})`
    });

    // Save the temporary secret to the admin user (ID 1)
    db.query('UPDATE users SET tfa_secret = ? WHERE id = 1', [secret.base32], (err) => {
        if (err) { return next(err); }

        qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
            if (err) { return next(err); }
            res.json({ success: true, secret: secret.base32, qrCode: data_url });
        });
    });
});

// Verify the token and enable 2FA for the admin
app.post('/api/admin/tfa/verify', requireAdmin, (req, res, next) => {
    const { token } = req.body;
    const adminId = req.session.userId;

    db.query('SELECT tfa_secret FROM users WHERE id = ?', [adminId], (err, results) => {
        if (err) { return next(err); }
        if (results.length === 0 || !results[0].tfa_secret) {
            return res.status(500).json({ success: false, message: 'Could not retrieve 2FA secret. Please start over.' });
        }

        const secret = results[0].tfa_secret;
        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: token,
            time: Math.floor(Date.now() / 1000), // Use server time for verification
            window: 1 // Allow for a 30-second window of tolerance
        });

        if (verified) {
            // Token is correct, permanently enable 2FA for the user
            db.query('UPDATE users SET tfa_enabled = TRUE WHERE id = ?', [adminId], (err) => {
                if (err) { return next(err); }
                logger.info(`2FA enabled for admin ID ${adminId}.`);
                res.json({ success: true, message: 'Two-Factor Authentication has been enabled!' });
            });
        } else {
            res.status(400).json({ success: false, message: 'Invalid token. Please try again.' });
        }
    });
});

// Disable 2FA for the admin
app.post('/api/admin/tfa/disable', requireAdmin, (req, res, next) => {
    const adminId = req.session.userId;
    // Set enabled to false and clear the secret for security
    db.query('UPDATE users SET tfa_enabled = FALSE, tfa_secret = NULL WHERE id = ?', [adminId], (err) => {
        if (err) { return next(err); }
        logger.info(`2FA disabled for admin ID ${adminId}.`);
        res.json({ success: true, message: 'Two-Factor Authentication has been disabled.' });
    });
});

// Serve the admin page, but only if the user is logged in as an admin
app.get('/admin.html', requireAdmin, (req, res) => {
    // The 'requireAdmin' middleware runs first. If it passes, we serve the file.
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// API endpoint for admin.js to verify authentication status
app.get('/api/admin/check-auth', requireAdmin, (req, res, next) => {
    // The requireAdmin middleware already confirmed they are an admin.
    // We can send back a success response with some user info.
    db.query('SELECT name, tfa_enabled FROM users WHERE id = ?', [req.session.userId], (err, results) => {
        if (err) { return next(err); }
        if (results.length === 0) {
            return res.status(404).json({ success: false, message: 'Admin user not found.' });
        }
        res.json({ success: true, user: results[0] });
    });
});

// Serve the user dashboard page, but only if the user is logged in
app.get('/dashboard.html', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Fetch all users for the admin portal (protected by middleware)
app.get('/api/admin/users', requireAdmin, (req, res, next) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;
    const search = req.query.search || '';
    const status = req.query.status || '';

    let whereClauses = [];
    let queryParams = [];

    if (search) {
        // Use MATCH...AGAINST for FULLTEXT search, which is much faster than LIKE
        whereClauses.push(`MATCH(name, email, username) AGAINST(? IN BOOLEAN MODE)`);
        // Prepare the search term for boolean mode. '+' requires the word, '*' is a wildcard.
        const searchTerm = search.split(' ').filter(word => word.length > 0).map(word => `+${word}*`).join(' ');
        queryParams.push(searchTerm);
    }

    if (status) {
        whereClauses.push(`status = ?`);
        queryParams.push(status);
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

    const countQuery = `SELECT COUNT(*) as total FROM users ${whereSql}`;
    const dataQuery = `SELECT id, username, name, email, phone_number, signup_date as created_at, status FROM users ${whereSql} ORDER BY signup_date DESC LIMIT ? OFFSET ?`;

    db.query(countQuery, queryParams, (err, countResult) => {
        if (err) { return next(err); }

        const total = countResult[0].total;
        const totalPages = Math.ceil(total / limit);

        db.query(dataQuery, [...queryParams, limit, offset], (err, results) => {
            if (err) { return next(err); }

            res.json({
                users: results,
                pagination: {
                    total: total,
                    page: page,
                    totalPages: totalPages
                }
            });
        });
    });
});

// --- Admin Signup Token Endpoints ---

// Get all signup tokens
app.get('/api/admin/signup-tokens', requireAdmin, (req, res, next) => {
    const query = 'SELECT token, status, created_at FROM signup_tokens ORDER BY created_at DESC';
    db.query(query, (err, results) => {
        if (err) { return next(err); }
        res.json({ tokens: results });
    });
});

// Generate a new signup token
app.post('/api/admin/signup-tokens', requireAdmin, (req, res, next) => {
    // Generate a shorter, 12-character hex token
    const newToken = `WE-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
    const query = 'INSERT INTO signup_tokens (token) VALUES (?)';
    db.query(query, [newToken], (err, result) => {
        if (err) {
            logger.error(`Admin: Error generating signup token: ${err.message}`);
            return res.status(500).json({ success: false, message: 'Failed to generate token.' });
        }
        logger.info(`Admin generated new signup token: ${newToken}`);
        res.json({ success: true, message: 'New token generated successfully.' });
    });
});

// Fetch a single user by ID for the admin portal
app.get('/api/admin/users/:id', requireAdmin, (req, res, next) => {
    const userId = req.params.id;
    const query = 'SELECT id, username, name, email, phone_number, signup_date as created_at, balance, status FROM users WHERE id = ?';

    db.query(query, [userId], (err, results) => {
        if (err) { return next(err); }

        if (results.length > 0) {
            const user = results[0];
            // Now fetch real related data
            const investmentsQuery = "SELECT COUNT(*) as count FROM investments WHERE user_id = ?";
            const transactionsQuery = `
                SELECT COUNT(*) as count FROM (
                    (SELECT id FROM deposits WHERE user_id = ?)
                    UNION ALL
                    (SELECT id FROM withdrawals WHERE user_id = ?)
                ) as user_transactions
            `;

            db.query(investmentsQuery, [userId], (err, invResults) => {
                if (err) { return next(err); }

                db.query(transactionsQuery, [userId, userId], (err, txResults) => {
                    if (err) { return next(err); }

                    user.last_login = null; // last_login is not tracked in the DB
                    user.investments = { length: invResults[0].count || 0 };
                    user.transactions = { length: txResults[0].count || 0 };
                    res.json(user);
                });
            });
        } else {
            res.status(404).json({ message: 'User not found.' });
        }
    });
});

// API endpoint for admin to update a user's balance
app.post('/api/admin/users/:id/balance', requireAdmin, (req, res, next) => {
    const userId = req.params.id;
    const { newBalance } = req.body;

    if (newBalance === undefined || isNaN(parseFloat(newBalance))) {
        return res.status(400).json({ success: false, message: 'Invalid balance amount provided.' });
    }

    const query = 'UPDATE users SET balance = ? WHERE id = ?';
    db.query(query, [parseFloat(newBalance), userId], (err, result) => {
        if (err) { return next(err); }
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        res.json({ success: true, message: 'User balance updated successfully.' });
    });
});

// API endpoint to update a user's status
app.post('/api/admin/users/:id/status', requireAdmin, (req, res, next) => {
    const userId = req.params.id;
    const { status } = req.body;

    // Validate status
    const validStatuses = ['active', 'inactive', 'suspended'];
    if (!validStatuses.includes(status)) {
        return res.status(400).json({ success: false, message: 'Invalid status provided.' });
    }

    const query = 'UPDATE users SET status = ? WHERE id = ?';
    db.query(query, [status, userId], (err, result) => {
        if (err) { return next(err); }
        if (result.affectedRows === 0) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }
        res.json({ success: true, message: 'User status updated successfully.' });
    });
});

// Endpoint for real admin stats
app.get('/api/admin/stats', requireAdmin, (req, res, next) => {
    const queries = {
        users: "SELECT COUNT(*) as total, SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_users FROM users",
        investments: 'SELECT COUNT(*) as total, SUM(amount) as total_invested FROM investments',
        transactions: `
            SELECT COUNT(*) as total, SUM(amount) as total_volume FROM (
                (SELECT id, amount FROM deposits WHERE status = 'Completed')
                UNION ALL
                (SELECT id, amount FROM withdrawals WHERE status = 'Completed')
            ) as all_transactions
        `,
        pendingWithdrawals: "SELECT COUNT(*) as pending FROM withdrawals WHERE status = 'Pending'"
    };

    db.query(queries.users, (err, usersRes) => {
        if (err) { return next(err); }
        db.query(queries.investments, (err, invRes) => {
            if (err) { return next(err); }
            db.query(queries.transactions, (err, txRes) => {
                if (err) { return next(err); }
                db.query(queries.pendingWithdrawals, (err, wdRes) => {
                    if (err) { return next(err); }

                    res.json({
                        users: {
                            total: usersRes[0].total || 0,
                            active_users: usersRes[0].active_users || 0
                        },
                        investments: {
                            total: invRes[0].total || 0,
                            total_invested: invRes[0].total_invested || 0
                        },
                        transactions: {
                            total: txRes[0].total || 0,
                            total_volume: txRes[0].total_volume || 0
                        },
                        withdrawals: {
                            pending: wdRes[0].pending || 0
                        }
                    });
                });
            });
        });
    });
});

// Endpoint for real recent admin transactions
app.get('/api/admin/transactions', requireAdmin, (req, res, next) => {
    const query = `
        (SELECT id, 'Deposit' as type, amount, status, request_date as created_at FROM deposits)
        UNION ALL
        (SELECT id, 'Withdrawal' as type, amount, status, request_date as created_at FROM withdrawals)
        ORDER BY created_at DESC
        LIMIT ?
    `;
    const limit = parseInt(req.query.limit) || 10;

    db.query(query, [limit], (err, results) => {
        if (err) { return next(err); }
        res.json({ transactions: results });
    });
});

// API endpoint to get all investments for admin
app.get('/api/admin/investments', requireAdmin, (req, res, next) => {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    const search = req.query.search || '';
    const status = req.query.status || '';

    let whereClauses = [];
    let queryParams = [];

    if (search) {
        // Search against user name and plan name
        whereClauses.push(`(u.name LIKE ? OR p.name LIKE ?)`);
        const searchTerm = `%${search}%`;
        queryParams.push(searchTerm, searchTerm);
    }

    if (status) {
        whereClauses.push(`i.status = ?`);
        queryParams.push(status);
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

    const dataQuery = `
        SELECT i.id, i.user_id, u.name as user_name, p.name as package_name, i.amount, i.status, i.start_date, i.end_date 
        FROM investments i
        JOIN users u ON i.user_id = u.id
        JOIN plans p ON i.plan_id = p.id
        ${whereSql}
        ORDER BY i.start_date DESC LIMIT ? OFFSET ?
    `;

    const countQuery = `SELECT COUNT(i.id) as total FROM investments i JOIN users u ON i.user_id = u.id JOIN plans p ON i.plan_id = p.id ${whereSql}`;

    db.query(countQuery, queryParams, (err, countResult) => {
        if (err) { return next(err); }
        const total = countResult[0].total;
        const totalPages = Math.ceil(total / limit);

        db.query(dataQuery, [...queryParams, limit, offset], (err, results) => {
            if (err) { return next(err); }
            res.json({
                investments: results,
                pagination: { total, page, totalPages }
            });
        });
    });
});

// API endpoint to get all transactions (deposits and withdrawals) for admin
app.get('/api/admin/all-transactions', requireAdmin, (req, res, next) => {
    const query = `
        (SELECT id, user_id, full_name, 'Deposit' as type, amount, method, status, request_date FROM deposits)
        UNION ALL
        (SELECT id, user_id, full_name, 'Withdrawal' as type, amount, method, status, request_date FROM withdrawals)
        ORDER BY request_date DESC
    `;
    db.query(query, (err, results) => {
        if (err) { return next(err); }
        res.json({ transactions: results });
    });
});

// API endpoint to get current logged-in user's data
app.get('/api/user/me', requireLogin, (req, res, next) => {
    // The user is logged in, so their name is in the session
    // No need to query the database again
    res.json({ name: req.session.userName });
});

// API endpoint for admin revenue chart data
app.get('/api/admin/financial-overview', requireAdmin, (req, res, next) => {
    const thirtyDaysAgo = 'DATE_SUB(CURDATE(), INTERVAL 30 DAY)';

    const investmentQuery = `
        SELECT DATE(start_date) as day, SUM(amount) as total
        FROM investments
        WHERE start_date >= ${thirtyDaysAgo}
        GROUP BY day;
    `;

    const transactionQuery = `
        SELECT DATE(request_date) as day, SUM(amount) as total
        FROM deposits
        WHERE status = 'Completed' AND request_date >= ${thirtyDaysAgo}
        GROUP BY day;
    `;

    const withdrawalQuery = `
        SELECT DATE(request_date) as day, SUM(amount) as total
        FROM withdrawals
        WHERE status = 'Completed' AND request_date >= ${thirtyDaysAgo}
        GROUP BY day;
    `;

    db.query(investmentQuery, (err, investmentResults) => {
        if (err) { return next(err); }
        
        db.query(transactionQuery, (err, transactionResults) => {
            if (err) { return next(err); }

            db.query(withdrawalQuery, (err, withdrawalResults) => {
                if (err) {
                    return next(err);
                }

                // Helper function to process results
                const processData = (results) => {
                    const dataMap = new Map();
                    for (let i = 29; i >= 0; i--) {
                        const d = new Date();
                        d.setDate(d.getDate() - i);
                        const dayString = d.toISOString().split('T')[0];
                        dataMap.set(dayString, 0);
                    }
                    results.forEach(row => {
                        const dayString = new Date(row.day).toISOString().split('T')[0];
                        dataMap.set(dayString, parseFloat(row.total));
                    });
                    return Array.from(dataMap.values());
                };

                const investmentData = processData(investmentResults);
                const transactionData = processData(transactionResults);
                const withdrawalData = processData(withdrawalResults);

                const labels = [];
                for (let i = 29; i >= 0; i--) {
                    const d = new Date();
                    d.setDate(d.getDate() - i);
                    labels.push(d.toLocaleDateString('default', { month: 'short', day: 'numeric' }));
                }

                res.json({
                    labels,
                    investmentData,
                    transactionData,
                    withdrawalData
                });
            });
        });
    });
});

// --- Admin Support Ticket API Endpoints ---

// Get all support tickets for admin
app.get('/api/admin/support/tickets', requireAdmin, (req, res, next) => {
    const query = `
        SELECT t.id, t.subject, t.status, t.updated_at, u.name as user_name
        FROM support_tickets t
        JOIN users u ON t.user_id = u.id
        ORDER BY t.status = 'Open' DESC, t.updated_at DESC
    `;
    db.query(query, (err, results) => {
        if (err) { return next(err); }
        res.json({ tickets: results });
    });
});

// Get a single ticket and its messages for admin
app.get('/api/admin/support/tickets/:id', requireAdmin, (req, res, next) => {
    const ticketId = req.params.id;
    const ticketQuery = 'SELECT t.*, u.name as user_name FROM support_tickets t JOIN users u ON t.user_id = u.id WHERE t.id = ?';
    const messagesQuery = 'SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC';

    db.query(ticketQuery, [ticketId], (err, ticketResult) => {
        if (err) { return next(err); }
        if (ticketResult.length === 0) {
            return res.status(404).json({ message: 'Ticket not found.' });
        }
        db.query(messagesQuery, [ticketId], (err, messagesResult) => {
            if (err) { return next(err); }
            res.json({ ticket: ticketResult[0], messages: messagesResult });
        });
    });
});

// Admin replies to a ticket
app.post('/api/admin/support/tickets/:id/reply', requireAdmin, (req, res, next) => {
    const ticketId = req.params.id;
    const { message, user_id } = req.body; // user_id of the ticket owner

    if (!message) {
        return res.status(400).json({ success: false, message: 'Reply message cannot be empty.' });
    }

    const insertQuery = 'INSERT INTO ticket_messages (ticket_id, user_id, message, is_admin_reply) VALUES (?, ?, ?, ?)';
    const updateQuery = "UPDATE support_tickets SET status = 'Answered', updated_at = CURRENT_TIMESTAMP WHERE id = ?";

    db.query(insertQuery, [ticketId, req.session.userId, message, true], (err, result) => {
        if (err) { return next(err); }
        db.query(updateQuery, [ticketId]); // Fire-and-forget status update
        createNotification(user_id, 'support_reply', `You have a new reply on your support ticket #${ticketId}.`);
        logger.info(`Admin (user ${req.session.userId}) replied to ticket ${ticketId}.`);
        res.json({ success: true, message: 'Reply sent successfully.' });
    });
});

app.get('/api/admin/deposits', requireAdmin, (req, res, next) => {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    const search = req.query.search || '';
    const status = req.query.status || '';

    let whereClauses = [];
    let queryParams = [];

    if (search) {
        whereClauses.push(`MATCH(d.full_name, d.method, d.txn_id) AGAINST(? IN BOOLEAN MODE)`);
        queryParams.push(search.split(' ').map(w => `+${w}*`).join(' '));
    }
    if (status) {
        whereClauses.push(`d.status = ?`);
        queryParams.push(status);
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';
    const countQuery = `SELECT COUNT(d.id) as total FROM deposits d ${whereSql}`;
    const dataQuery = `SELECT d.id, d.user_id, d.full_name, d.amount, d.method, d.txn_id, d.status, d.request_date, u.balance as current_balance FROM deposits d JOIN users u ON d.user_id = u.id ${whereSql} ORDER BY d.request_date DESC LIMIT ? OFFSET ?`;

    db.query(countQuery, queryParams, (err, countResult) => {
        if (err) { return next(err); }
        const total = countResult[0].total;
        db.query(dataQuery, [...queryParams, limit, offset], (err, results) => {
            if (err) { return next(err); }
            res.json({ deposits: results, pagination: { total, page, totalPages: Math.ceil(total / limit) } });
        });
    });
});

// API endpoint to get current settings
app.get('/api/admin/settings', requireAdmin, (req, res, next) => {
    const query = 'SELECT * FROM settings';
    db.query(query, (err, results) => {
        if (err) {
            return next(err);
        }
        // Convert array of rows to a key-value object
        const settings = results.reduce((acc, row) => {
            acc[row.setting_key] = row.setting_value;
            return acc;
        }, {});
        res.json(settings);
    });
});

// API endpoint for admin to update settings
app.post('/api/admin/settings', requireAdmin, (req, res, next) => {
    const settings = req.body;

    db.getConnection((err, connection) => {
        if (err) { return next(err); }

        connection.beginTransaction(async (err) => {
            if (err) { connection.release(); return next(err); }

            try {
                for (const [key, value] of Object.entries(settings)) {
                    const sanitizedValue = (typeof value === 'boolean') ? value.toString() : value;
                    const query = 'INSERT INTO settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = ?';
                    await connection.promise().query(query, [key, sanitizedValue, sanitizedValue]);
                }
                await connection.promise().commit();
                connection.release();
                res.json({ success: true, message: 'Settings saved successfully!' });
            } catch (dbErr) {
                await connection.promise().rollback();
                connection.release();
                next(dbErr);
            }
        });
    });
});

app.get('/api/admin/withdrawals', requireAdmin, (req, res, next) => {
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;
    const search = req.query.search || '';
    const status = req.query.status || '';

    let whereClauses = [];
    let queryParams = [];

    if (search) {
        whereClauses.push(`MATCH(w.full_name, w.method, w.wallet_address) AGAINST(? IN BOOLEAN MODE)`);
        queryParams.push(search.split(' ').map(w => `+${w}*`).join(' '));
    }
    if (status) {
        whereClauses.push(`w.status = ?`);
        queryParams.push(status);
    }

    const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';
    const countQuery = `SELECT COUNT(w.id) as total FROM withdrawals w ${whereSql}`;
    const dataQuery = `SELECT w.id, w.user_id, w.full_name, w.amount, w.method, w.wallet_address, w.status, w.request_date, u.balance as current_balance FROM withdrawals w JOIN users u ON w.user_id = u.id ${whereSql} ORDER BY w.request_date DESC LIMIT ? OFFSET ?`;

    db.query(countQuery, queryParams, (err, countResult) => {
        if (err) { return next(err); }
        const total = countResult[0].total;
        db.query(dataQuery, [...queryParams, limit, offset], (err, results) => {
            if (err) { return next(err); }
            res.json({ withdrawals: results, pagination: { total, page, totalPages: Math.ceil(total / limit) } });
        });
    });
});

// API endpoint for admin to approve or reject a deposit
app.post('/api/admin/deposits/:id/status', requireAdmin, (req, res, next) => {
    const depositId = req.params.id;
    const { status } = req.body; // 'Completed' or 'Rejected'

    if (!['Completed', 'Rejected'].includes(status)) {
        return res.status(400).json({ success: false, message: 'Invalid status.' });
    }

    db.getConnection((err, connection) => {
        if (err) { return next(err); }

        connection.beginTransaction(err => {
            if (err) { connection.release(); return next(err); }

            connection.query('SELECT * FROM deposits WHERE id = ? AND status = "Pending" FOR UPDATE', [depositId], (err, deposits) => {
                if (err || deposits.length === 0) {
                    return connection.rollback(() => { connection.release(); res.status(404).json({ success: false, message: 'Pending deposit not found.' }); });
                }

                const deposit = deposits[0];

                // Update deposit status
                connection.query('UPDATE deposits SET status = ? WHERE id = ?', [status, depositId], (err, result) => {
                    if (err) { return connection.rollback(() => { connection.release(); next(err); }); }

                    if (status === 'Completed') {
                        // If completed, add the amount to the user's balance
                        connection.query('UPDATE users SET balance = balance + ? WHERE id = ?', [deposit.amount, deposit.user_id], (err, result) => {
                            if (err) { return connection.rollback(() => { connection.release(); next(err); }); }
                            
                            connection.commit(commitErr => {
                                if (commitErr) { return connection.rollback(() => { connection.release(); next(commitErr); }); }
                                connection.release();
                                createNotification(deposit.user_id, 'deposit_completed', `Your deposit of ${formatCurrency(deposit.amount)} has been approved.`);
                                logger.info(`Admin approved deposit ${depositId} for user ${deposit.user_id}. Amount: ${deposit.amount}`);
                                res.json({ success: true, message: 'Deposit approved and balance updated.' });
                            });
                        });
                    } else { // If rejected, just commit the status change
                        connection.commit(commitErr => {
                            if (commitErr) { return connection.rollback(() => { connection.release(); next(commitErr); }); }
                            connection.release();
                            createNotification(deposit.user_id, 'deposit_rejected', `Your deposit of ${formatCurrency(deposit.amount)} was rejected.`);
                            logger.info(`Admin rejected deposit ${depositId} for user ${deposit.user_id}.`);
                            res.json({ success: true, message: 'Deposit rejected successfully.' });
                        });
                    }
                });
            });
        });
    });
});

// API endpoint for admin to approve or reject a withdrawal
app.post('/api/admin/withdrawals/:id/status', requireAdmin, (req, res, next) => {
    const withdrawalId = req.params.id;
    const { status } = req.body;

    // Validate status
    const validStatuses = ['Completed', 'Rejected'];
    if (!validStatuses.includes(status)) {
        return res.status(400).json({ success: false, message: 'Invalid status provided.' });
    }

    db.getConnection((err, connection) => {
        if (err) { return next(err); }

        connection.beginTransaction(err => {
            if (err) { connection.release(); return next(err); }

            // 1. Get withdrawal details
            connection.query('SELECT * FROM withdrawals WHERE id = ? AND status = "Pending" FOR UPDATE', [withdrawalId], (err, results) => {
                if (err || results.length === 0) {
                    return connection.rollback(() => { connection.release(); res.status(404).json({ success: false, message: 'Pending withdrawal not found.' }); });
                }

                const withdrawal = results[0];
                const userId = withdrawal.user_id;
                const amount = parseFloat(withdrawal.amount);

                // 2. Update withdrawal status
                connection.query('UPDATE withdrawals SET status = ? WHERE id = ?', [status, withdrawalId], (err, updateResult) => {
                    if (err) { return connection.rollback(() => { connection.release(); next(err); }); }

                    // 3. If rejected, refund the amount to the user's balance
                    if (status === 'Rejected') {
                        connection.query('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, userId], (err, refundResult) => {
                            if (err) { return connection.rollback(() => { connection.release(); next(err); }); }

                            // Commit transaction for rejection
                            connection.commit(err => {
                                if (err) { return connection.rollback(() => { connection.release(); next(err); }); }
                                connection.release();
                                createNotification(userId, 'withdrawal_rejected', `Your withdrawal request of ${formatCurrency(amount)} was rejected and the amount has been returned to your balance.`);
                                logger.info(`Admin rejected withdrawal ${withdrawalId} for user ${userId}. Amount ${amount} refunded.`);
                                res.json({ success: true, message: 'Withdrawal rejected and funds returned to user.' });
                            });
                        });
                    } else { // If 'Completed'
                        // Commit transaction for completion
                        connection.commit(err => {
                            if (err) { return connection.rollback(() => { connection.release(); next(err); }); }
                            connection.release();
                            createNotification(userId, 'withdrawal_completed', `Your withdrawal request of ${formatCurrency(amount)} has been approved and processed.`);
                            logger.info(`Admin approved withdrawal ${withdrawalId} for user ${userId}. Amount: ${amount}`);
                            // Optionally send an email to the user confirming completion
                            res.json({ success: true, message: 'Withdrawal approved successfully.' });
                        });
                    }
                });
            });
        });
    });
});


// API endpoint to get detailed user profile data
app.get('/api/user/profile', requireLogin, (req, res, next) => {
    const userId = req.session.userId;
    const query = 'SELECT name, email, phone_number, username, signup_date, notify_updates, notify_alerts, notify_promo FROM users WHERE id = ?';

    db.query(query, [userId], (err, results) => {
        if (err) { return next(err); }

        if (results.length > 0) {
            res.json(results[0]);
        } else {
            res.status(404).send('User not found.');
        }
    });
});

// API endpoint to UPDATE user profile data
app.post('/api/user/profile', requireLogin, (req, res, next) => {
    const { email, phone_number } = req.body;
    const userId = req.session.userId;

    // Basic validation
    if (!email || !phone_number) {
        return res.status(400).json({ success: false, message: 'Email and phone number are required.' });
    }

    const query = 'UPDATE users SET email = ?, phone_number = ? WHERE id = ?';
    db.query(query, [email, phone_number, userId], (err, result) => {
        if (err) {
            // Check for duplicate email entry
            if (err.code === 'ER_DUP_ENTRY') {
                return res.status(409).json({ success: false, message: 'This email address is already in use.' });
            }
            return next(err);
        }
        res.json({ success: true, message: 'Profile updated successfully!' });
    });
});

// API endpoint to UPDATE notification preferences
app.post('/api/user/preferences', requireLogin, (req, res, next) => {
    const { preference, value } = req.body;
    const userId = req.session.userId;

    // Whitelist valid preference columns to prevent SQL injection
    const validPreferences = ['notify_updates', 'notify_alerts', 'notify_promo'];
    if (!validPreferences.includes(preference)) {
        return res.status(400).json({ success: false, message: 'Invalid preference key.' });
    }

    // Ensure value is a boolean
    const booleanValue = value === true || value === 'true';

    const query = `UPDATE users SET ${preference} = ? WHERE id = ?`;
    db.query(query, [booleanValue, userId], (err, result) => {
        if (err) { return next(err); }
        res.json({ success: true, message: 'Preference saved.' });
    });
});

// API endpoint to CHANGE user password
app.post('/api/user/change-password', requireLogin, (req, res, next) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.session.userId;

    if (!currentPassword || !newPassword) {
        return res.status(400).json({ success: false, message: 'All password fields are required.' });
    }

    // 1. Get the current hashed password from the database
    const getPasswordQuery = 'SELECT password FROM users WHERE id = ?';
    db.query(getPasswordQuery, [userId], (err, results) => {
        if (err) { return next(err); }
        if (results.length === 0) { return res.status(404).json({ success: false, message: 'User not found.' }); }

        const hashedPassword = results[0].password;

        // 2. Compare the submitted current password with the one in the DB
        bcrypt.compare(currentPassword, hashedPassword, (compareErr, isMatch) => {
            if (compareErr) { return next(compareErr); }

            if (!isMatch) {
                return res.status(401).json({ success: false, message: 'Incorrect current password.' });
            }

            // 3. If they match, hash the new password
            const saltRounds = 10;
            bcrypt.hash(newPassword, saltRounds, (hashErr, newHashedPassword) => {
                if (hashErr) { return next(hashErr); }

                // 4. Update the database with the new hashed password
                const updateQuery = 'UPDATE users SET password = ? WHERE id = ?';
                db.query(updateQuery, [newHashedPassword, userId], (updateErr, updateResult) => {
                    if (updateErr) {
                        return res.status(500).json({ success: false, message: 'Failed to update password.' });
                    }
                    createNotification(userId, 'password_change', 'Your password was changed successfully.');
                    logger.info(`User ${userId} changed their password successfully.`);
                    res.json({ success: true, message: 'Password updated successfully!' });
                });
            });
        });
    });
});

// API for dashboard stats (now using real data)
app.get('/api/dashboard/stats', requireLogin, (req, res, next) => {
    const userId = req.session.userId;

    const balanceQuery = 'SELECT balance FROM users WHERE id = ?';
    const investmentQuery = "SELECT SUM(amount) AS totalInvestment, SUM(expected_return) AS totalProfit, COUNT(id) AS activePlans FROM investments WHERE user_id = ? AND status = 'Active'";
    const expiringQuery = "SELECT COUNT(id) AS expiringCount FROM investments WHERE user_id = ? AND status = 'Active' AND end_date BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 30 DAY)";
    const recentInvestmentQuery = "SELECT SUM(amount) AS recentInvestment FROM investments WHERE user_id = ? AND start_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)";
    const balanceTrendQuery = `
        SELECT 
            (SELECT COALESCE(SUM(amount), 0) FROM deposits WHERE user_id = ? AND request_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)) - 
            (SELECT COALESCE(SUM(amount), 0) FROM withdrawals WHERE user_id = ? AND request_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)) 
        AS netChange
    `;

    db.query(balanceQuery, [userId], (err, balanceResults) => {
        if (err) { return next(err); }

        db.query(investmentQuery, [userId], (err, investmentResults) => {
            if (err) { return next(err); }

            db.query(expiringQuery, [userId], (err, expiringResults) => {
                if (err) { return next(err); }

                db.query(recentInvestmentQuery, [userId], (err, recentInvestmentResults) => {
                    if (err) { return next(err); }

                    db.query(balanceTrendQuery, [userId, userId], (err, balanceTrendResults) => {
                        if (err) { return next(err); }

                        const totalInvestment = parseFloat(investmentResults[0].totalInvestment) || 0;
                        const totalProfit = parseFloat(investmentResults[0].totalProfit) || 0;
                        const recentInvestment = parseFloat(recentInvestmentResults[0].recentInvestment) || 0;

                        const stats = {
                            totalBalance: balanceResults.length > 0 ? balanceResults[0].balance : 0,
                            totalInvestment: totalInvestment,
                            totalProfit: totalProfit,
                            activePlans: investmentResults[0].activePlans || 0,
                            // Trend data
                            balanceTrend: balanceTrendResults[0].netChange || 0,
                            investmentTrendPercent: totalInvestment > 0 ? (recentInvestment / totalInvestment) * 100 : 0,
                            profitRoiPercent: totalInvestment > 0 ? (totalProfit / totalInvestment) * 100 : 0,
                            expiringPlans: expiringResults[0].expiringCount || 0
                        };

                        res.json(stats);
                    });
                });
            });
        });
    });
});

// API for portfolio investments
app.get('/api/portfolio/investments', requireLogin, (req, res, next) => {
    const userId = req.session.userId;
    const query = `
        SELECT p.name AS package_name, i.amount, i.status, i.start_date, i.end_date, i.expected_return 
        FROM investments i
        JOIN plans p ON i.plan_id = p.id
        WHERE i.user_id = ? ORDER BY i.start_date DESC
    `;

    db.query(query, [userId], (err, results) => {
        if (err) { return next(err); }

        let totalInvested = 0;
        let totalProfit = 0;

        const today = new Date();
        const investments = results.map(inv => {
            if (inv.status.toLowerCase() === 'active' || inv.status.toLowerCase() === 'completed') {
                totalInvested += parseFloat(inv.amount);
                totalProfit += parseFloat(inv.expected_return);
            }

            const startDate = new Date(inv.start_date);
            const endDate = new Date(inv.end_date);
            const totalDuration = endDate.getTime() - startDate.getTime();
            const elapsedDuration = today.getTime() - startDate.getTime();
            
            let progress = 0;
            if (totalDuration > 0) {
                progress = Math.min(100, (elapsedDuration / totalDuration) * 100);
            }
            if (today >= endDate || inv.status === 'Completed') {
                progress = 100;
            }

            return {
                name: inv.package_name,
                amount: inv.amount,
                profit: inv.expected_return,
                startDate: inv.start_date,
                endDate: inv.end_date,
                status: inv.status,
                progress: progress.toFixed(0)
            };
        });

        const response = {
            summary: {
                totalInvested: totalInvested,
                totalProfit: totalProfit,
                totalValue: totalInvested + totalProfit
            },
            investments: investments
        };

        res.json(response);
    });
});

// API for recent transactions (deposits and withdrawals)
app.get('/api/dashboard/transactions', requireLogin, (req, res, next) => {
    const userId = req.session.userId;
    // This query combines deposits and withdrawals into a single feed
    const query = `
        (SELECT id, 'Deposit' as type, method as plan, amount, request_date as date, status FROM deposits WHERE user_id = ?)
        UNION ALL
        (SELECT id, 'Withdrawal' as type, method as plan, amount, request_date as date, status FROM withdrawals WHERE user_id = ?)
        ORDER BY date DESC
        LIMIT 10
    `;
    db.query(query, [userId, userId], (err, results) => {
        if (err) { return next(err); }
        res.json(results);
    });
});

// API to get available investment packages
app.get('/api/packages', requireLogin, (req, res, next) => {
    // Fetch packages from the database instead of a hardcoded array
    // Using GROUP BY to ensure each plan name appears only once, even if there are duplicates in the DB.
    // It selects the one with the lowest ID as the canonical version.
    const query = `
        SELECT p1.id, p1.name, p1.description, p1.min_amount, p1.max_amount, p1.return_rate AS roi_percent, p1.duration_days FROM plans p1
        INNER JOIN (SELECT name, MIN(id) as id FROM plans WHERE status = 'active' GROUP BY name) p2 ON p1.name = p2.name AND p1.id = p2.id
        ORDER BY p1.min_amount ASC`;
    db.query(query, (err, results) => {
        if (err) { return next(err); }
        res.json(results);
    });
});

// API to handle a new investment
app.post('/api/invest', requireLogin, (req, res, next) => {
    const { packageId, amount } = req.body;
    const userId = req.session.userId;
    const investmentAmount = parseFloat(amount); // Convert amount to a number


    // 2. Fetch the selected package from the DB and check user balance in a transaction
    const getPackageQuery = "SELECT id, name, min_amount, max_amount, return_rate, duration_days FROM plans WHERE id = ? AND status = 'active'";
    db.query(getPackageQuery, [packageId], (err, packages) => {
        if (err) { return next(err); }
        if (packages.length === 0) {
            return res.status(404).json({ success: false, message: 'Investment package not found or is inactive.' });
        }
        const selectedPackage = packages[0];

        if (isNaN(investmentAmount) || investmentAmount <= 0) {
            return res.status(400).json({ success: false, message: 'Invalid investment amount.' });
        }

        if (investmentAmount < selectedPackage.min_amount || investmentAmount > selectedPackage.max_amount) {
            return res.status(400).json({ success: false, message: `Investment amount must be between $${selectedPackage.min_amount} and $${selectedPackage.max_amount}.` });
        }

        db.getConnection((err, connection) => {
            if (err) { return next(err); }

            connection.beginTransaction(err => {
                if (err) { connection.release(); return next(err); }

                connection.query('SELECT balance FROM users WHERE id = ? FOR UPDATE', [userId], (err, results) => {
                    if (err || results.length === 0) {
                        return connection.rollback(() => { connection.release(); res.status(404).json({ success: false, message: 'User not found.' }); });
                    }
                    if (results[0].balance < investmentAmount) {
                        return connection.rollback(() => { connection.release(); res.status(400).json({ success: false, message: 'Insufficient balance.' }); });
                    }

                    const newBalance = results[0].balance - investmentAmount;
                    connection.query('UPDATE users SET balance = ? WHERE id = ?', [newBalance, userId], (err, result) => {
                        if (err) { return connection.rollback(() => { connection.release(); next(err); }); }

                        const startDate = new Date();
                        const endDate = new Date();
                        endDate.setDate(startDate.getDate() + selectedPackage.duration_days);
                        const expectedReturn = investmentAmount * (selectedPackage.return_rate / 100);

                        const investmentQuery = 'INSERT INTO investments (user_id, plan_id, amount, start_date, end_date, expected_return) VALUES (?, ?, ?, ?, ?, ?)';
                        connection.query(investmentQuery, [userId, selectedPackage.id, investmentAmount, startDate, endDate, expectedReturn], (err, result) => {
                            if (err) { return connection.rollback(() => { connection.release(); next(err); }); }

                            connection.commit(err => {
                                if (err) { return connection.rollback(() => { connection.release(); next(err); }); }
                                
                                connection.release();
                                createNotification(userId, 'investment_start', `You invested $${investmentAmount} in the ${selectedPackage.name}.`);
                                logger.info(`User ${userId} invested ${investmentAmount} in package ${selectedPackage.id}.`);

                                // Send email notification to admin
                                const mailOptions = {
                                    from: '"WINNING EDGE" <noreply@winningedgeinvestment.com>',
                                    to: ADMIN_EMAIL,
                                    subject: 'New Investment Created',
                                    html: `
                                        <div style="font-family: sans-serif; padding: 20px; background-color: #f4f4f4;">
                                            <h2 style="color: #1a2a6c;">New Investment Notification</h2>
                                            <p>A user has successfully made a new investment.</p>
                                            <hr>
                                            <p><strong>User ID:</strong> ${userId}</p>
                                            <p><strong>Full Name:</strong> ${req.session.userName}</p>
                                            <p><strong>Username:</strong> ${req.session.userUsername}</p>
                                            <p><strong>Package:</strong> ${selectedPackage.name}</p>
                                            <p><strong>Amount Invested:</strong> ${formatCurrency(investmentAmount)}</p>
                                            <hr>
                                            <p>This is an automated notification. No action is required.</p>
                                        </div>
                                    `
                                };
                                transporter.sendMail(mailOptions, (emailErr) => {
                                    if (emailErr) logger.error(`Error sending new investment email to admin: ${emailErr.message}`);
                                });

                                res.json({ success: true, message: `Successfully invested $${investmentAmount} in the ${selectedPackage.name}!` });
                            });
                        });
                    });
                });
            });
        });
    });
});

// Helper to format currency for emails
const formatCurrency = (amount) => {
    return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(amount);
};

// API for analytics data (mock data)
app.get('/api/analytics/data', requireLogin, (req, res, next) => {
    const userId = req.session.userId;
    const query = `
        SELECT p.name AS package_name, i.amount, i.status, i.start_date, i.end_date, i.expected_return 
        FROM investments i
        JOIN plans p ON i.plan_id = p.id
        WHERE i.user_id = ?
    `;

    db.query(query, [userId], (err, results) => {
        if (err) { return next(err); }

        let totalReturn = 0;
        let highestValue = 0;
        let totalInvested = 0;
        let totalDurationDays = 0;
        const assetAllocation = {};

        results.forEach(inv => {
            const status = inv.status.toLowerCase();
            if (status === 'active' || status === 'completed') {
                const amount = parseFloat(inv.amount);
                totalReturn += parseFloat(inv.expected_return);
                totalInvested += amount;
                
                if (amount > highestValue) {
                    highestValue = amount;
                }

                const startDate = new Date(inv.start_date);
                const endDate = new Date(inv.end_date);
                const duration = (endDate.getTime() - startDate.getTime()) / (1000 * 3600 * 24);
                totalDurationDays += duration;

                assetAllocation[inv.package_name] = (assetAllocation[inv.package_name] || 0) + amount;
            }
        });

        const averageDailyGain = totalDurationDays > 0 ? totalReturn / totalDurationDays : 0;
        const annualizedReturn = totalInvested > 0 ? (averageDailyGain * 365 / totalInvested) : 0;

        const kpis = {
            totalReturn: totalReturn,
            annualizedReturn: annualizedReturn,
            highestValue: highestValue,
            averageDailyGain: averageDailyGain
        };

        // --- Calculate Real Portfolio Growth ---
        // Sort investments by start date to build a timeline
        const sortedInvestments = results.sort((a, b) => new Date(a.start_date) - new Date(b.start_date));
        
        let cumulativeValue = 0;
        const growthData = sortedInvestments.map(inv => {
            cumulativeValue += parseFloat(inv.amount);
            return {
                date: new Date(inv.start_date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
                value: cumulativeValue
            };
        });

        const portfolioGrowth = {
            labels: growthData.map(d => d.date),
            data: growthData.map(d => d.value)
        };

        res.json({ kpis, portfolioGrowth, assetAllocation: {
            labels: Object.keys(assetAllocation),
            data: Object.values(assetAllocation)
        }});
    });
});

// API endpoint to get deposit wallet addresses
app.get('/api/deposit-info', requireLogin, (req, res, next) => {
    const query = "SELECT setting_key, setting_value FROM settings WHERE setting_key IN ('btc_address', 'ltc_address', 'usdt_address')";
    db.query(query, (err, results) => {
        if (err) { return next(err); }
        const addresses = results.reduce((acc, row) => {
            // Shorten the key for the frontend (e.g., 'btc_address' -> 'btc')
            const shortKey = row.setting_key.replace('_address', '');
            acc[shortKey] = row.setting_value;
            return acc;
        }, {});
        res.json(addresses);
    });
});

// API to get a user's deposit history from the database
app.get('/api/deposits', requireLogin, (req, res, next) => {
    const userId = req.session.userId;
    const query = 'SELECT id, amount, method, status, request_date AS date FROM deposits WHERE user_id = ? ORDER BY request_date DESC';

    db.query(query, [userId], (err, results) => {
        if (err) { return next(err); }
        res.json(results);
    });
});

// API endpoint to handle a new deposit submission
app.post('/api/deposit', requireLogin, (req, res, next) => {
    const { amount, method, txn_id } = req.body;
    const userId = req.session.userId;

    // 1. Basic Validation
    if (!amount || !method || !txn_id) {
        return res.status(400).json({ success: false, message: 'Amount, method, and Transaction ID are required.' });
    }

    // 2. Insert the deposit record into the database with a 'Pending' status
    // NOTE: You need to create a 'deposits' table in your database.
    // SQL for table: CREATE TABLE deposits (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT, full_name VARCHAR(255), amount DECIMAL(10, 2), method VARCHAR(20), txn_id VARCHAR(255), status VARCHAR(20) DEFAULT 'Pending', request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id));
    const query = 'INSERT INTO deposits (user_id, full_name, amount, method, txn_id) VALUES (?, ?, ?, ?, ?)';
    db.query(query, [userId, req.session.userName, amount, method, txn_id], (err, result) => {
        if (err) { return next(err); }

        // 3. Send an email notification to the admin (fire and forget)
        const mailOptions = {
            from: '"WINNING EDGE" <noreply@winningedgeinvestment.com>',
            to: ADMIN_EMAIL,
            subject: 'New Deposit Request Submitted',
            html: `
                <div style="font-family: sans-serif; padding: 20px; background-color: #f4f4f4;">
                    <h2 style="color: #1a2a6c;">New Deposit Request</h2>
                    <p>A new deposit request has been submitted for verification.</p>
                    <hr>
                    <p><strong>User ID:</strong> ${req.session.userId}</p>
                    <p><strong>Full Name:</strong> ${req.session.userName}</p>
                    <p><strong>Username:</strong> ${req.session.userUsername}</p>
                    <p><strong>Amount:</strong> $${amount}</p>
                    <p><strong>Method:</strong> ${method.toUpperCase()}</p>
                    <p><strong>Transaction ID:</strong> ${txn_id}</p>
                    <hr>
                    <p>Please log in to the admin panel to verify and approve this transaction.</p>
                </div>
            `
        };

        transporter.sendMail(mailOptions, (emailErr, info) => {
            if (emailErr) {
                // Log the error, but don't block the user's success response
                logger.error(`Error sending admin deposit notification email: ${emailErr.message}`);
            } else {
                logger.info('Admin deposit notification email sent: ' + info.response);
            }
        });

        // 4. Send a success response to the user
        logger.info(`User ${userId} submitted a deposit request for ${amount} via ${method}.`);
        createNotification(userId, 'deposit_request', `Your deposit request of $${amount} (${method.toUpperCase()}) was submitted.`);
        res.json({ success: true, message: 'Your deposit request has been submitted and will be confirmed shortly.' });
    });
});

// API to get a user's withdrawal history from the database
app.get('/api/withdrawals', requireLogin, (req, res, next) => {
    const userId = req.session.userId;
    const query = 'SELECT id, amount, method, status, request_date AS date FROM withdrawals WHERE user_id = ? ORDER BY request_date DESC';

    db.query(query, [userId], (err, results) => {
        if (err) { return next(err); }
        res.json(results);
    });
});

// API endpoint to handle a new withdrawal request
app.post('/api/withdrawal', requireLogin, (req, res, next) => {
    const { amount, method, wallet_address } = req.body;
    const userId = req.session.userId;

    const withdrawalAmount = parseFloat(amount);

    if (!withdrawalAmount || withdrawalAmount <= 0 || !method || !wallet_address) {
        return res.status(400).json({ success: false, message: 'A valid amount, method, and wallet address are required.' });
    }

    db.getConnection((err, connection) => {
        if (err) { return next(err); }

        connection.beginTransaction(err => {
            if (err) { connection.release(); return next(err); }

            // 1. Check balance and lock the user row
            connection.query('SELECT balance FROM users WHERE id = ? FOR UPDATE', [userId], (err, results) => {
                if (err || results.length === 0) {
                    return connection.rollback(() => { connection.release(); res.status(404).json({ success: false, message: 'User not found.' }); });
                }
                if (results[0].balance < withdrawalAmount) {
                    return connection.rollback(() => { connection.release(); res.status(400).json({ success: false, message: 'Insufficient balance for this withdrawal.' }); });
                }

                // 2. Deduct balance
                const newBalance = results[0].balance - withdrawalAmount;
                connection.query('UPDATE users SET balance = ? WHERE id = ?', [newBalance, userId], (err, updateResult) => {
                    if (err) { return connection.rollback(() => { connection.release(); res.status(500).json({ success: false, message: 'Failed to update balance.' }); }); }

                    // 3. Create withdrawal request
                    const withdrawalQuery = 'INSERT INTO withdrawals (user_id, full_name, amount, method, wallet_address) VALUES (?, ?, ?, ?, ?)';
                    connection.query(withdrawalQuery, [userId, req.session.userName, withdrawalAmount, method, wallet_address], (err, withdrawalResult) => {
                        if (err) { return connection.rollback(() => { connection.release(); res.status(500).json({ success: false, message: 'Failed to create withdrawal request.' }); }); }

                        // 4. Commit transaction
                        connection.commit(err => {
                            if (err) { return connection.rollback(() => { connection.release(); res.status(500).json({ success: false, message: 'Failed to commit transaction.' }); }); }
                            connection.release();

                            // 5. Send notifications (email, etc.)
                            const mailOptions = {
                                from: '"WINNING EDGE" <noreply@winningedgeinvestment.com>',
                                to: ADMIN_EMAIL,
                                subject: 'New Withdrawal Request Submitted',
                                html: `<p>A new withdrawal request of ${formatCurrency(withdrawalAmount)} has been submitted by ${req.session.userName} (ID: ${userId}). The amount has been deducted from their balance pending approval.</p>`
                            };
                            transporter.sendMail(mailOptions, (emailErr) => {
                                if (emailErr) logger.error(`Error sending withdrawal notification email: ${emailErr.message}`);
                            });

                            createNotification(userId, 'withdrawal_request', `Your withdrawal request of ${formatCurrency(withdrawalAmount)} was submitted.`);
                            logger.info(`User ${userId} submitted a withdrawal request for ${withdrawalAmount}.`);
                            res.json({ success: true, message: 'Your withdrawal request has been submitted and will be processed shortly.' });
                        });
                    });
                });
            });
        });
    });
});

// API to get count of pending notifications for the user
app.get('/api/notifications/count', requireLogin, (req, res, next) => {
    const userId = req.session.userId;
    // This now counts unread notifications from the new table
    const query = "SELECT COUNT(*) AS count FROM notifications WHERE user_id = ? AND is_read = FALSE";

    db.query(query, [userId], (err, results) => {
        if (err) { return next(err); }
        res.json({ count: results[0].count });
    });
});

// API to get recent notifications for the user
app.get('/api/notifications', requireLogin, (req, res, next) => {
    const userId = req.session.userId;
    const query = "SELECT id, message, type, is_read, created_at FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 10";

    db.query(query, [userId], (err, results) => {
        if (err) { return next(err); }
        res.json(results);
    });
});

// API to mark notifications as read
app.post('/api/notifications/mark-read', requireLogin, (req, res, next) => {
    const userId = req.session.userId;
    const query = "UPDATE notifications SET is_read = TRUE WHERE user_id = ? AND is_read = FALSE";

    db.query(query, [userId], (err, result) => {
        if (err) { return next(err); }
        res.json({ success: true });
    });
});

// --- Support Ticket API Endpoints ---

// Get all support tickets for a user
app.get('/api/support/tickets', requireLogin, (req, res, next) => {
    const userId = req.session.userId;
    const query = 'SELECT id, subject, status, updated_at FROM support_tickets WHERE user_id = ? ORDER BY updated_at DESC';
    db.query(query, [userId], (err, results) => {
        if (err) { return next(err); }
        res.json(results);
    });
});

// Get a single ticket and its messages
app.get('/api/support/tickets/:id', requireLogin, (req, res, next) => {
    const ticketId = req.params.id;
    const userId = req.session.userId;

    // First, verify the user owns this ticket
    const ticketQuery = 'SELECT * FROM support_tickets WHERE id = ? AND user_id = ?';
    db.query(ticketQuery, [ticketId, userId], (err, ticketResult) => {
        if (err || ticketResult.length === 0) {
            return res.status(404).json({ message: 'Ticket not found or access denied.' });
        }

        const messagesQuery = 'SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC';
        db.query(messagesQuery, [ticketId], (err, messagesResult) => {
            if (err) { return next(err); }
            res.json({ ticket: ticketResult[0], messages: messagesResult });
        });
    });
});

// Create a new support ticket
app.post('/api/support/tickets', requireLogin, (req, res, next) => {
    const { subject, message } = req.body;
    const userId = req.session.userId;

    if (!subject || !message) {
        return res.status(400).json({ success: false, message: 'Subject and message are required.' });
    }

    db.getConnection((err, connection) => {
        if (err) { return next(err); }

        connection.beginTransaction(err => {
            if (err) { connection.release(); return next(err); }

            const ticketQuery = 'INSERT INTO support_tickets (user_id, subject) VALUES (?, ?)';
            connection.query(ticketQuery, [userId, subject], (err, ticketResult) => {
                if (err) { return connection.rollback(() => { connection.release(); next(err); }); }

                const ticketId = ticketResult.insertId;
                const messageQuery = 'INSERT INTO ticket_messages (ticket_id, user_id, message) VALUES (?, ?, ?)';
                connection.query(messageQuery, [ticketId, userId, message], (err, messageResult) => {
                    if (err) { return connection.rollback(() => { connection.release(); next(err); }); }

                    connection.commit(err => {
                        if (err) { return connection.rollback(() => { connection.release(); next(err); }); }
                        
                        connection.release();

                        // Send admin email notification
                        const mailOptions = {
                            from: '"WINNING EDGE Support" <noreply@winningedgeinvestment.com>',
                            to: ADMIN_EMAIL,
                            subject: `New Support Ticket #${ticketId}: ${subject}`,
                            html: `<p>A new support ticket has been created by user ${req.session.userName} (ID: ${userId}).</p><p><strong>Subject:</strong> ${subject}</p><p><strong>Message:</strong></p><p>${message}</p><p>Please log in to the admin panel to respond.</p>`
                        };
                        transporter.sendMail(mailOptions, (emailErr) => {
                            if (emailErr) logger.error(`Error sending support ticket email notification: ${emailErr.message}`);
                        });

                        createNotification(userId, 'support_ticket', `Your support ticket #${ticketId} was created.`);
                        logger.info(`User ${userId} created support ticket #${ticketId}.`);
                        res.status(201).json({ success: true, message: 'Support ticket created successfully!' });
                    });
                });
            });
        });
    });
});

// User replies to a ticket
app.post('/api/support/tickets/:id/reply', requireLogin, (req, res, next) => {
    const ticketId = req.params.id;
    const userId = req.session.userId;
    const { message } = req.body;

    if (!message) {
        return res.status(400).json({ success: false, message: 'Reply message cannot be empty.' });
    }

    // Verify the user owns the ticket before proceeding
    db.query('SELECT id FROM support_tickets WHERE id = ? AND user_id = ?', [ticketId, userId], (err, ticketResult) => {
        if (err || ticketResult.length === 0) {
            return res.status(404).json({ success: false, message: 'Ticket not found or access denied.' });
        }

        const insertQuery = 'INSERT INTO ticket_messages (ticket_id, user_id, message, is_admin_reply) VALUES (?, ?, ?, ?)';
        const updateQuery = "UPDATE support_tickets SET status = 'Open', updated_at = CURRENT_TIMESTAMP WHERE id = ?";

        db.query(insertQuery, [ticketId, userId, message, false], (err, result) => {
            if (err) { return next(err); }
            db.query(updateQuery, [ticketId]); // Update status back to 'Open'
            
            // Optionally, notify admin via email here
            logger.info(`User ${userId} replied to ticket ${ticketId}.`);
            res.json({ success: true, message: 'Reply sent successfully.' });
        });
    });
});

// API endpoint to handle contact form submissions
app.post('/api/contact', (req, res, next) => {
    const { firstName, lastName, email, subject, message } = req.body;

    // Basic server-side validation
    if (!firstName || !lastName || !email || !subject || !message) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    const fullName = `${firstName} ${lastName}`;

    // Prepare email for the admin
    const mailOptions = {
        from: `"WINNING EDGE Contact Form" <${process.env.SMTP_USER}>`,
        to: ADMIN_EMAIL,
        subject: `New Contact Form Submission: ${subject}`,
        replyTo: email, // So admin can reply directly to the user
        html: `
            <div style="font-family: Arial, sans-serif; line-height: 1.6;">
                <h2 style="color: #1a2a6c;">New Message from Website Contact Form</h2>
                <p>You have received a new message from the contact form on your website.</p>
                <hr>
                <p><strong>Name:</strong> ${fullName}</p>
                <p><strong>Email:</strong> <a href="mailto:${email}">${email}</a></p>
                <p><strong>Subject:</strong> ${subject}</p>
                <p><strong>Message:</strong></p>
                <div style="background-color: #f4f4f4; padding: 15px; border-radius: 5px; border: 1px solid #ddd;">
                    <p style="margin: 0;">${message.replace(/\n/g, '<br>')}</p>
                </div>
                <hr>
                <p style="font-size: 0.9em; color: #777;">This email was sent from the contact form on winningedgeinvestment.com.</p>
            </div>
        `
    };

    // Send the email
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            logger.error(`Contact form email failed to send: ${error.message}`);
            return next(error); // Pass to error handler
        }
        logger.info(`Contact form message sent from ${email}. Message ID: ${info.messageId}`);
        res.json({ success: true, message: 'Your message has been sent successfully!' });
    });
});

// Handle user logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return next(err);
        }
        // Redirect to the login page after destroying the session
        res.redirect('/login.html');
    });
});

// --- Automated Task to Process Completed Investments ---
const processCompletedInvestments = () => {
    logger.info('Running scheduled task: Processing completed investments...');

    db.getConnection((err, connection) => {
        if (err) {
            logger.error('Could not get connection for investment processing task:', err);
            return;
        }

        // Find all active investments that have reached their end date
        const findQuery = "SELECT * FROM investments WHERE status = 'active' AND end_date <= CURDATE()";
        connection.query(findQuery, (err, investments) => {
            if (err) {
                logger.error('Error finding completed investments:', err);
                connection.release();
                return;
            }

            if (investments.length === 0) {
                logger.info('No investments to process.');
                connection.release();
                return;
            }

            console.log(`Found ${investments.length} investments to process.`);

            investments.forEach(inv => {
                const payoutAmount = parseFloat(inv.amount) + parseFloat(inv.expected_return);

                connection.beginTransaction(txErr => {
                    if (txErr) { logger.error('Transaction start error for inv ID ' + inv.id, txErr); return; }

                    // 1. Update user's balance
                    const balanceQuery = 'UPDATE users SET balance = balance + ? WHERE id = ?';
                    connection.query(balanceQuery, [payoutAmount, inv.user_id], (err, result) => {
                        if (err) { return connection.rollback(() => logger.error('Balance update failed for inv ID ' + inv.id, err)); }

                        // 2. Update investment status to 'completed'
                        const statusQuery = "UPDATE investments SET status = 'completed' WHERE id = ?";
                        connection.query(statusQuery, [inv.id], (err, result) => {
                            if (err) { return connection.rollback(() => logger.error('Status update failed for inv ID ' + inv.id, err)); }

                            connection.commit(commitErr => {
                                if (commitErr) { return connection.rollback(() => logger.error('Commit failed for inv ID ' + inv.id, commitErr)); }
                                
                                console.log(`Successfully processed investment ID: ${inv.id} for user ID: ${inv.user_id}. Payout: ${payoutAmount}`);
                                createNotification(inv.user_id, 'investment_completed', `Your investment of ${formatCurrency(inv.amount)} has matured. ${formatCurrency(payoutAmount)} has been added to your balance.`);
                            });
                        });
                    });
                });
            });

            connection.release();
        });
    });
};


// --- Start the Server ---
if (require.main === module) {
    app.listen(port, () => {
        logger.info(`Server running at http://localhost:${port}`);
        logger.info(`Login Portal: http://localhost:${port}/login.html`);
        logger.info(`Signup Portal: http://localhost:${port}/signup.html`);
        logger.info(`Admin Login: http://localhost:${port}/admin-login.html`);

        // Run the investment processing task every hour (3600000 milliseconds)
        setInterval(processCompletedInvestments, 3600000);
        // Also run it once on server startup after a short delay
        setTimeout(processCompletedInvestments, 5000);
    });
}

module.exports = app;

// --- Centralized Error Handling Middleware ---
// This should be the LAST middleware added to the app.
app.use((err, req, res, next) => {
    // Log the full error internally
    logger.error(`${err.status || 500} - ${err.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
    logger.error(err.stack);

    // Don't leak stack trace to client in production
    if (process.env.NODE_ENV === 'production') {
        // For API requests, send a generic JSON error
        if (req.originalUrl.startsWith('/api/')) {
            return res.status(500).json({ success: false, message: 'An internal server error occurred. Please try again later.' });
        }
        // For page requests, you could render a generic error page
        return res.status(500).send('<h1>500 - Internal Server Error</h1><p>Something went wrong. Please try again later.</p>');
    }

    // In development, send back a more detailed error
    res.status(err.status || 500);
    res.json({
        error: { message: err.message, stack: err.stack }
    });
});