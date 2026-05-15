const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// MySQL Connection
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const promisePool = pool.promise();

// Middleware
app.use(cors({
    origin: '*',
    credentials: true
}));
app.use(express.json({ limit: '50mb' }));

// Helper Functions
function generateUserId() { 
    return 'GBS-' + Date.now() + '-' + Math.floor(Math.random() * 1000); 
}

function generateDonationId() { 
    return 'DON-' + Date.now() + '-' + Math.floor(Math.random() * 1000); 
}

function generateEventId() { 
    return 'EVT-' + Date.now() + '-' + Math.floor(Math.random() * 1000); 
}

function generateMessageId() { 
    return 'MSG-' + Date.now() + '-' + Math.floor(Math.random() * 1000); 
}

// Authentication Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid or expired token.' });
    }
}

async function verifyAdmin(req, res, next) {
    try {
        if (req.user.role === 'admin') {
            next();
        } else {
            res.status(403).json({ error: 'Admin access required.' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
}

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        const [existing] = await promisePool.query('SELECT * FROM users WHERE email = ?', [email]);
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Email already registered' });
        }
        
        const userId = generateUserId();
        const hashedPassword = await bcrypt.hash(password, 10);
        
        await promisePool.query(
            'INSERT INTO users (user_id, name, email, password, role) VALUES (?, ?, ?, ?, ?)',
            [userId, name, email, hashedPassword, 'user']
        );
        
        const token = jwt.sign(
            { userId, email, name, role: 'user' },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRE }
        );
        
        res.json({ 
            success: true, 
            token, 
            user: { id: userId, name, email, role: 'user', bio: '' } 
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const [users] = await promisePool.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign(
            { userId: user.user_id, email: user.email, name: user.name, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRE }
        );
        
        res.json({
            success: true,
            token,
            user: {
                id: user.user_id,
                name: user.name,
                email: user.email,
                role: user.role,
                bio: user.bio || ''
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get Profile
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const [users] = await promisePool.query(
            'SELECT user_id, name, email, bio, role FROM users WHERE user_id = ?',
            [req.user.userId]
        );
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(users[0]);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Update Profile
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const { name, bio } = req.body;
        await promisePool.query(
            'UPDATE users SET name = ?, bio = ? WHERE user_id = ?',
            [name, bio, req.user.userId]
        );
        res.json({ success: true, message: 'Profile updated' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== DONATION ROUTES ====================

// Submit Donation
app.post('/api/donations', authenticateToken, async (req, res) => {
    try {
        const { donorName, type, details, amount, image } = req.body;
        const donationId = generateDonationId();
        
        await promisePool.query(
            `INSERT INTO donations (donation_id, user_id, donor_name, donor_email, type, details, amount, image, status)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [donationId, req.user.userId, donorName, req.user.email, type, details, amount || null, image || null, 'Pending']
        );
        
        res.json({ success: true, donationId, message: 'Donation submitted successfully' });
    } catch (error) {
        console.error('Donation POST error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get User's Donations
app.get('/api/donations/my', authenticateToken, async (req, res) => {
    try {
        const [donations] = await promisePool.query(
            'SELECT * FROM donations WHERE user_id = ? ORDER BY created_at DESC',
            [req.user.userId]
        );
        res.json(donations);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get All Donations (Admin)
app.get('/api/donations/all', authenticateToken, verifyAdmin, async (req, res) => {
    try {
        const [donations] = await promisePool.query('SELECT * FROM donations ORDER BY created_at DESC');
        res.json(donations);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Update Donation Status (Admin)
app.put('/api/donations/:id/status', authenticateToken, verifyAdmin, async (req, res) => {
    try {
        const { status, rejectionReason } = req.body;
        await promisePool.query(
            'UPDATE donations SET status = ?, rejection_reason = ? WHERE donation_id = ?',
            [status, rejectionReason || null, req.params.id]
        );
        res.json({ success: true, message: 'Status updated' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete Donation (Admin)
app.delete('/api/donations/:id', authenticateToken, verifyAdmin, async (req, res) => {
    try {
        await promisePool.query('DELETE FROM donations WHERE donation_id = ?', [req.params.id]);
        res.json({ success: true, message: 'Donation deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get Donation Stats
app.get('/api/donations/stats', async (req, res) => {
    try {
        const [approvedMoney] = await promisePool.query(
            "SELECT SUM(amount) as total FROM donations WHERE type = 'Money' AND status = 'Approved'"
        );
        const [donors] = await promisePool.query(
            'SELECT COUNT(DISTINCT user_id) as count FROM donations WHERE status = "Approved"'
        );
        const [items] = await promisePool.query(
            "SELECT COUNT(*) as count FROM donations WHERE type IN ('Items', 'Cleaning') AND status = 'Approved'"
        );
        
        res.json({
            approvedMoney: approvedMoney[0].total || 0,
            totalDonors: donors[0].count || 0,
            itemsPledged: items[0].count || 0
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== EVENT ROUTES ====================

// Get All Events
app.get('/api/events', async (req, res) => {
    try {
        const [events] = await promisePool.query('SELECT * FROM events ORDER BY deadline DESC');
        res.json(events);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get Active Events
app.get('/api/events/active', async (req, res) => {
    try {
        const [events] = await promisePool.query(
            "SELECT * FROM events WHERE deadline > NOW() ORDER BY deadline ASC"
        );
        res.json(events);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Create Event (Admin)
app.post('/api/events', authenticateToken, verifyAdmin, async (req, res) => {
    try {
        const { title, description, deadline } = req.body;
        const eventId = generateEventId();
        
        await promisePool.query(
            'INSERT INTO events (event_id, title, description, deadline) VALUES (?, ?, ?, ?)',
            [eventId, title, description, deadline]
        );
        
        res.json({ success: true, eventId, message: 'Event created' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Update Event (Admin)
app.put('/api/events/:id', authenticateToken, verifyAdmin, async (req, res) => {
    try {
        const { title, description, deadline } = req.body;
        await promisePool.query(
            'UPDATE events SET title = ?, description = ?, deadline = ? WHERE event_id = ?',
            [title, description, deadline, req.params.id]
        );
        res.json({ success: true, message: 'Event updated' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete Event (Admin)
app.delete('/api/events/:id', authenticateToken, verifyAdmin, async (req, res) => {
    try {
        await promisePool.query('DELETE FROM events WHERE event_id = ?', [req.params.id]);
        res.json({ success: true, message: 'Event deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== MESSAGE ROUTES ====================

// Send Message
app.post('/api/messages', async (req, res) => {
    try {
        const { senderName, senderEmail, messageText } = req.body;
        const messageId = generateMessageId();
        const [result] = await promisePool.query(
            'INSERT INTO messages (message_id, sender_name, sender_email, message_text) VALUES (?, ?, ?, ?)',
            [messageId, senderName, senderEmail, messageText]
        );
        res.json({ success: true, messageId, id: result.insertId });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get User Messages
app.get('/api/messages/my', authenticateToken, async (req, res) => {
    try {
        const [messages] = await promisePool.query(
            'SELECT * FROM messages WHERE sender_email = ? OR for_user = ? ORDER BY created_at DESC',
            [req.user.email, req.user.email]
        );
        res.json(messages);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get All Messages (Admin)
app.get('/api/messages/all', authenticateToken, verifyAdmin, async (req, res) => {
    try {
        const [messages] = await promisePool.query('SELECT * FROM messages ORDER BY created_at DESC');
        res.json(messages);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Reply to Message (Admin)
app.put('/api/messages/:id/reply', authenticateToken, verifyAdmin, async (req, res) => {
    try {
        const { reply } = req.body;
        const identifier = req.params.id;
        console.log('Replying to identifier:', identifier);
        
        // Find message by either numeric id or string message_id
        const [msg] = await promisePool.query(
            'SELECT sender_email FROM messages WHERE id = ? OR message_id = ?',
            [identifier, identifier]
        );
        if (msg.length === 0) {
            return res.status(404).json({ error: 'Message not found' });
        }
        const forUser = msg[0].sender_email;
        
        // Update using the same condition (id or message_id)
        await promisePool.query(
            'UPDATE messages SET reply = ?, for_user = ? WHERE id = ? OR message_id = ?',
            [reply, forUser, identifier, identifier]
        );
        
        res.json({ success: true, message: 'Reply sent' });
    } catch (error) {
        console.error('Reply error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ==================== ADMIN ROUTES ====================

// Get Donation Goal
app.get('/api/admin/goal', async (req, res) => {
    try {
        const [goal] = await promisePool.query(
            "SELECT setting_value FROM admin_settings WHERE setting_key = 'donation_goal'"
        );
        res.json({ goal: goal[0]?.setting_value || 350000 });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Update Donation Goal (Admin)
app.put('/api/admin/goal', authenticateToken, verifyAdmin, async (req, res) => {
    try {
        const { goal } = req.body;
        await promisePool.query(
            "UPDATE admin_settings SET setting_value = ? WHERE setting_key = 'donation_goal'",
            [goal.toString()]
        );
        res.json({ success: true, message: 'Goal updated' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Verify Admin PIN
app.post('/api/admin/verify', async (req, res) => {
    try {
        const { pin } = req.body;
        const [settings] = await promisePool.query(
            "SELECT setting_value FROM admin_settings WHERE setting_key = 'admin_pin'"
        );
        
        if (settings.length > 0 && settings[0].setting_value === pin) {
            const token = jwt.sign(
                { role: 'admin', isAdmin: true },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );
            res.json({ success: true, token });
        } else {
            res.status(401).json({ error: 'Invalid PIN' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Update Admin Password
app.put('/api/admin/password', authenticateToken, verifyAdmin, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        
        const [settings] = await promisePool.query(
            "SELECT setting_value FROM admin_settings WHERE setting_key = 'admin_pin'"
        );
        
        if (settings.length === 0 || settings[0].setting_value !== currentPassword) {
            return res.status(401).json({ error: 'Current password incorrect' });
        }
        
        await promisePool.query(
            "UPDATE admin_settings SET setting_value = ? WHERE setting_key = 'admin_pin'",
            [newPassword]
        );
        
        res.json({ success: true, message: 'Password updated' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== HEALTH CHECK ====================
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Gelan Donate API Server is running', 
        timestamp: new Date().toISOString()
    });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({ 
        name: 'Gelan Donate API',
        version: '1.0.0',
        endpoints: {
            health: 'GET /api/health',
            auth: 'POST /api/auth/register, POST /api/auth/login',
            donations: 'GET/POST /api/donations',
            events: 'GET /api/events'
        }
    });
});

// Start Server
app.listen(PORT, async () => {
    console.log(`\n╔═══════════════════════════════════════════════════════════╗`);
    console.log(`║     🌟 GELAN DONATE BACKEND SERVER 🌟                    ║`);
    console.log(`╠═══════════════════════════════════════════════════════════╣`);
    console.log(`║  🚀 Server running on: http://localhost:${PORT}              ║`);
    console.log(`║  📡 API Base URL:      http://localhost:${PORT}/api          ║`);
    console.log(`║  ❤️  Health Check:      http://localhost:${PORT}/api/health   ║`);
    console.log(`╚═══════════════════════════════════════════════════════════╝\n`);
    
    // Test database connection
    try {
        await promisePool.query('SELECT 1');
        console.log(`✅ MySQL connected successfully\n`);
    } catch (error) {
        console.log(`❌ MySQL connection failed. Make sure XAMPP MySQL is running.\n`);
    }
});