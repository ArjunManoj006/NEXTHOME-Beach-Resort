const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const fs = require('fs').promises;
const path = require('path');
const session = require('express-session');
const app = express();

// Middleware
app.use(bodyParser.json()); // Parse JSON bodies (for API requests)
app.use(bodyParser.urlencoded({ extended: true })); // Parse form data
app.use(express.static('public')); // Serve static files

// Set up session middleware
app.use(session({
    secret: 'your-secret-key', // Replace with a secure secret key
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set to true if using HTTPS in production
}));

// Path to the users.json file
const USERS_FILE = path.join(__dirname, 'users.json');

// Ensure users.json exists (create if it doesn't)
async function initializeUsersFile() {
    try {
        await fs.access(USERS_FILE);
    } catch (error) {
        // File doesn't exist, create it with an empty array
        await fs.writeFile(USERS_FILE, JSON.stringify([]));
    }
}

// Read users from the JSON file
async function readUsers() {
    try {
        const data = await fs.readFile(USERS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading users:', error.message);
        return [];
    }
}

// Write users to the JSON file
async function writeUsers(users) {
    try {
        await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
    } catch (error) {
        console.error('Error writing users:', error.message);
        throw error;
    }
}

// API endpoint to handle registration
app.post('/api/register', async (req, res) => {
    try {
        console.log('Incoming registration request:', req.body);

        const { username, email, password } = req.body;

        // Validate that all fields are present
        if (!username || !email || !password) {
            console.log('Missing required fields:', { username, email, password });
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Read existing users
        const users = await readUsers();

        // Check if username or email already exists
        const existingUser = users.find(user => user.username === username || user.email === email);
        if (existingUser) {
            console.log('Duplicate user detected:', { username, email });
            return res.status(400).json({ error: 'Username or email already exists' });
        }

        // Hash the password
        console.log('Hashing password...');
        const hashedPassword = await bcrypt.hash(password, 10);
        console.log('Password hashed successfully');

        // Create new user
        const newUser = {
            username,
            email,
            password: hashedPassword,
            created_at: new Date().toISOString()
        };

        // Add new user to the array
        users.push(newUser);

        // Write updated users back to the file
        console.log('Saving user to users.json...');
        await writeUsers(users);
        console.log('User registered successfully:', { username, email });

        // Store user in session
        req.session.user = { username, email };

        // Send success response
        res.status(200).json({ message: 'Registration successful' });
    } catch (error) {
        console.error('Error registering user:', error.message);
        console.error('Stack trace:', error.stack);
        res.status(500).json({ error: 'Error registering user: ' + error.message });
    }
});

// API endpoint to handle login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        console.log('Incoming login request:', { email });

        // Read existing users
        const users = await readUsers();

        // Find user by email
        const user = users.find(user => user.email === email);
        if (!user) {
            console.log('User not found:', email);
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Compare password
        console.log('Comparing password for user:', email);
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log('Password mismatch for user:', email);
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        console.log('User logged in successfully:', email);

        // Store user in session
        req.session.user = { username: user.username, email };

        // Send success response with user data
        res.status(200).json({ message: 'Login successful', user: { username: user.username, email } });
    } catch (error) {
        console.error('Error logging in:', error.message);
        console.error('Stack trace:', error.stack);
        res.status(500).json({ error: 'Error logging in: ' + error.message });
    }
});

// API endpoint to get the logged-in user's data
app.get('/api/user', (req, res) => {
    if (req.session.user) {
        res.status(200).json(req.session.user);
    } else {
        res.status(401).json({ error: 'Not logged in' });
    }
});

// API endpoint to handle logout
app.get('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).json({ error: 'Error logging out' });
        }
        res.status(200).json({ message: 'Logged out successfully' });
    });
});

// Initialize users.json and start the server
initializeUsersFile().then(() => {
    app.listen(3001, () => {
        console.log('Server running on http://localhost:3001');
    });
}).catch((error) => {
    console.error('Failed to initialize users file:', error.message);
    process.exit(1);
});