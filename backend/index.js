const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const axios = require('axios');
const NodeCache = require('node-cache');

const app = express();
const PORT = 5000;
const cache = new NodeCache({ stdTTL: 3600 }); // Cache images for 1 hour

// Middlewares
app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(bodyParser.json());

// MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'root', // Update with your MySQL password
  database: 'virtual_db',
});

// Connect to DB
db.connect((err) => {
  if (err) {
    console.log('Database connection failed:', err);
  } else {
    console.log('Connected to MySQL database');
  }
});

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Expecting 'Bearer <token>'
  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, 'your_secret_key', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user; // Store user data in request
    next();
  });
};

// Signup API
app.post('/signup', async (req, res) => {
  const { firstName, lastName, email, password, dob, mobile } = req.body;

  // Validate required fields
  if (!firstName || !lastName || !email || !password || !dob || !mobile) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  // Validate mobile number (10 digits)
  if (!/^\d{10}$/.test(mobile)) {
    return res.status(400).json({ message: 'Mobile number must be 10 digits' });
  }

  // Validate password length
  if (password.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters' });
  }

  try {
    // Check if user already exists
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (results.length > 0) {
        return res.status(400).json({ message: 'User already exists' });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert new user
      db.query(
        'INSERT INTO users (firstName, lastName, email, password, dob, mobile) VALUES (?, ?, ?, ?, ?, ?)',
        [firstName, lastName, email, hashedPassword, dob, mobile],
        (err, results) => {
          if (err) {
            return res.status(500).json({ error: err.message });
          }
          res.status(201).json({ message: 'Signup successful' });
        }
      );
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login API
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: 'User not found' });
    }

    const user = results[0];

    // Compare hashed password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    const token = jwt.sign({ id: user.id }, 'your_secret_key', { expiresIn: '1h' });

    res.json({ message: 'Login successful', token });
  });
});

// Get user details
app.get('/user', authenticateToken, (req, res) => {
  db.query('SELECT id, firstName, email FROM users WHERE id = ?', [req.user.id], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(results[0]);
  });
});

// Get costumes
app.get('/costumes', (req, res) => {
  db.query('SELECT * FROM costumes', (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ costumes: results });
  });
});

// Proxy endpoint for images
app.get('/proxy-image', async (req, res) => {
  const { url } = req.query;
  if (!url) {
    return res.status(400).json({ error: 'Image URL is required' });
  }
  if (!url.match(/\.(png|jpg|jpeg|gif)$/i)) {
    return res.status(400).json({ error: 'Invalid image URL' });
  }

  const cacheKey = url;
  const cachedImage = cache.get(cacheKey);
  if (cachedImage) {
    console.log(`Serving cached image: ${url}`);
    res.set({
      'Content-Type': cachedImage.contentType,
      'Access-Control-Allow-Origin': 'http://localhost:3000',
      'Access-Control-Allow-Methods': 'GET',
      'Cross-Origin-Resource-Policy': 'cross-origin'
    });
    return res.send(cachedImage.data);
  }

  try {
    console.log(`Fetching image: ${url}`);
    const response = await axios.get(url, { responseType: 'arraybuffer' });
    cache.set(cacheKey, {
      data: response.data,
      contentType: response.headers['content-type']
    });
    res.set({
      'Content-Type': response.headers['content-type'],
      'Access-Control-Allow-Origin': 'http://localhost:3000',
      'Access-Control-Allow-Methods': 'GET',
      'Cross-Origin-Resource-Policy': 'cross-origin'
    });
    res.send(response.data);
  } catch (err) {
    console.error('Error fetching image:', err.message);
    res.status(500).json({ error: 'Failed to fetch image' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});