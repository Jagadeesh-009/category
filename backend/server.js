const express = require('express');
const cors = require('cors');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const util = require('util');

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: ['http://localhost:3000'],
    methods: ['POST', 'GET'],
    credentials: true,
  })
);
app.use(cookieParser());

const saltRounds = 10;

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Jagadeesh@123',
  database: 'signupdb',
});

const dbQuery = util.promisify(db.query).bind(db);

app.listen(8081, () => {
  console.log('Server running at http://localhost:8081');
});

// Middleware to verify JWT
const verifyUser = (req, res, next) => {
  const token = req.cookies.jwtToken;
  if (!token) return res.status(401).json({ error: 'You are not authenticated' });

  jwt.verify(token, 'jwtSecret', (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Token is not valid' });

    req.username = decoded.name;
    next();
  });
};

// Signup Route
app.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hash = await bcrypt.hash(password.toString(), saltRounds);

    const sqlQuery = 'INSERT INTO signin (username, email, password) VALUES (?)';
    const values = [username, email, hash];

    await dbQuery(sqlQuery, [values]);

    res.status(200).json({ status: 'success' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error during signup' });
  }
});

// Login Route
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const sqlQuery = 'SELECT * FROM signin WHERE username = ?';

    const result = await dbQuery(sqlQuery, [username]);

    if (result.length === 0) {
      return res.status(401).json({ error: 'User not found' });
    }

    const user = result[0];
    const isMatch = await bcrypt.compare(password.toString(), user.password);

    if (!isMatch) {
      return res.status(401).json({ error: 'Password is not matching' });
    }

    const jwtToken = jwt.sign({ name: user.username }, 'jwtSecret', { expiresIn: '1d' });
    res.cookie('jwtToken', jwtToken, { httpOnly: true });
    res.status(200).json({ status: 'success' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Logout Route
app.get('/logout', (req, res) => {
  res.clearCookie('jwtToken');
  return res.json({ status: 'success' });
});

// Protected Route
app.get('/', verifyUser, (req, res) => {
  return res.json({ status: 'success', username: req.username });
});
