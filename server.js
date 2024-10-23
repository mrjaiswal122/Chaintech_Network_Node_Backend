const express = require('express');
const dotenv = require('dotenv');
dotenv.config();

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const Redis = require('ioredis');

const redis = new Redis({
  password: `${process.env.REDIS_PASSWORD}`,
  port: process.env.REDIS_PORT,
  host: `${process.env.REDIS_HOST}`,
});

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret'; // Use environment variables in production

// Register route
app.post('/register', async (req, res) => {
  console.log('In the Register');

  const { name, email, password,age,gender,location,bio,twitter,linkedin,github } = req.body;
  // Check if user already exists with the same email
  const existingUser = await redis.get(`user:${email}`);
  if (existingUser) {
    return res.status(409).json({ msg: 'Email already exists' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  // Store user in Redis
  await redis.set(`user:${email}`, JSON.stringify({ name, email, password: hashedPassword,age,gender,location,bio,twitter,linkedin,github }));
  res.status(201).send('User registered');
});

// Login route
app.post('/login', async (req, res) => {
  console.log('In the login');

  const { email, password } = req.body;

  // Fetch user from Redis
  const user = await redis.get(`user:${email}`);
  if (!user) {
    return res.status(401).json({ msg: 'Invalid credentials' });
  }

  const parsedUser = JSON.parse(user);
  const isPasswordValid = await bcrypt.compare(password, parsedUser.password);

  if (!isPasswordValid) {
    return res.status(401).json({ msg: 'Invalid credentials' });
  }

  const token = jwt.sign({ email: parsedUser.email }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Verify token middleware
// Middleware to authenticate JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  
  // Check if authorization header is present and has 'Bearer' format
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.log('No token found or invalid format');
    return res.status(401).json({ msg: 'Unauthorized: No token or invalid token format' });
  }

  // Extract the token from the Bearer header
  const token = authHeader.split(" ")[1];

  // Verify the token
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      if(err.msg==='jwt expired'){
        console.log('Token expired');
        return res.status(200).json({ msg: 'Unauthorized: Token expired' });
      }else if(err.msg==='jwt malformed'){
        console.log('Token malformed');
        return res.status(200).json({ msg: 'Forbidden: Invalid token' });
      }
      console.log('Token verification failed:', err.message);
      return res.status(403).json({ msg: 'Forbidden: Invalid token' });
    }
    
    // Attach user data to request object
    req.user = user;
    next();
  });
};

// Route to get account info
app.get('/account', authenticateToken, async (req, res) => {
  try {
    // Fetch user data from Redis
    const user = await redis.get(`user:${req.user.email}`);
    if (!user) {
      return res.status(404).json({ msg: 'User not found' });
    }

    // Parse and respond with user details
    const { name, email, age, gender, location, bio, twitter, linkedin, github } = JSON.parse(user);
    res.json({ name, email, age, gender, location, bio, twitter, linkedin, github });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).json({ msg: 'Internal Server Error' });
  }
});

app.post('/update', authenticateToken, async (req, res) => {
  const { name, email, age, gender, location, bio, twitter, linkedin, github } = req.body;

  // Fetch the existing user from Redis
  const existingUser = await redis.get(`user:${req.user.email}`);
  if (!existingUser) return res.status(404).send('User not found');

  const parsedUser = JSON.parse(existingUser);
  const { password: existingPassword } = parsedUser; // Keep the original password

  // Update the user information in Redis
  await redis.set(
    `user:${req.user.email}`,
    JSON.stringify({ name, email, password: existingPassword, age, gender, location, bio, twitter, linkedin, github })
  );

  res.json({ name, email, age, gender, location, bio, twitter, linkedin, github });
});


app.listen(5000, () => {
  console.log('Server running on port 5000');
});
