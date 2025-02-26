const express = require('express');
const { PrismaClient } = require('@prisma/client');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { body, validationResult } = require('express-validator');

const app = express();
const prisma = new PrismaClient();

app.use(express.json());

// Middleware for JWT verification
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Generate unique referral code
const generateReferralCode = () => {
  return crypto.randomBytes(6).toString('hex');
};

// Validation middleware
const registerValidation = [
  body('email').isEmail().normalizeEmail(),
  body('username').isLength({ min: 3 }),
  body('password').isLength({ min: 8 }),
];

app.get('/', (req, res) => {
  res.send('Hello World');
});

// Register endpoint
app.post('/api/register', registerValidation, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, username, password } = req.body;
    const { referralCode } = req.query; // Get referral code from query params

    // Check if user already exists
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [
          { email },
          { username },
        ],
      },
    });

    if (existingUser) {
      return res.status(400).json({
        error: 'User with this email or username already exists',
      });
    }

    // Find referrer if referral code is provided
    let referrer = null;
    if (referralCode) {
      referrer = await prisma.user.findUnique({
        where: { referralCode },
      });

      if (!referrer) {
        return res.status(400).json({ error: 'Invalid referral code' });
      }

      // Prevent self-referral
      if (referrer.email === email) {
        return res.status(400).json({ error: 'Cannot use your own referral code' });
      }
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = await prisma.user.create({
      data: {
        email,
        username,
        password: hashedPassword,
        referralCode: generateReferralCode(),
        referredById: referrer?.id,
      },
    });

    // Generate JWT token
    const token = jwt.sign(
      { userId: newUser.id, email: newUser.email },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: newUser.id,
        email: newUser.email,
        username: newUser.username,
        referralCode: newUser.referralCode,
        referredBy: referrer ? {
          id: referrer.id,
          username: referrer.username
        } : null
      },
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        referralCode: user.referralCode,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get referral statistics
app.get('/api/referral-stats', authenticateToken, async (req, res) => {
  try {
    const referredUsers = await prisma.user.findMany({
      where: {
        referredById: req.user.userId,
      },
      select: {
        id: true,
        username: true,
        email: true,
        createdAt: true,
      },
    });

    res.json({
      totalReferrals: referredUsers.length,
      referredUsers,
    });
  } catch (error) {
    console.error('Referral stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
