const express = require('express');
const { body } = require('express-validator');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const handleValidation = require('../utils/validation');
const { authenticate } = require('../middleware/security');

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

function signToken(user) {
  return jwt.sign({ id: user._id.toString(), role: user.role }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  });
}

router.post(
  '/register-admin',
  [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
    body('password').isLength({ min: 6 }).withMessage('Password min length 6'),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const adminCount = await User.countDocuments({ role: 'admin' });
      if (adminCount > 0) {
        return res.status(403).json({
          message: 'Admin already exists. Login as admin and use admin user creation endpoint to add more admins.',
        });
      }

      const { name, email, password } = req.body;
      
      // Check if user already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(409).json({ 
          message: 'Email already in use',
          code: 'USER_EXISTS'
        });
      }

      const user = new User({ name, email, password, role: 'admin', emailVerified: true });
      await user.save();

      const token = signToken(user);
      const safeUser = {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        active: user.active,
      };
      return res.status(201).json({ token, user: safeUser });
    } catch (err) {
      if (err?.code === 11000) {
        return res.status(409).json({ 
          message: 'Email already in use',
          code: 'DUPLICATE_EMAIL'
        });
      }
      console.error('register-admin error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// Fixed register endpoint - only for registration
router.post(
  '/register',
  [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
    body('password').isLength({ min: 6 }).withMessage('Password min length 6'),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { name, email, password } = req.body;
      
      // Check if user already exists first
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(409).json({ 
          message: 'User with this email already exists. Please login instead.',
          code: 'USER_EXISTS'
        });
      }

      // Create new user
      const user = new User({
        name,
        email,
        password,
        role: 'user',
        emailVerified: false,
      });
      
      await user.save();

      const token = signToken(user);
      const safeUser = {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        active: user.active,
      };

      return res.status(201).json({ 
        message: 'User registered successfully',
        token, 
        user: safeUser 
      });
    } catch (err) {
      if (err?.code === 11000) {
        return res.status(409).json({ 
          message: 'Email already in use',
          code: 'DUPLICATE_EMAIL'
        });
      }
      console.error('User registration error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// Separate login endpoint
router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Valid email required').normalizeEmail(),
    body('password').notEmpty().withMessage('Password required'),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email }).select('+password');

      if (!user) {
        return res.status(401).json({ 
          message: 'Invalid credentials',
          code: 'INVALID_CREDENTIALS'
        });
      }

      if (!user.active) {
        return res.status(403).json({ 
          message: 'Account is disabled. Please contact support.',
          code: 'ACCOUNT_DISABLED'
        });
      }

      const match = await user.comparePassword(password);
      if (!match) {
        return res.status(401).json({ 
          message: 'Invalid credentials',
          code: 'INVALID_CREDENTIALS'
        });
      }

      const token = signToken(user);
      const safeUser = {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        active: user.active,
      };
      
      return res.json({ 
        message: 'Login successful',
        token, 
        user: safeUser 
      });
    } catch (err) {
      console.error('Login error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// Optional: Check if user exists endpoint
router.post(
  '/check-user',
  [
    body('email').isEmail().withMessage('Valid email required').normalizeEmail(),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { email } = req.body;
      const user = await User.findOne({ email }).select('email');
      
      return res.json({ 
        exists: !!user,
        email: email
      });
    } catch (err) {
      console.error('Check user error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

router.get('/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password').lean();
    if (!user) return res.status(404).json({ message: 'User not found' });
    return res.json({
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      active: user.active,
    });
  } catch (err) {
    return res.status(500).json({ message: 'Internal server error' });
  }
});

module.exports = router;
