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

// User registration endpoint (enabled for regular users)
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
      
      // Check if user already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(409).json({ message: 'Email already in use' });
      }

      const user = new User({ 
        name, 
        email, 
        password, 
        role: 'user', 
        emailVerified: false 
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
      
      return res.status(201).json({ token, user: safeUser });
    } catch (err) {
      console.error('User registration error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// User login endpoint
router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Valid email required'),
    body('password').notEmpty().withMessage('Password required'),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { email, password } = req.body;
      
      const user = await User.findOne({ email }).select('+password');
      if (!user || user.role !== 'user') {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      
      if (!user.active) {
        return res.status(403).json({ message: 'Account is disabled' });
      }

      const match = await user.comparePassword(password);
      if (!match) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      const token = signToken(user);
      const safeUser = {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        active: user.active,
      };
      
      return res.json({ token, user: safeUser });
    } catch (err) {
      console.error('User login error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// Get current user profile
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
      emailVerified: user.emailVerified,
      createdAt: user.createdAt,
    });
  } catch (err) {
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// Update user profile
router.patch(
  '/profile',
  authenticate,
  [
    body('name').optional().trim().notEmpty().withMessage('Name cannot be empty'),
    body('email').optional().isEmail().withMessage('Valid email required').normalizeEmail(),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const user = await User.findById(req.user.id);
      if (!user) return res.status(404).json({ message: 'User not found' });

      if (req.body.name) user.name = req.body.name;
      if (req.body.email) user.email = req.body.email;

      await user.save();
      
      const safeUser = {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        active: user.active,
      };
      
      return res.json(safeUser);
    } catch (err) {
      if (err.code === 11000) {
        return res.status(409).json({ message: 'Email already in use' });
      }
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

module.exports = router;
