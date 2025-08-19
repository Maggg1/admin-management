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
        return res.status(409).json({ message: 'Email already in use' });
      }
      console.error('register-admin error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

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
      const user = new User({ name, email, password, role: 'user', active: true });
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
        return res.status(409).json({ message: 'Email already in use' });
      }
      console.error('register error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

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
      if (!user) return res.status(401).json({ message: 'Invalid credentials' });
      if (!user.active) return res.status(403).json({ message: 'User is disabled' });

      const match = await user.comparePassword(password);
      if (!match) return res.status(401).json({ message: 'Invalid credentials' });

      if (user.role !== 'admin' && typeof user.emailVerified === 'boolean' && !user.emailVerified) {
        return res.status(403).json({ message: 'Email not verified' });
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
      console.error('login error:', err);
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