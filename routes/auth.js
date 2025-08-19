// routes/auth.js
const express = require('express');
const jwt = require('jsonwebtoken');
const { body } = require('express-validator');
const { authenticate } = require('../middleware/security'); // Make sure you have this

const User = require('../models/User');
const handleValidation = require('../utils/validation');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret'; // replace in production

// POST /api/auth/register - for regular user registration from Expo
router.post(
  '/register',
  [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email required').normalizeEmail(),
    body('password').isLength({ min: 6 }).withMessage('Password min length is 6'),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { name, email, password } = req.body;
      let user = await User.findOne({ email });
      if (user) {
        return res.status(409).json({ message: 'Email already in use' });
      }

      user = new User({ name, email, password, role: 'user' }); // Default role is 'user'
      await user.save();

      const payload = { id: user._id, email: user.email, role: user.role };
      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });

      return res.status(201).json({
        token,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          active: user.active,
        },
      });
    } catch (err) {
      console.error('register error:', err);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// POST /api/auth/register-admin
router.post(
  '/register-admin',
  [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email required').normalizeEmail(),
    body('password').isLength({ min: 6 }).withMessage('Password min length is 6'),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const existingAdmins = await User.countDocuments({ role: 'admin' });
      if (existingAdmins >= 1) {
        return res.status(403).json({ message: 'Admin registration is closed' });
      }

      const { name, email, password } = req.body;
      const user = new User({ name, email, password, role: 'admin' });
      await user.save();

      const payload = { id: user._id, email: user.email, role: user.role };
      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });

      return res.status(201).json({
        token,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          active: user.active,
        },
      });
    } catch (err) {
      if (err.code === 11000) {
        return res.status(409).json({ message: 'Email already in use' });
      }
      console.error('register-admin error:', err);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// POST /api/auth/login - for regular user login from Expo
router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Valid email required').normalizeEmail(),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email });

      if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      const isMatch = await user.comparePassword(password);
      if (!isMatch) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      if (!user.active) {
        return res.status(403).json({ message: 'Account is not active' });
      }

      const payload = { id: user._id, email: user.email, role: user.role };
      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });

      return res.status(200).json({
        token,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          active: user.active,
        },
      });
    } catch (err) {
      console.error('login error:', err);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

// GET /api/auth/me - Get current user
router.get('/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    console.error('get user error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// PATCH /api/auth/me - Update current user
router.patch(
  '/me',
  authenticate,
  [
    body('name').optional().trim().notEmpty().withMessage('Name cannot be empty'),
    body('email').optional().isEmail().withMessage('Valid email required').normalizeEmail(),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const user = await User.findById(req.user.id);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

      const { name, email } = req.body;
      if (name) {
        user.name = name;
      }
      if (email) {
        const existingUser = await User.findOne({ email });
        if (existingUser && existingUser._id.toString() !== req.user.id) {
          return res.status(409).json({ message: 'Email already in use' });
        }
        user.email = email;
      }

      await user.save();
      res.json(await User.findById(req.user.id).select('-password'));
    } catch (err) {
      console.error('update user error:', err);
      res.status(500).json({ message: 'Server error' });
    }
  }
);

module.exports = router;