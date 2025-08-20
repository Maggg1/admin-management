const express = require('express');
const { body } = require('express-validator');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const handleValidation = require('../utils/validation');

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

function signToken(user) {
  return jwt.sign({ id: user._id.toString(), role: user.role }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  });
}

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
      
      console.log(`🔐 Admin login attempt for email: ${email}`);
      
      const user = await User.findOne({ email }).select('+password');
      if (!user || user.role !== 'admin') {
        console.log(`❌ Admin login failed: User not found or not an admin for email: ${email}`);
        return res.status(401).json({ 
          message: 'Invalid credentials',
          debug: process.env.NODE_ENV === 'development' ? 'User not found or not an admin' : undefined
        });
      }
      
      if (!user.active) {
        console.log(`❌ Admin login failed: User account disabled for email: ${email}`);
        return res.status(403).json({ 
          message: 'User is disabled',
          debug: process.env.NODE_ENV === 'development' ? 'Account inactive' : undefined
        });
      }

      const match = await user.comparePassword(password);
      if (!match) {
        console.log(`❌ Admin login failed: Invalid password for email: ${email}`);
        return res.status(401).json({ 
          message: 'Invalid credentials',
          debug: process.env.NODE_ENV === 'development' ? 'Password mismatch' : undefined
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
      
      console.log(`✅ Admin login successful for email: ${email}`);
      return res.json({ token, user: safeUser });
    } catch (err) {
      console.error('🔥 Admin login error:', err);
      return res.status(500).json({ 
        message: 'Internal server error',
        debug: process.env.NODE_ENV === 'development' ? err.message : undefined
      });
    }
  }
);

module.exports = router;