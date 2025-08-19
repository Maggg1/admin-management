const express = require('express');
const { body } = require('express-validator');
const { authenticate } = require('../middleware/security');
const User = require('../models/User');
const handleValidation = require('../utils/validation');

const router = express.Router();

// PATCH /users/me - Update current user
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
      const updatedUser = await User.findById(req.user.id).select('-password');
      res.json(updatedUser);
    } catch (err) {
      console.error('update user error:', err);
      if (err.code === 11000) {
        return res.status(409).json({ message: 'Email already in use' });
      }
      res.status(500).json({ message: 'Server error' });
    }
  }
);

module.exports = router;