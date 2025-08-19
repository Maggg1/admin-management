'use strict';

const express = require('express');
const mongoose = require('mongoose');
const { body, param, query } = require('express-validator');

// Local modules (to be created): User model and validation helper
const User = require('../models/User');
const handleValidation = require('../utils/validation');
const { authenticate, authorize } = require('../middleware/security');
const Activity = require('../models/Activity');
const Feedback = require('../models/Feedback');
const Reward = require('../models/Reward');

const router = express.Router();

// GET /api/admin/users - list users with pagination, search, and sorting
router.get(
  '/users',
  [
    query('page').optional().isInt({ min: 1 }).toInt(),
    query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
    query('search').optional().isString().trim(),
    query('sort')
      .optional()
      .isIn(['createdAt', 'name', 'email', 'role'])
      .withMessage('Invalid sort field'),
    query('order')
      .optional()
      .isIn(['asc', 'desc'])
      .withMessage('Invalid order'),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const page = req.query.page || 1;
      const limit = req.query.limit || 10;
      const search = req.query.search || '';
      const sortField = req.query.sort || 'createdAt';
      const sortOrder = req.query.order === 'asc' ? 1 : -1;

      const filter = {};
      if (search) {
        filter.$or = [
          { name: { $regex: search, $options: 'i' } },
          { email: { $regex: search, $options: 'i' } },
        ];
      }

      const total = await User.countDocuments(filter);
      const data = await User.find(filter)
        .sort({ [sortField]: sortOrder })
        .skip((page - 1) * limit)
        .limit(limit)
        .select('-password')
        .lean();

      return res.json({ data, page, limit, total, totalPages: Math.ceil(total / limit) });
    } catch (err) {
      console.error('list users error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// POST /api/admin/users - create a user (admin-only)
router.post(
  '/users',
  [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
    body('password').isLength({ min: 6 }).withMessage('Password min length 6'),
    body('role').optional().isIn(['admin', 'user']).withMessage('Invalid role'),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { name, email, password, role = 'user' } = req.body;
      const user = new User({ name, email, password, role });
      await user.save();
      const safeUser = { id: user._id, name: user.name, email: user.email, role: user.role, active: user.active };
      return res.status(201).json(safeUser);
    } catch (err) {
      if (err && err.code === 11000) {
        return res.status(409).json({ message: 'Email already in use' });
      }
      console.error('create user error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// GET /api/admin/users/:id - read user by ID
router.get(
  '/users/:id',
  [param('id').custom((v) => mongoose.Types.ObjectId.isValid(v)).withMessage('Invalid ID')],
  handleValidation,
  async (req, res) => {
    try {
      const user = await User.findById(req.params.id).select('-password').lean();
      if (!user) return res.status(404).json({ message: 'User not found' });
      return res.json(user);
    } catch (err) {
      console.error('get user error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// PATCH /api/admin/users/:id - update user
router.patch(
  '/users/:id',
  [
    param('id').custom((v) => mongoose.Types.ObjectId.isValid(v)).withMessage('Invalid ID'),
    body('email').optional().isEmail().withMessage('Valid email required').normalizeEmail(),
    body('name').optional().isString().trim(),
    body('password').optional().isLength({ min: 6 }).withMessage('Password min length 6'),
    body('role').optional().isIn(['admin', 'user']).withMessage('Invalid role'),
    body('active').optional().isBoolean().withMessage('Active must be boolean'),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const user = await User.findById(req.params.id).select('+password');
      if (!user) return res.status(404).json({ message: 'User not found' });

      const updatable = ['name', 'email', 'role', 'active'];
      for (const key of updatable) {
        if (typeof req.body[key] !== 'undefined') user[key] = req.body[key];
      }
      if (typeof req.body.password !== 'undefined' && req.body.password) {
        user.password = req.body.password; // will hash via pre-save
      }

      await user.save();
      const safeUser = { id: user._id, name: user.name, email: user.email, role: user.role, active: user.active };
      return res.json(safeUser);
    } catch (err) {
      if (err && err.code === 11000) {
        return res.status(409).json({ message: 'Email already in use' });
      }
      console.error('update user error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// DELETE /api/admin/users/:id - delete user with last-admin safeguard
router.delete(
  '/users/:id',
  [param('id').custom((v) => mongoose.Types.ObjectId.isValid(v)).withMessage('Invalid ID')],
  handleValidation,
  async (req, res) => {
    try {
      const toDelete = await User.findById(req.params.id);
      if (!toDelete) {
        console.log(`User not found for deletion: ${req.params.id}`);
        return res.status(404).json({ message: 'User not found' });
      }

      // Prevent deleting the last admin
      if (toDelete.role === 'admin') {
        const adminCount = await User.countDocuments({ role: 'admin' });
        if (adminCount <= 1) {
          console.log(`Attempted to delete last admin user: ${req.params.id}`);
          return res.status(400).json({ message: 'Cannot delete the last admin user' });
        }
      }

      // Check if trying to delete self
      if (toDelete._id.toString() === req.user.id) {
        console.log(`Attempted to delete self: ${req.params.id}`);
        return res.status(400).json({ message: 'Cannot delete your own account' });
      }

      await User.deleteOne({ _id: req.params.id });
      console.log(`User deleted successfully: ${req.params.id}`);
      return res.json({ success: true, message: 'User deleted successfully' });
    } catch (err) {
      console.error('delete user error:', err);
      if (err.name === 'CastError') {
        return res.status(400).json({ message: 'Invalid user ID format' });
      }
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// GET /api/admin/activities
router.get('/activities', async (req, res) => {
  try {
    const { type, limit = 10 } = req.query;
    const query = {};
    if (type) {
      query.type = type;
    }
    const activities = await Activity.find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit));
    res.json(activities);
  } catch (err) {
    console.error('get activities error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST /api/admin/activities
router.post('/activities', async (req, res) => {
  try {
    const { type, user, details } = req.body;
    const activity = new Activity({
      type,
      user,
      details,
    });
    await activity.save();
    res.status(201).json(activity);
  } catch (error) {
    res.status(400).json({ message: 'Error creating activity', error: error.message });
  }
});

// POST /admin/shakes
router.post('/shakes', authorize('admin'), async (req, res) => {
  try {
    const { userId, amount } = req.body;
    const activity = new Activity({
      type: 'shake',
      user: userId,
      details: { amount },
    });
    await activity.save();
    res.status(201).json(activity);
  } catch (error) {
    res.status(400).json({ message: 'Error creating shake activity', error: error.message });
  }
});

// GET /admin/shakes
router.get('/shakes', authorize('admin'), async (req, res) => {
  try {
    const shakes = await Activity.find({ type: 'shake' }).populate('user', 'name email');
    res.json(shakes);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching shakes', error: error.message });
  }
});

// GET /admin/activities
router.get('/activities', async (req, res) => {
  try {
    const { type, limit } = req.query;
    const query = {};
    if (type) {
      query.type = type;
    }

    let activityQuery = Activity.find(query).populate('user', 'name email').sort({ createdAt: -1 });
    if (limit) {
      activityQuery = activityQuery.limit(parseInt(limit, 10));
    }

    const activities = await activityQuery;
    res.json(activities);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching activities', error: error.message });
  }
});

// GET /admin/shakes
router.get('/shakes', async (req, res) => {
  try {
    const shakes = await Activity.find({ type: 'shake' }).populate('user', 'name email').sort({ createdAt: -1 });
    res.json(shakes);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching shakes', error: error.message });
  }
});

// GET /admin/feedbacks
const getFeedbacksHandler = [
  query('page').optional().isInt({ min: 1 }).toInt(),
  query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  query('search').optional().isString().trim(),
  handleValidation,
  async (req, res) => {
    try {
      const page = req.query.page || 1;
      const limit = req.query.limit || 50;
      const search = req.query.search || '';

      const filter = {};
      if (search) {
        const users = await User.find({
          $or: [
            { name: { $regex: search, $options: 'i' } },
            { email: { $regex: search, $options: 'i' } },
          ],
        }).select('_id');
        const userIds = users.map((u) => u._id);

        filter.$or = [
          { message: { $regex: search, $options: 'i' } },
          { type: { $regex: search, $options: 'i' } },
          { user: { $in: userIds } },
        ];
      }

      const total = await Feedback.countDocuments(filter);
      const feedbacks = await Feedback.find(filter)
        .populate('user', 'name email')
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean();

      res.json({
        data: feedbacks,
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      });
    } catch (error) {
      console.error('Error fetching feedbacks:', error);
      res.status(500).json({ message: 'Error fetching feedbacks', error: error.message });
    }
  },
];

router.get('/feedbacks', getFeedbacksHandler);
router.get('/feedback', getFeedbacksHandler);

// Rewards CRUD
// POST /api/admin/rewards - create a reward
router.post(
  '/rewards',
  [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('points').isInt({ min: 0 }).withMessage('Points must be a non-negative integer'),
    body('description').optional().isString().trim(),
    body('active').optional().isBoolean(),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { name, description, points, active } = req.body;
      const reward = new Reward({ name, description, points, active });
      await reward.save();
      res.status(201).json(reward);
    } catch (err) {
      console.error('create reward error:', err);
      res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// GET /api/admin/rewards - list rewards
router.get('/rewards', async (req, res) => {
  try {
    const rewards = await Reward.find({}).sort({ createdAt: -1 });
    res.json(rewards);
  } catch (err) {
    console.error('list rewards error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// GET /api/admin/rewards/:id - get reward by ID
router.get(
  '/rewards/:id',
  [param('id').custom((v) => mongoose.Types.ObjectId.isValid(v)).withMessage('Invalid ID')],
  handleValidation,
  async (req, res) => {
    try {
      const reward = await Reward.findById(req.params.id);
      if (!reward) return res.status(404).json({ message: 'Reward not found' });
      res.json(reward);
    } catch (err) {
      console.error('get reward error:', err);
      res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// PATCH /api/admin/rewards/:id - update a reward
router.patch(
  '/rewards/:id',
  [
    param('id').custom((v) => mongoose.Types.ObjectId.isValid(v)).withMessage('Invalid ID'),
    body('name').optional().trim().notEmpty().withMessage('Name is required'),
    body('points').optional().isInt({ min: 0 }).withMessage('Points must be a non-negative integer'),
    body('description').optional().isString().trim(),
    body('active').optional().isBoolean(),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const reward = await Reward.findById(req.params.id);
      if (!reward) return res.status(404).json({ message: 'Reward not found' });

      const { name, description, points, active } = req.body;
      if (name) reward.name = name;
      if (description) reward.description = description;
      if (points !== undefined) reward.points = points;
      if (active !== undefined) reward.active = active;

      await reward.save();
      res.json(reward);
    } catch (err) {
      console.error('update reward error:', err);
      res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// DELETE /api/admin/rewards/:id - delete a reward
router.delete(
  '/rewards/:id',
  [param('id').custom((v) => mongoose.Types.ObjectId.isValid(v)).withMessage('Invalid ID')],
  handleValidation,
  async (req, res) => {
    try {
      const reward = await Reward.findByIdAndDelete(req.params.id);
      if (!reward) return res.status(404).json({ message: 'Reward not found' });
      res.json({ success: true, message: 'Reward deleted' });
    } catch (err) {
      console.error('delete reward error:', err);
      res.status(500).json({ message: 'Internal server error' });
    }
  }
);

module.exports = router;