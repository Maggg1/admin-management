'use strict';
const express = require('express');
const { body, validationResult } = require('express-validator');
const Reward = require('../models/Reward');
const { authenticate, authorize } = require('../middleware/security');
const handleValidation = require('../utils/validation');

const router = express.Router();

// Middleware to authorize only admins
const adminOnly = authorize(['admin']);

// POST /api/rewards - Create a new reward
router.post(
  '/',
  authenticate,
  adminOnly,
  [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('probability').isFloat({ min: 0, max: 100 }).withMessage('Probability must be between 0 and 100'),
    body('imageUrl').optional().isURL().withMessage('Image URL must be a valid URL'),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { name, description, imageUrl, probability } = req.body;
      const reward = new Reward({ name, description, imageUrl, probability });
      await reward.save();
      res.status(201).json(reward);
    } catch (err) {
      console.error('Create reward error:', err);
      res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// GET /api/rewards - Get all rewards
router.get('/', async (req, res) => {
  try {
    const rewards = await Reward.find().sort({ probability: -1 });
    res.json(rewards);
  } catch (err) {
    console.error('Get rewards error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// GET /api/rewards/random - Get a random reward for the daily shake
router.get('/random', authenticate, async (req, res) => {
    try {
        const rewards = await Reward.find();
        if (rewards.length === 0) {
            return res.status(404).json({ message: 'No rewards available' });
        }

        const totalProbability = rewards.reduce((sum, reward) => sum + reward.probability, 0);
        if (totalProbability <= 0) {
            const randomIndex = Math.floor(Math.random() * rewards.length);
            return res.json(rewards[randomIndex]);
        }

        const random = Math.random() * totalProbability;
        let cumulativeProbability = 0;

        for (const reward of rewards) {
            cumulativeProbability += reward.probability;
            if (random < cumulativeProbability) {
                return res.json(reward);
            }
        }
        
        res.json(rewards[rewards.length - 1]);

    } catch (err) {
        console.error('Get random reward error:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});


// GET /api/rewards/:id - Get a single reward by ID
router.get('/:id', async (req, res) => {
  try {
    const reward = await Reward.findById(req.params.id);
    if (!reward) {
      return res.status(404).json({ message: 'Reward not found' });
    }
    res.json(reward);
  } catch (err) {
    console.error('Get reward by ID error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// PUT /api/rewards/:id - Update a reward
router.put(
  '/:id',
  authenticate,
  adminOnly,
  [
    body('name').optional().trim().notEmpty().withMessage('Name cannot be empty'),
    body('probability').optional().isFloat({ min: 0, max: 100 }).withMessage('Probability must be between 0 and 100'),
    body('imageUrl').optional().isURL().withMessage('Image URL must be a valid URL'),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { name, description, imageUrl, probability } = req.body;
      const reward = await Reward.findByIdAndUpdate(
        req.params.id,
        { name, description, imageUrl, probability },
        { new: true, runValidators: true }
      );
      if (!reward) {
        return res.status(404).json({ message: 'Reward not found' });
      }
      res.json(reward);
    } catch (err) {
      console.error('Update reward error:', err);
      res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// DELETE /api/rewards/:id - Delete a reward
router.delete('/:id', authenticate, adminOnly, async (req, res) => {
  try {
    const reward = await Reward.findByIdAndDelete(req.params.id);
    if (!reward) {
      return res.status(404).json({ message: 'Reward not found' });
    }
    res.status(204).send();
  } catch (err) {
    console.error('Delete reward error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

module.exports = router;