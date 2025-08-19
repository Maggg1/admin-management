'use strict';
const express = require('express');
const Reward = require('../models/Reward');

const router = express.Router();

// GET /api/rewards - list all active rewards
router.get('/', async (req, res) => {
  try {
    const rewards = await Reward.find({ active: true }).sort({ points: 1 });
    res.json(rewards);
  } catch (err) {
    console.error('get rewards error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

module.exports = router;