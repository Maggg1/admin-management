const express = require('express');
const { authenticate } = require('../middleware/security');
const Activity = require('../models/Activity');
const router = express.Router();

// GET /shakes
router.get('/', authenticate, async (req, res) => {
  try {
    const shakes = await Activity.find({ type: 'shake', user: req.user.id }).sort({ createdAt: -1 });
    res.json(shakes);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching shakes', error: error.message });
  }
});

// POST /shakes
router.post('/', authenticate, async (req, res) => {
  try {
    const { details } = req.body;
    const activity = new Activity({
      type: 'shake',
      user: req.user.id,
      details,
    });
    await activity.save();
    res.status(201).json(activity);
  } catch (error) {
    res.status(400).json({ message: 'Error creating shake', error: error.message });
  }
});

module.exports = router;