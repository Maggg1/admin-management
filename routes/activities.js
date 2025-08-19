const express = require('express');
const { authenticate } = require('../middleware/security');
const Activity = require('../models/Activity');

const router = express.Router();

// GET /activities - for authenticated users
router.get('/', authenticate, async (req, res) => {
  try {
    const { type, limit } = req.query;
    const query = { user: req.user.id };
    if (type) {
      query.type = type;
    }

    let activityQuery = Activity.find(query).sort({ createdAt: -1 });
    if (limit) {
      activityQuery = activityQuery.limit(parseInt(limit, 10));
    }

    const activities = await activityQuery;
    res.json(activities);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching activities', error: error.message });
  }
});

// POST /activities - for authenticated users
router.post('/', authenticate, async (req, res) => {
  try {
    const { type, details } = req.body;
    const activity = new Activity({
      type,
      user: req.user.id,
      details,
    });
    await activity.save();
    res.status(201).json(activity);
  } catch (error) {
    res.status(400).json({ message: 'Error creating activity', error: error.message });
  }
});

module.exports = router;