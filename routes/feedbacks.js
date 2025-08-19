const express = require('express');
const { authenticate } = require('../middleware/security');
const Feedback = require('../models/Feedback');
const router = express.Router();

// POST /feedbacks
router.post('/', authenticate, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) {
      return res.status(400).json({ message: 'Feedback message is required' });
    }
    const feedback = new Feedback({
      message,
      user: req.user.id,
    });
    await feedback.save();
    res.status(201).json(feedback);
  } catch (error) {
    res.status(400).json({ message: 'Error submitting feedback', error: error.message });
  }
});

module.exports = router;