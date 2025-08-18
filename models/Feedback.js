'use strict';

const mongoose = require('mongoose');

const feedbackSchema = new mongoose.Schema(
  {
    user: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'User', 
      required: true, 
      index: true 
    },
    message: { 
      type: String, 
      required: true, 
      trim: true 
    },
    rating: { 
      type: Number, 
      min: 1, 
      max: 5 
    },
  },
  { timestamps: true }
);

feedbackSchema.index({ createdAt: -1 });
feedbackSchema.index({ user: 1, createdAt: -1 });

const Feedback = mongoose.models.Feedback || mongoose.model('Feedback', feedbackSchema);

module.exports = Feedback;
