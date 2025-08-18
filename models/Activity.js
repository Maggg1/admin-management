'use strict';

const mongoose = require('mongoose');

const activitySchema = new mongoose.Schema(
  {
    user: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'User', 
      required: true, 
      index: true 
    },
    type: { 
      type: String, 
      required: true, 
      trim: true 
    },
    details: { 
      type: mongoose.Schema.Types.Mixed 
    },
  },
  { timestamps: true }
);

activitySchema.index({ createdAt: -1 });
activitySchema.index({ user: 1, createdAt: -1 });

const Activity = mongoose.models.Activity || mongoose.model('Activity', activitySchema);

module.exports = Activity;
