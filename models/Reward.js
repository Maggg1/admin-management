'use strict';
const mongoose = require('mongoose');

const rewardSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },
  description: {
    type: String,
    trim: true,
  },
  imageUrl: {
    type: String,
    trim: true,
  },
  probability: {
    type: Number,
    required: true,
    min: 0,
    max: 100,
  },
  points: {
    type: Number,
    default: 0,
    min: 0,
  },
  active: {
    type: Boolean,
    default: true,
  },
}, { timestamps: true });

const Reward = mongoose.model('Reward', rewardSchema);

module.exports = Reward;