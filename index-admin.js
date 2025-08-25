const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// Admin-specific routes
const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const userRoutes = require('./routes/users');
const activityRoutes = require('./routes/activities');
const rewardRoutes = require('./routes/rewards');
const feedbackRoutes = require('./routes/feedbacks');

const app = express();

// Security middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api', limiter);

// Admin-specific API routes
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/users', userRoutes);
app.use('/api/activities', activityRoutes);
app.use('/api/rewards', rewardRoutes);
app.use('/api/feedbacks', feedbackRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'Admin API is running', timestamp: new Date().toISOString() });
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ message: 'API endpoint not found' });
});

const PORT = process.env.ADMIN_API_PORT || 4000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://addenasang:abcd1234@ac-ixwwvqn-shard-00-00.9wlmev7.mongodb.net:27017,ac-ixwwvqn-shard-00-01.9wlmev7.mongodb.net:27017,ac-ixwwvqn-shard-00-02.9wlmev7.mongodb.net:27017/admin_backend?ssl=true&replicaSet=atlas-ixwwvqn-shard-0&authSource=admin&retryWrites=true&w=majority';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('✅ Connected to MongoDB for Admin API');
  app.listen(PORT, () => {
    console.log(`🚀 Admin API server running on port ${PORT}`);
  });
})
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

module.exports = app;
