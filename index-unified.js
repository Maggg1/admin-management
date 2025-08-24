const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
  origin: [
    'http://localhost:3000', // Expo development
    'http://localhost:3001', // React development
    'exp://*', // Expo apps
    'https://*.expo.dev', // Expo web
    process.env.FRONTEND_URL // Your production frontend
  ].filter(Boolean),
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
const MONGODB_URI = 'mongodb+srv://root:local12345@cluster0.9wlemv7.mongodb.net/admin_backend?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('✅ MongoDB connected successfully');
})
.catch((err) => {
  console.error('❌ MongoDB connection error:', err.message);
  process.exit(1);
});

// Routes
app.use('/api/auth', require('./routes/unified-auth'));
app.use('/api/users', require('./routes/users'));
app.use('/api/shakes', require('./routes/shakes'));
app.use('/api/activities', require('./routes/activities'));
app.use('/api/feedbacks', require('./routes/feedbacks'));
app.use('/api/rewards', require('./routes/rewards'));
app.use('/api/admin', require('./routes/admin'));

// Admin panel routes
app.use('/admin', express.static(path.join(__dirname, 'public/admin')));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ 
    message: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { error: err.message })
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Endpoint not found' });
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`🚀 Unified backend server running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`🔐 API endpoints: http://localhost:${PORT}/api`);
  console.log(`👨‍💼 Admin panel: http://localhost:${PORT}/admin`);
});

module.exports = app;
