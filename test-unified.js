// Test script for unified backend with local MongoDB
const express = require('express');
const mongoose = require('mongoose');
const app = express();

// Use local MongoDB for testing
const MONGODB_URI = 'mongodb://addenasang:abcd1234@ac-ixwwvqn-shard-00-00.9wlmev7.mongodb.net:27017,ac-ixwwvqn-shard-00-01.9wlmev7.mongodb.net:27017,ac-ixwwvqn-shard-00-02.9wlmev7.mongodb.net:27017/admin_backend?ssl=true&replicaSet=atlas-ixwwvqn-shard-0&authSource=admin&retryWrites=true&w=majority';

console.log('🔧 Testing unified backend with local MongoDB...');

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('✅ MongoDB connected successfully to local database');
  console.log('🚀 Unified backend is ready for testing');
  console.log('📊 Test endpoints:');
  console.log('   - Health: http://localhost:4000/health');
  console.log('   - User registration: POST http://localhost:4000/api/auth/register');
  console.log('   - Admin registration: POST http://localhost:4000/api/auth/register-admin');
  console.log('   - Login: POST http://localhost:4000/api/auth/login');
  
  // Close connection after test
  mongoose.connection.close();
  console.log('✅ Test completed successfully');
  process.exit(0);
})
.catch((err) => {
  console.error('❌ MongoDB connection error:', err.message);
  console.log('\n💡 To fix this:');
  console.log('1. Install MongoDB locally or');
  console.log('2. Update the MONGODB_URI in index-unified.js to use your MongoDB Atlas connection string');
  console.log('3. Ensure your IP is whitelisted in MongoDB Atlas');
  process.exit(1);
});
