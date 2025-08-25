#!/usr/bin/env node
'use strict';

const http = require('http');
const mongoose = require('mongoose');

// Configuration
const PORT = process.env.PORT || 3000;
const BASE_URL = `http://localhost:${PORT}`;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://addenasang:abcd1234@ac-ixwwvqn-shard-00-00.9wlmev7.mongodb.net:27017,ac-ixwwvqn-shard-00-01.9wlmev7.mongodb.net:27017,ac-ixwwvqn-shard-00-02.9wlmev7.mongodb.net:27017/admin_backend?ssl=true&replicaSet=atlas-ixwwvqn-shard-0&authSource=admin&retryWrites=true&w=majority';
const DB_NAME = process.env.DB_NAME || 'admin_backend';

// Colors for console output
const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  reset: '\x1b[0m'
};

function log(message, color = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

async function makeRequest(options) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          resolve({ status: res.statusCode, headers: res.headers, data: parsed });
        } catch {
          resolve({ status: res.statusCode, headers: res.headers, data: data });
        }
      });
    });
    
    req.on('error', reject);
    
    if (options.body) {
      req.write(JSON.stringify(options.body));
    }
    
    req.end();
  });
}

async function testDatabaseConnection() {
  log('\n🔍 Testing Database Connection...', colors.blue);
  try {
    await mongoose.connect(MONGO_URI, { dbName: DB_NAME });
    log('✅ MongoDB connected successfully', colors.green);
    
    // Check if users exist
    const User = require('../models/User');
    const userCount = await User.countDocuments();
    log(`📊 Found ${userCount} users in database`, colors.blue);
    
    if (userCount === 0) {
      log('⚠️  No users found - you may need to register first', colors.yellow);
    }
    
    await mongoose.disconnect();
  } catch (error) {
    log(`❌ Database connection failed: ${error.message}`, colors.red);
    return false;
  }
  return true;
}

async function testServerHealth() {
  log('\n🔍 Testing Server Health...', colors.blue);
  try {
    const response = await makeRequest({
      hostname: 'localhost',
      port: PORT,
      path: '/health',
      method: 'GET'
    });
    
    if (response.status === 200) {
      log('✅ Server is running and healthy', colors.green);
      return true;
    } else {
      log(`❌ Server health check failed: ${response.status}`, colors.red);
      return false;
    }
  } catch (error) {
    log(`❌ Cannot connect to server: ${error.message}`, colors.red);
    log('💡 Make sure the server is running: npm run dev', colors.yellow);
    return false;
  }
}

async function testLoginEndpoint() {
  log('\n🔍 Testing Login Endpoint...', colors.blue);
  
  // Test 1: Check if endpoint exists
  try {
    const response = await makeRequest({
      hostname: 'localhost',
      port: PORT,
      path: '/api/auth/login',
      method: 'OPTIONS'
    });
    
    if (response.status === 204 || response.status === 200) {
      log('✅ Login endpoint is accessible', colors.green);
    }
  } catch (error) {
    log(`❌ Login endpoint not accessible: ${error.message}`, colors.red);
    return;
  }
  
  // Test 2: Test with invalid credentials
  log('🧪 Testing with invalid credentials...', colors.blue);
  try {
    const response = await makeRequest({
      hostname: 'localhost',
      port: PORT,
      path: '/api/auth/login',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: { email: 'invalid@test.com', password: 'wrong' }
    });
    
    if (response.status === 401) {
      log('✅ Login endpoint correctly rejects invalid credentials', colors.green);
    } else {
      log(`⚠️  Unexpected response for invalid credentials: ${response.status}`, colors.yellow);
      log(`Response: ${JSON.stringify(response.data)}`, colors.yellow);
    }
  } catch (error) {
    log(`❌ Error testing invalid credentials: ${error.message}`, colors.red);
  }
}

async function checkEnvironmentVariables() {
  log('\n🔍 Checking Environment Variables...', colors.blue);
  
  const requiredVars = ['JWT_SECRET'];
  const optionalVars = ['MONGO_URI', 'DB_NAME', 'PORT', 'NODE_ENV'];
  
  requiredVars.forEach(varName => {
    if (process.env[varName]) {
      log(`✅ ${varName} is set`, colors.green);
    } else {
      log(`❌ ${varName} is missing`, colors.red);
    }
  });
  
  optionalVars.forEach(varName => {
    if (process.env[varName]) {
      log(`ℹ️  ${varName} = ${process.env[varName]}`, colors.blue);
    } else {
      log(`⚠️  ${varName} not set, using defaults`, colors.yellow);
    }
  });
}

async function createTestUser() {
  log('\n🔍 Creating Test User...', colors.blue);
  try {
    await mongoose.connect(MONGO_URI, { dbName: DB_NAME });
    const User = require('../models/User');
    
    // Check if test user exists
    const existingUser = await User.findOne({ email: 'test@example.com' });
    if (existingUser) {
      log('ℹ️  Test user already exists: test@example.com / password123', colors.blue);
      await mongoose.disconnect();
      return;
    }
    
    // Create test user
    const testUser = new User({
      name: 'Test User',
      email: 'test@example.com',
      password: 'password123',
      role: 'admin',
      active: true
    });
    
    await testUser.save();
    log('✅ Test user created: test@example.com / password123', colors.green);
    
    await mongoose.disconnect();
  } catch (error) {
    log(`❌ Error creating test user: ${error.message}`, colors.red);
  }
}

async function runAllTests() {
  log('🚀 Starting Authentication Debug Tests...\n', colors.blue);
  
  await checkEnvironmentVariables();
  const dbConnected = await testDatabaseConnection();
  const serverHealthy = await testServerHealth();
  
  if (serverHealthy && dbConnected) {
    await testLoginEndpoint();
    await createTestUser();
    
    log('\n🎯 Quick Test Commands:', colors.blue);
    log(`curl -X POST ${BASE_URL}/api/auth/login -H "Content-Type: application/json" -d '{"email":"test@example.com","password":"password123"}'`, colors.green);
    log(`curl ${BASE_URL}/health`, colors.green);
    log(`curl ${BASE_URL}/ready`, colors.green);
  }
  
  log('\n✨ Debug tests completed!', colors.blue);
}

// Run tests if called directly
if (require.main === module) {
  runAllTests().catch(console.error);
}

module.exports = { runAllTests };
