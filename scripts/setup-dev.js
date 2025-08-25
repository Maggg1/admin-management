#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const User = require('../models/User');

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

async function setupEnvironment() {
  log('🚀 Setting up development environment...\n', colors.blue);
  
  // 1. Check if .env exists
  const envPath = path.join(__dirname, '..', '.env');
  if (!fs.existsSync(envPath)) {
    log('⚠️  .env file not found, creating from .env.example...', colors.yellow);
    const envExamplePath = path.join(__dirname, '..', '.env.example');
    if (fs.existsSync(envExamplePath)) {
      fs.copyFileSync(envExamplePath, envPath);
      log('✅ .env file created from .env.example', colors.green);
    } else {
      log('❌ .env.example not found, please create .env manually', colors.red);
      return;
    }
  } else {
    log('✅ .env file already exists', colors.green);
  }
  
  // 2. Create test admin user
  log('\n👤 Creating test admin user...', colors.blue);
  try {
    require('dotenv').config();
    const MONGO_URI = process.env.MONGO_URI || 'mongodb://addenasang:abcd1234@ac-ixwwvqn-shard-00-00.9wlmev7.mongodb.net:27017,ac-ixwwvqn-shard-00-01.9wlmev7.mongodb.net:27017,ac-ixwwvqn-shard-00-02.9wlmev7.mongodb.net:27017/admin_backend?ssl=true&replicaSet=atlas-ixwwvqn-shard-0&authSource=admin&retryWrites=true&w=majority';
    const DB_NAME = process.env.DB_NAME || 'admin_backend';
    
    await mongoose.connect(MONGO_URI, { dbName: DB_NAME });
    
    // Check if admin exists
    const adminExists = await User.findOne({ email: 'admin@example.com' });
    if (adminExists) {
      log('ℹ️  Admin user already exists: admin@example.com / admin123', colors.blue);
    } else {
      const adminUser = new User({
        name: 'Admin User',
        email: 'admin@example.com',
        password: 'admin123',
        role: 'admin',
        active: true
      });
      
      await adminUser.save();
      log('✅ Admin user created: admin@example.com / admin123', colors.green);
    }
    
    // Create regular test user
    const testUserExists = await User.findOne({ email: 'test@example.com' });
    if (!testUserExists) {
      const testUser = new User({
        name: 'Test User',
        email: 'test@example.com',
        password: 'password123',
        role: 'user',
        active: true
      });
      
      await testUser.save();
      log('✅ Test user created: test@example.com / password123', colors.green);
    }
    
    await mongoose.disconnect();
  } catch (error) {
    log(`❌ Error creating test users: ${error.message}`, colors.red);
  }
}

// Run setup
runAllTests().catch(console.error);
