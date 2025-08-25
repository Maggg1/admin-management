'use strict';

const { retry, retryDatabaseOperation, retryApiCall } = require('../utils/retry');
const mongoose = require('mongoose');

// Test retry utility
async function testRetryUtility() {
  console.log('🧪 Testing retry utility...');

  // Test 1: Successful operation
  console.log('\n1. Testing successful operation...');
  try {
    const result = await retry(async () => {
      return 'Success!';
    });
    console.log('✅ Success:', result);
  } catch (error) {
    console.error('❌ Unexpected error:', error.message);
  }

  // Test 2: Operation that fails then succeeds
  console.log('\n2. Testing operation that fails then succeeds...');
  let attempts = 0;
  try {
    const result = await retry(async () => {
      attempts++;
      if (attempts < 3) {
        throw new Error(`Temporary error (attempt ${attempts})`);
      }
      return `Success after ${attempts} attempts`;
    }, { maxRetries: 3, delay: 100 });
    console.log('✅ Success:', result);
  } catch (error) {
    console.error('❌ Unexpected error:', error.message);
  }

  // Test 3: Operation that always fails
  console.log('\n3. Testing operation that always fails...');
  try {
    await retry(async () => {
      throw new Error('Permanent error');
    }, { maxRetries: 2, delay: 100 });
    console.error('❌ Should have thrown an error');
  } catch (error) {
    console.log('✅ Expected error:', error.message);
  }

  // Test 4: Database operation simulation
  console.log('\n4. Testing database retry...');
  let dbAttempts = 0;
  try {
    const result = await retryDatabaseOperation(async () => {
      dbAttempts++;
      if (dbAttempts < 2) {
        const error = new Error('MongoNetworkError: connection timeout');
        error.name = 'MongoNetworkError';
        throw error;
      }
      return 'Database operation successful';
    });
    console.log('✅ Database success:', result);
  } catch (error) {
    console.error('❌ Database error:', error.message);
  }

  // Test 5: API call simulation
  console.log('\n5. Testing API retry...');
  let apiAttempts = 0;
  try {
    const result = await retryApiCall(async () => {
      apiAttempts++;
      if (apiAttempts < 2) {
        const error = new Error('Request failed with status code 503');
        error.response = { status: 503 };
        throw error;
      }
      return 'API call successful';
    });
    console.log('✅ API success:', result);
  } catch (error) {
    console.error('❌ API error:', error.message);
  }

  console.log('\n🎉 All retry tests completed!');
}

// Test MongoDB connection retry
async function testMongoRetry() {
  console.log('\n🧪 Testing MongoDB connection retry...');
  
  const MONGO_URI = process.env.MONGO_URI || 'mongodb://addenasang:abcd1234@ac-ixwwvqn-shard-00-00.9wlmev7.mongodb.net:27017,ac-ixwwvqn-shard-00-01.9wlmev7.mongodb.net:27017,ac-ixwwvqn-shard-00-02.9wlmev7.mongodb.net:27017/admin_backend?ssl=true&replicaSet=atlas-ixwwvqn-shard-0&authSource=admin&retryWrites=true&w=majority';
  
  try {
    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 2000,
      connectTimeoutMS: 2000,
    });
    
    console.log('✅ MongoDB connection successful');
    await mongoose.connection.close();
  } catch (error) {
    console.log('❌ MongoDB connection failed (expected if not running):', error.message);
  }
}

// Run tests
async function runTests() {
  try {
    await testRetryUtility();
    await testMongoRetry();
  } catch (error) {
    console.error('❌ Test suite error:', error);
  } finally {
    process.exit(0);
  }
}

// Only run if called directly
if (require.main === module) {
  runTests();
}

module.exports = { testRetryUtility, testMongoRetry };
