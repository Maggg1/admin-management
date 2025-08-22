const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const userAuthRoutes = require('./routes/userAuth');

// Create in-memory MongoDB server for testing
async function setupTestEnvironment() {
  console.log('🚀 Setting up test environment with in-memory MongoDB...');
  
  // Start in-memory MongoDB
  const mongod = await MongoMemoryServer.create();
  const uri = mongod.getUri();
  
  // Connect to in-memory database
  await mongoose.connect(uri);
  console.log('✅ Connected to in-memory MongoDB');
  
  return { mongod, uri };
}

// Test user registration
async function testUserRegistration() {
  try {
    const { mongod, uri } = await setupTestEnvironment();
    
    console.log('\n🧪 Testing user registration on port 4001...');
    
    // Create a simple Express server for testing
    const express = require('express');
    const app = express();
    app.use(express.json());
    
    // Mount user auth routes
    app.use('/api/auth', userAuthRoutes);
    
    // Health check
    app.get('/health', (req, res) => {
      res.json({ status: 'Test server running', timestamp: new Date().toISOString() });
    });
    
    // Start test server
    const PORT = 4001;
    const server = app.listen(PORT, () => {
      console.log(`✅ Test server running on port ${PORT}`);
    });
    
    // Wait a moment for server to start
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Test health endpoint
    console.log('\n📊 Testing health endpoint...');
    const healthResponse = await fetch(`http://localhost:${PORT}/health`);
    console.log(`Health check: ${healthResponse.status} ${healthResponse.statusText}`);
    
    // Test user registration
    console.log('\n👤 Testing user registration...');
    try {
      const registerResponse = await fetch(`http://localhost:${PORT}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Test User',
          email: 'test@example.com',
          password: 'password123'
        })
      });
      
      const result = await registerResponse.json();
      console.log(`Registration response: ${registerResponse.status}`);
      console.log('Registration result:', result);
      
      if (registerResponse.status === 201) {
        console.log('✅ User registration SUCCESSFUL!');
      } else {
        console.log('❌ User registration FAILED');
      }
      
    } catch (error) {
      console.log('❌ Registration test error:', error.message);
    }
    
    // Cleanup
    server.close();
    await mongoose.disconnect();
    await mongod.stop();
    console.log('\n🧹 Test environment cleaned up');
    
  } catch (error) {
    console.error('❌ Test setup failed:', error.message);
  }
}

// Install mongodb-memory-server if not already installed
async function ensureDependencies() {
  try {
    require('mongodb-memory-server');
  } catch (error) {
    console.log('📦 Installing mongodb-memory-server...');
    const { execSync } = require('child_process');
    execSync('npm install mongodb-memory-server --no-save', { stdio: 'inherit' });
  }
}

// Run the test
async function runTest() {
  await ensureDependencies();
  await testUserRegistration();
}

runTest().catch(console.error);
