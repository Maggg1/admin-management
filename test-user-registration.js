const axios = require('axios');

const USER_BACKEND_URL = 'http://localhost:4001';
const ADMIN_BACKEND_URL = 'http://localhost:4000';

async function testUserRegistration() {
  console.log('🧪 Testing User Backend Registration...\n');
  
  try {
    // Test 1: User registration on user backend (should work)
    console.log('1. Testing user registration on USER backend (port 4001)...');
    try {
      const userResponse = await axios.post(`${USER_BACKEND_URL}/api/auth/register`, {
        name: 'Test User',
        email: `testuser${Date.now()}@example.com`,
        password: 'password123'
      });
      console.log('✅ SUCCESS: User registration worked on user backend');
      console.log('   Response:', userResponse.data);
    } catch (error) {
      console.log('❌ FAILED: User registration failed on user backend');
      console.log('   Error:', error.response?.data || error.message);
    }

    console.log('\n2. Testing user registration on ADMIN backend (port 4000)...');
    try {
      const adminResponse = await axios.post(`${ADMIN_BACKEND_URL}/api/auth/register`, {
        name: 'Test User',
        email: `testuser${Date.now()}@example.com`,
        password: 'password123'
      });
      console.log('❌ UNEXPECTED: User registration worked on admin backend (should fail)');
      console.log('   Response:', adminResponse.data);
    } catch (error) {
      console.log('✅ EXPECTED: User registration failed on admin backend (as intended)');
      console.log('   Error:', error.response?.data?.message || error.message);
    }

    console.log('\n3. Testing admin registration on ADMIN backend...');
    try {
      const adminRegResponse = await axios.post(`${ADMIN_BACKEND_URL}/api/auth/register-admin`, {
        name: 'Test Admin',
        email: `testadmin${Date.now()}@example.com`,
        password: 'admin123'
      });
      console.log('✅ SUCCESS: Admin registration worked on admin backend');
      console.log('   Response:', adminRegResponse.data);
    } catch (error) {
      console.log('❌ FAILED: Admin registration failed on admin backend');
      console.log('   Error:', error.response?.data || error.message);
    }

  } catch (error) {
    console.log('❌ General error:', error.message);
  }
}

// Check if servers are running first
async function checkServers() {
  console.log('🔍 Checking if servers are running...');
  
  try {
    const userHealth = await axios.get(`${USER_BACKEND_URL}/health`);
    console.log(`✅ User backend (4001) is running: ${userHealth.data.status}`);
  } catch (error) {
    console.log('❌ User backend (4001) is not running');
  }
  
  try {
    const adminHealth = await axios.get(`${ADMIN_BACKEND_URL}/health`);
    console.log(`✅ Admin backend (4000) is running: ${adminHealth.data.status}`);
  } catch (error) {
    console.log('❌ Admin backend (4000) is not running');
  }
  
  console.log('\n');
}

async function main() {
  await checkServers();
  await testUserRegistration();
  
  console.log('\n📋 Summary:');
  console.log('- User backend (4001): Should allow user registration');
  console.log('- Admin backend (4000): Should reject user registration but allow admin registration');
  console.log('\n💡 Your Expo app should use: http://localhost:4001/api/auth/register');
}

// Run the test
main().catch(console.error);
