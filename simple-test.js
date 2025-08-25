const http = require('http');

const USER_BACKEND_URL = 'http://localhost:4001';
const ADMIN_BACKEND_URL = 'http://localhost:4000';

function makeRequest(method, url, data = null) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port,
      path: urlObj.pathname,
      method: method,
      headers: {
        'Content-Type': 'application/json',
      },
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        try {
          resolve({
            status: res.statusCode,
            data: JSON.parse(data),
          });
        } catch (e) {
          resolve({
            status: res.statusCode,
            data: data,
          });
        }
      });
    });

    req.on('error', (error) => {
      reject(error);
    });

    if (data) {
      req.write(JSON.stringify(data));
    }
    req.end();
  });
}

async function testUserRegistration() {
  console.log('🧪 Testing Backend Separation...\n');
  
  const testEmail = `testuser${Date.now()}@example.com`;
  
  try {
    // Test 1: User registration on user backend (should work)
    console.log('1. Testing user registration on USER backend (port 4001)...');
    try {
      const response = await makeRequest('POST', `${USER_BACKEND_URL}/api/auth/register`, {
        name: 'Test User',
        email: testEmail,
        password: 'password123'
      });
      
      if (response.status === 201) {
        console.log('✅ SUCCESS: User registration worked on user backend');
        console.log('   Response:', JSON.stringify(response.data, null, 2));
      } else {
        console.log('❌ FAILED: User registration failed on user backend');
        console.log('   Status:', response.status);
        console.log('   Response:', JSON.stringify(response.data, null, 2));
      }
    } catch (error) {
      console.log('❌ ERROR: User registration failed on user backend');
      console.log('   Error:', error.message);
    }

    console.log('\n2. Testing user registration on ADMIN backend (port 4000)...');
    try {
      const response = await makeRequest('POST', `${ADMIN_BACKEND_URL}/api/auth/register`, {
        name: 'Test User',
        email: `testuser2${Date.now()}@example.com`,
        password: 'password123'
      });
      
      if (response.status === 403) {
        console.log('✅ EXPECTED: User registration correctly rejected on admin backend');
        console.log('   Response:', response.data?.message || 'Registration disabled');
      } else {
        console.log('❌ UNEXPECTED: User registration worked on admin backend (should fail)');
        console.log('   Status:', response.status);
        console.log('   Response:', JSON.stringify(response.data, null, 2));
      }
    } catch (error) {
      console.log('❌ ERROR: Request failed completely');
      console.log('   Error:', error.message);
    }

  } catch (error) {
    console.log('❌ General error:', error.message);
  }
}

async function checkServers() {
  console.log('🔍 Checking if servers are running...');
  
  try {
    const response = await makeRequest('GET', `${USER_BACKEND_URL}/health`);
    console.log(`✅ User backend (4001) is running: ${response.data.status}`);
  } catch (error) {
    console.log('❌ User backend (4001) is not running or not accessible');
  }
  
  try {
    const response = await makeRequest('GET', `${ADMIN_BACKEND_URL}/health`);
    console.log(`✅ Admin backend (4000) is running: ${response.data.status}`);
  } catch (error) {
    console.log('❌ Admin backend (4000) is not running or not accessible');
  }
  
  console.log('\n');
}

async function main() {
  await checkServers();
  await testUserRegistration();
  
  console.log('\n📋 Summary:');
  console.log('- Your Expo app should use: http://localhost:4001/api/auth/register');
  console.log('- NOT: http://localhost:4000/api/auth/register');
  console.log('\n💡 Update your Expo app\'s API_BASE_URL to point to port 4001');
}

// Run the test
main().catch(console.error);
