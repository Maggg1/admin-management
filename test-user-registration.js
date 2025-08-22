const http = require('http');

// Test user registration on the user backend
const testData = JSON.stringify({
  name: "Test User",
  email: "test@example.com",
  password: "password123"
});

const options = {
  hostname: 'localhost',
  port: 4001,
  path: '/api/auth/register',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': testData.length
  }
};

const req = http.request(options, (res) => {
  console.log(`Status Code: ${res.statusCode}`);
  
  let data = '';
  res.on('data', (chunk) => {
    data += chunk;
  });
  
  res.on('end', () => {
    console.log('Response:', data);
    if (res.statusCode === 201) {
      console.log('✅ User registration test PASSED!');
    } else {
      console.log('❌ User registration test FAILED!');
    }
  });
});

req.on('error', (error) => {
  console.log('Error:', error.message);
  if (error.code === 'ECONNREFUSED') {
    console.log('⚠️  User backend is not running on port 4001');
    console.log('Start it with: npm run start:user');
  }
});

req.write(testData);
req.end();
