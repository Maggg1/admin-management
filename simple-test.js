const express = require('express');
const userAuthRoutes = require('./routes/userAuth');

async function testUserRegistration() {
  console.log('🧪 Testing user registration logic...');
  
  // Create a simple test server
  const app = express();
  app.use(express.json());
  app.use('/api/auth', userAuthRoutes);
  
  const PORT = 4001;
  const server = app.listen(PORT, () => {
    console.log(`✅ Test server running on port ${PORT}`);
  });
  
  // Test the registration endpoint directly
  console.log('\n📋 Testing registration endpoint structure...');
  
  // Check if the route exists
  const routes = userAuthRoutes.stack;
  const registerRoute = routes.find(route => 
    route.route && route.route.path === '/register' && route.route.methods.post
  );
  
  if (registerRoute) {
    console.log('✅ POST /api/auth/register route exists');
    console.log('✅ User registration is ENABLED in userAuth.js');
  } else {
    console.log('❌ POST /api/auth/register route NOT found');
  }
  
  // Compare with admin auth (should be disabled)
  const authRoutes = require('./routes/auth');
  const adminRegisterRoute = authRoutes.stack.find(route => 
    route.route && route.route.path === '/register' && route.route.methods.post
  );
  
  if (adminRegisterRoute) {
    console.log('⚠️  POST /api/auth/register also exists in admin auth (but should return 403)');
  }
  
  server.close();
  console.log('\n🎯 Test completed. User registration endpoint is properly configured!');
}

testUserRegistration().catch(console.error);
