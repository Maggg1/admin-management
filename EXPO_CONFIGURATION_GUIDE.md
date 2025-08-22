# Expo Frontend Configuration Guide

## 🎯 Overview
This guide explains how to configure your Expo mobile app to work with the separated backend system.

## 🔧 Current Issue
Your Expo app is trying to register users at:
`https://adminmanagementsystem.up.railway.app/api/auth/register`

This is the **admin backend** where user registration is disabled. You need to point it to the **user backend**.

## 📱 Expo Configuration

### Development Configuration
```javascript
// In your Expo app's config (e.g., constants.js or config.js)

// For development (localhost)
export const API_BASE_URL = __DEV__ 
  ? 'http://localhost:4001/api' 
  : 'https://your-user-backend-domain.com/api';

// Or if using environment variables
export const API_BASE_URL = process.env.EXPO_PUBLIC_API_URL || 'http://localhost:4001/api';
```

### Environment Variables
Create a `.env` file in your Expo project root:
```bash
EXPO_PUBLIC_API_URL=http://localhost:4001/api
EXPO_PUBLIC_ADMIN_URL=http://localhost:4000/api
```

### Example API Service
```javascript
// services/api.js
import { API_BASE_URL } from '../config';

export const authAPI = {
  // User registration
  register: async (userData) => {
    const response = await fetch(`${API_BASE_URL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(userData)
    });
    return response.json();
  },

  // User login
  login: async (credentials) => {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials)
    });
    return response.json();
  },

  // Get user profile
  getProfile: async (token) => {
    const response = await fetch(`${API_BASE_URL}/auth/me`, {
      method: 'GET',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      }
    });
    return response.json();
  }
};
```

## 🚀 Quick Fix
Change your registration endpoint from:
```javascript
// ❌ Wrong - Admin backend
const url = 'https://adminmanagementsystem.up.railway.app/api/auth/register';

// ✅ Correct - User backend  
const url = 'http://localhost:4001/api/auth/register'; // Development
// or
const url = 'https://your-user-backend-domain.com/api/auth/register'; // Production
```

## 🌐 Production Deployment

### Option 1: Separate Domains (Recommended)
- **Admin Backend**: `admin-api.yourdomain.com` (port 4000)
- **User Backend**: `api.yourdomain.com` (port 4001)

### Option 2: Same Domain, Different Paths
- **Admin Backend**: `yourdomain.com/admin-api`
- **User Backend**: `yourdomain.com/api`

### Railway Deployment
For Railway deployment, you'll need to:
1. Deploy the user backend separately
2. Update your Expo app to use the user backend URL
3. Configure CORS for mobile app access

## 🔧 CORS Configuration
Both backends already include CORS middleware that should work with Expo. If you encounter CORS issues, check:

1. **User Backend** (`index-user.js`): Uses `app.use(cors())` for all origins
2. **Admin Backend** (`index-admin.js`): Also uses `app.use(cors())`

## 🧪 Testing

### Test User Registration
```bash
# Test user registration locally
curl -X POST http://localhost:4001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","email":"user@test.com","password":"password123"}'
```

### Test from Expo App
1. Start both backends: `npm run dev:both`
2. Run your Expo app: `npx expo start`
3. Test registration functionality

## 🐛 Troubleshooting

### Common Issues
1. **Connection Refused**: Ensure user backend is running on port 4001
2. **CORS Errors**: Check that CORS is enabled in both backends
3. **404 Errors**: Verify the endpoint URL is correct

### Network Configuration
For Android emulator to access localhost:
```javascript
// Use 10.0.2.2 for Android emulator
const API_BASE_URL = Platform.OS === 'android' 
  ? 'http://10.0.2.2:4001/api'
  : 'http://localhost:4001/api';
```

For iOS simulator, localhost should work directly.

## 📋 Next Steps
1. Update your Expo app's API configuration
2. Test registration with the user backend
3. Deploy user backend to production
4. Update production API URLs

## 🆘 Need Help?
If you encounter issues:
1. Check that both backends are running
2. Verify MongoDB connection
3. Test endpoints with curl first
4. Check console logs for errors
