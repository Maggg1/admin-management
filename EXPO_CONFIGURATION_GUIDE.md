# Expo Frontend Configuration Guide

## 🎯 Problem
Your Expo app is trying to register users at the admin backend (port 4000) instead of the user backend (port 4001), causing 403 errors.

## 🔧 Solution
Update your Expo app's API configuration to use the user backend endpoints.

## 📱 Expo App Configuration

### 1. Update API Base URL
In your Expo app, change the API base URL from:
```javascript
// ❌ WRONG - Using admin backend
const API_BASE_URL = 'https://adminmanagementsystem.up.railway.app/api';
// or
const API_BASE_URL = 'http://localhost:4000/api';
```

To:
```javascript
// ✅ CORRECT - Using user backend
const API_BASE_URL = 'http://localhost:4001/api'; // For development
// or for production:
const API_BASE_URL = 'https://your-user-backend-domain.com/api';
```

### 2. Environment-Based Configuration
Create environment-specific configuration:

```javascript
// config.js
const ENV = {
  development: {
    API_BASE_URL: 'http://localhost:4001/api',
  },
  staging: {
    API_BASE_URL: 'https://your-staging-domain.com/api',
  },
  production: {
    API_BASE_URL: 'https://your-production-domain.com/api',
  },
};

const getEnvVars = (env = process.env.NODE_ENV) => {
  return ENV[env] || ENV.development;
};

export default getEnvVars;
```

### 3. Usage in Your Expo App
```javascript
// authService.js
import getEnvVars from './config';

const { API_BASE_URL } = getEnvVars();

export const registerUser = async (userData) => {
  try {
    const response = await fetch(`${API_BASE_URL}/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(userData),
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.message || 'Registration failed');
    }
    
    return await response.json();
  } catch (error) {
    throw error;
  }
};

export const loginUser = async (credentials) => {
  try {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(credentials),
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.message || 'Login failed');
    }
    
    return await response.json();
  } catch (error) {
    throw error;
  }
};
```

### 4. React Native Usage Example
```javascript
// App.js or your registration component
import React, { useState } from 'react';
import { View, TextInput, Button, Alert } from 'react-native';
import { registerUser } from './services/authService';

const RegistrationScreen = () => {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleRegister = async () => {
    if (!name || !email || !password) {
      Alert.alert('Error', 'Please fill all fields');
      return;
    }

    setLoading(true);
    try {
      const result = await registerUser({ name, email, password });
      Alert.alert('Success', 'Registration successful!');
      // Navigate to login or home screen
    } catch (error) {
      Alert.alert('Error', error.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <View style={{ padding: 20 }}>
      <TextInput
        placeholder="Name"
        value={name}
        onChangeText={setName}
        style={{ borderWidth: 1, padding: 10, marginBottom: 10 }}
      />
      <TextInput
        placeholder="Email"
        value={email}
        onChangeText={setEmail}
        keyboardType="email-address"
        autoCapitalize="none"
        style={{ borderWidth: 1, padding: 10, marginBottom: 10 }}
      />
      <TextInput
        placeholder="Password"
        value={password}
        onChangeText={setPassword}
        secureTextEntry
        style={{ borderWidth: 1, padding: 10, marginBottom: 10 }}
      />
      <Button
        title={loading ? "Registering..." : "Register"}
        onPress={handleRegister}
        disabled={loading}
      />
    </View>
  );
};

export default RegistrationScreen;
```

## 🚀 Testing Your Setup

### 1. Start Both Backends
```bash
# Terminal 1 - Admin Backend
npm run start:admin

# Terminal 2 - User Backend  
npm run start:user
```

### 2. Test User Registration
```bash
# Test with curl
curl -X POST http://localhost:4001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","email":"user@test.com","password":"password123"}'
```

### 3. Test User Login
```bash
curl -X POST http://localhost:4001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@test.com","password":"password123"}'
```

## 🌐 Deployment Considerations

### For Railway Deployment
1. **Admin Backend**: Deploy to `adminmanagementsystem.up.railway.app` (port 4000)
2. **User Backend**: Deploy to a different Railway app (port 4001)

### Environment Variables for Production
```bash
# User Backend .env
MONGODB_URI=your-mongodb-connection-string
JWT_SECRET=your-production-jwt-secret
USER_API_PORT=4001
ALLOWED_ORIGINS=https://yourapp.com,https://yourapp.expo.dev
```

### CORS Configuration
Ensure your user backend allows requests from your Expo app's domains:
- `https://yourapp.expo.dev` (Expo Go)
- Your custom domain when published

## 🐛 Troubleshooting

### Common Issues
1. **CORS Errors**: Make sure `ALLOWED_ORIGINS` includes your Expo app's URL
2. **Connection Refused**: Check if both backends are running on correct ports
3. **MongoDB Connection**: Ensure MongoDB is running locally or connection string is correct

### Debugging Steps
1. Check console logs from both backends
2. Test endpoints with curl or Postman
3. Verify MongoDB connection
4. Check CORS headers in responses

## 📞 Support
If you encounter issues:
1. Check both backend servers are running
2. Verify MongoDB connection
3. Test endpoints directly with curl
4. Check browser console for CORS errors

Remember: Your Expo app should ONLY communicate with the user backend (port 4001) for authentication and user operations.
