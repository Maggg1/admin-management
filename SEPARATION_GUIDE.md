# Backend Separation Guide - Admin vs User Systems

## 🎯 Overview
This guide explains how to separate your backend into two distinct systems:
1. **Admin Backend** - For admin management (Port 4000)
2. **User Backend** - For mobile app users (Port 4001)

## ✅ Completed Changes

### 1. Created Separate Backend Entry Points
- `index-admin.js` - Admin backend server
- `index-user.js` - User backend server

### 2. Created User-Specific Authentication
- `routes/userAuth.js` - User registration/login endpoints (enabled)

### 3. Maintained Admin-Only System
- `routes/auth.js` - Admin authentication (registration disabled for users)
- `routes/admin.js` - Admin user management endpoints

## 🚀 Quick Start

### Start Both Backends

```bash
# Option 1: Run both backends simultaneously
npm run dev:both

# Option 2: Run separately
# Terminal 1: Admin Backend
npm run dev:admin
# Runs on http://localhost:4000

# Terminal 2: User Backend  
npm run dev:user
# Runs on http://localhost:4001
```

### Test User Registration (Now Enabled)
```bash
curl -X POST http://localhost:4001/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","email":"user@test.com","password":"password123"}'
```

### Test Admin Functions
```bash
# First, create initial admin (if none exists)
curl -X POST http://localhost:4000/api/auth/register-admin \
  -H "Content-Type: application/json" \
  -d '{"name":"Admin","email":"admin@test.com","password":"admin123"}'

# Then login as admin
curl -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.com","password":"admin123"}'
```

## 📱 Expo Integration

### API Configuration for Mobile App
```javascript
// In your Expo app
const USER_API_BASE_URL = 'http://localhost:4001/api';

// Example registration
const registerUser = async (userData) => {
  const response = await fetch(`${USER_API_BASE_URL}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(userData)
  });
  return response.json();
};
```

## 🔧 Environment Setup

### Update package.json
Add these scripts to your package.json:
```json
{
  "scripts": {
    "start:admin": "node index-admin.js",
    "start:user": "node index-user.js",
    "dev:admin": "nodemon index-admin.js",
    "dev:user": "nodemon index-user.js"
  }
}
```

### Environment Variables
Create `.env` file:
```bash
# For both backends
MONGODB_URI=mongodb://localhost:27017/admin-backend
JWT_SECRET=your-secret-key

# Optional: Different ports
ADMIN_API_PORT=4000
USER_API_PORT=4001
```

## 📊 Architecture Comparison

| Feature | Admin Backend (4000) | User Backend (4001) |
|---------|---------------------|---------------------|
| **Registration** | Disabled for users | Enabled for all |
| **User Creation** | Admin-only via `/admin/users` | Public via `/auth/register` |
| **Authentication** | Admin login only | User login only |
| **User Management** | Full CRUD via admin endpoints | Self-service only |
| **Target** | Web admin panel | Mobile app (Expo) |

## 🔄 API Endpoints

### User Backend (Port 4001)
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `GET /api/auth/me` - Get current user
- `PATCH /api/auth/profile` - Update user profile

### Admin Backend (Port 4000)
- `POST /api/auth/register-admin` - First admin creation
- `POST /api/auth/login` - Admin login
- `POST /api/admin/users` - Create user (admin only)
- `GET /api/admin/users` - List users (admin only)
- `PATCH /api/admin/users/:id` - Update user (admin only)
- `DELETE /api/admin/users/:id` - Delete user (admin only)

## 🎯 Next Steps

1. **Install dependencies**: `npm install`
2. **Start MongoDB**: Ensure MongoDB is running
3. **Test endpoints**: Use the curl commands above
4. **Configure Expo**: Update your mobile app to use port 4001
5. **Deploy separately**: Deploy admin and user backends to different domains

## 🚨 Important Notes

- **Same Database**: Both backends use the same MongoDB database
- **User Roles**: Users created via user backend get `role: 'user'`
- **Admin Roles**: Users created via admin backend can be `admin` or `user`
- **No Conflict**: The systems are completely separate and won't interfere

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Kill processes on ports 4000 or 4001
npx kill-port 4000
npx kill-port 4001
```

### MongoDB Connection Issues
```bash
# Ensure MongoDB is running
mongod
# Or use MongoDB Atlas connection string
```

### CORS Issues
Both backends include CORS middleware, so they should work with Expo's development server.
