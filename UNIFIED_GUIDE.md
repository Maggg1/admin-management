# Unified Backend System - Admin and User on Same Server

## 🎯 Overview
This guide explains the unified backend system where both admin and user functionality run on the same server (Port 3000). This allows the admin to see user activities and who's logging in real-time.

## ✅ Current Setup

### Single Backend Server
- `index.js` - Unified backend server (Port 3000) with both admin and user functionality
- All APIs are available on the same domain/port
- Admin can monitor user activities in real-time

### Available API Endpoints

#### User Authentication & Management
- `POST /api/auth/register` - User registration (enabled)
- `POST /api/auth/login` - User login
- `GET /api/auth/me` - Get current user profile
- `PATCH /api/auth/profile` - Update user profile

#### Admin Authentication & Management
- `POST /api/admin/auth/register-admin` - First admin creation
- `POST /api/admin/auth/login` - Admin login
- `GET /api/admin/auth/me` - Get admin profile

#### User Management (Admin Only)
- `GET /api/admin/users` - List users with pagination
- `POST /api/admin/users` - Create user
- `GET /api/admin/users/:id` - Get user by ID
- `PATCH /api/admin/users/:id` - Update user
- `DELETE /api/admin/users/:id` - Delete user

#### Activities & Feedback
- `GET /api/activities` - Get user activities
- `POST /api/activities` - Create activity
- `GET /api/feedbacks` - Get feedback with pagination

#### Rewards & Shakes
- `GET /api/rewards` - Get rewards
- `POST /api/rewards` - Create reward
- `GET /api/admin/shakes` - Get shake activities (admin only)
- `POST /api/admin/shakes` - Create shake activity (admin only)

## 🚀 Quick Start

### Start Unified Backend

```bash
# Option 1: Development mode with auto-restart
npm run dev

# Option 2: Production mode
npm start

# Server runs on http://localhost:3000
```

### Test User Registration
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","email":"user@test.com","password":"password123"}'
```

### Test Admin Functions
```bash
# First, create initial admin
curl -X POST http://localhost:3000/api/admin/auth/register-admin \
  -H "Content-Type: application/json" \
  -d '{"name":"Admin","email":"admin@test.com","password":"admin123"}'

# Then login as admin
curl -X POST http://localhost:3000/api/admin/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.com","password":"admin123"}'
```

## 📱 Expo Integration

### API Configuration for Mobile App
```javascript
// In your Expo app - use the unified server
const API_BASE_URL = 'http://localhost:3000/api';

// Example registration
const registerUser = async (userData) => {
  const response = await fetch(`${API_BASE_URL}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(userData)
  });
  return response.json();
};
```

## 🔧 Environment Setup

### Update package.json
The main scripts to use:
```json
{
  "scripts": {
    "start": "node index.js",
    "dev": "nodemon index.js"
  }
}
```

### Environment Variables
Create `.env` file:
```bash
# Main server configuration
PORT=3000
MONGODB_URI=mongodb://localhost:27017/admin-backend
JWT_SECRET=your-secret-key
JWT_EXPIRES_IN=7d

# CORS configuration
ALLOWED_ORIGINS=http://localhost:19006,http://localhost:3000,http://localhost:5173
```

## 📊 Architecture Benefits

| Feature | Unified Backend (Port 3000) |
|---------|-----------------------------|
| **Deployment** | Single server to manage |
| **Monitoring** | Real-time user activity tracking |
| **Database** | Single MongoDB connection |
| **Authentication** | Unified JWT token system |
| **CORS** | Simplified configuration |
| **Maintenance** | Reduced complexity |

## 🎯 Key Advantages

1. **Real-time Monitoring**: Admin can see user logins and activities immediately
2. **Simplified Deployment**: Only one server to deploy and maintain
3. **Shared Database**: All data in one place for comprehensive reporting
4. **Consistent Authentication**: Single JWT secret and token format
5. **Reduced Complexity**: No need to manage multiple servers/ports

## 🚨 Important Notes

- **User Registration**: Enabled at `/api/auth/register` for regular users
- **Admin Registration**: First admin creation at `/api/admin/auth/register-admin`
- **Same Database**: All data stored in single MongoDB database
- **Role-based Access**: Proper authorization middleware protects admin endpoints
- **CORS Configured**: Works with Expo development server and web admin panel

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Kill process on port 3000
npx kill-port 3000
```

### MongoDB Connection Issues
```bash
# Ensure MongoDB is running
mongod
# Or use MongoDB Atlas connection string
```

### CORS Issues
The unified server includes comprehensive CORS configuration for:
- Expo development (ports 19000-19006)
- Web admin panel (port 3000)
- React development (port 5173)

## 🔄 Migration from Separate Servers

If you were previously using separate servers:
1. Stop any running `index-admin.js` or `index-user.js` processes
2. Update your Expo app to use port 3000 instead of 4001
3. Use `npm run dev` or `npm start` to run the unified server
4. All existing data remains available in the same database
