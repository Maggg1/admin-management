# MongoDB Setup Guide

## 🎯 Quick Solution for Network Request Failed Error

The "network request failed" error in your ShakeApp is happening because:
1. MongoDB is not running locally
2. Your backends can't connect to the database
3. Your Expo app can't connect to the backend

## 🚀 Immediate Solutions

### Option 1: Use MongoDB Atlas (Cloud - Recommended)
1. Go to https://www.mongodb.com/atlas
2. Create a free account and cluster
3. Get your connection string
4. Update your `.env` file:

```bash
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/admin-backend
```

### Option 2: Install MongoDB Locally
```bash
# Using Chocolatey (Windows)
choco install mongodb

# Or download from https://www.mongodb.com/try/download/community
```

### Option 3: Use Docker
```bash
docker run -d -p 27017:27017 --name mongodb mongo:latest
```

## 🔧 Quick Fix for Testing

For immediate testing, let's modify the user backend to use a different approach:

1. **Stop the current server** (Ctrl+C in the terminal)
2. **Use an in-memory database for testing** (temporary solution)

## 📱 Expo App Configuration

Make sure your Expo app is pointing to the correct backend:

```javascript
// For development (User backend - port 4001)
const API_BASE_URL = 'http://localhost:4001/api';

// For Android emulator
const API_BASE_URL = 'http://10.0.2.2:4001/api';

// For production (after deployment)
const API_BASE_URL = 'https://your-user-backend-domain.com/api';
```

## 🐛 Troubleshooting Steps

1. **Check if backend is running**: 
   ```bash
   curl http://localhost:4001/health
   ```

2. **Check MongoDB connection**:
   ```bash
   telnet localhost 27017
   ```

3. **Test user registration directly**:
   ```bash
   curl -X POST http://localhost:4001/api/auth/register \
     -H "Content-Type: application/json" \
     -d '{"name":"Test","email":"test@test.com","password":"test123"}'
   ```

## 🎯 Next Steps

1. **Set up MongoDB** (choose one option above)
2. **Start user backend**: `npm run dev:user`
3. **Test connection**: Use the test script provided
4. **Update Expo app**: Point to correct backend URL

## 📞 Need Help?

If you need help setting up MongoDB, I can guide you through:
- MongoDB Atlas setup
- Local MongoDB installation  
- Docker setup
- Connection string configuration
