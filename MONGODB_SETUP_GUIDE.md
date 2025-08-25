# MongoDB Setup Guide

## 🎯 Problem
Your backends are failing to start because MongoDB is not running.

## 🔧 Solutions

### Option 1: Install and Start MongoDB Locally

#### 1. Download MongoDB Community Server
Download from: https://www.mongodb.com/try/download/community

#### 2. Install MongoDB
- Run the installer
- Choose "Complete" installation
- Install MongoDB as a service (recommended)

#### 3. Start MongoDB Service
```bash
# Start MongoDB service
net start MongoDB

# Or manually start mongod
mongod --dbpath "C:\data\db"
```

#### 4. Create data directory
```bash
mkdir C:\data\db
```

### Option 2: Use MongoDB Atlas (Cloud - Recommended)

#### 1. Create free account at https://www.mongodb.com/atlas

#### 2. Create a cluster
- Choose free tier
- Select your region
- Create database user

#### 3. Get connection string
- Go to Cluster -> Connect -> Connect your application
- Copy the connection string

#### 4. Update .env file
```bash
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/admin-backend?retryWrites=true&w=majority
```

### Option 3: Use In-Memory Database for Testing

I've created a test script that works without MongoDB for quick testing:

```bash
node test-with-memory-db.js
```

## 🚀 Quick Start Commands

### Start MongoDB (if installed locally)
```bash
# Method 1: Start as service
net start MongoDB

# Method 2: Manual start
mongod --dbpath "C:\data\db"
```

### Start Backends (after MongoDB is running)
```bash
# Terminal 1 - Admin Backend
npm run start:admin

# Terminal 2 - User Backend
npm run start:user
```

## 📊 Verify MongoDB Connection

### Check if MongoDB is running
```bash
# Check MongoDB service status
sc query MongoDB

# Check if port 27017 is listening
netstat -an | find "27017"
```

### Test MongoDB connection
```bash
# Connect with mongo shell
mongo
```

## 🔧 Troubleshooting

### Common Issues
1. **Port 27017 already in use**: 
   ```bash
   netstat -ano | findstr :27017
   taskkill /PID <PID> /F
   ```

2. **Data directory doesn't exist**:
   ```bash
   mkdir C:\data\db
   ```

3. **Permission issues**: Run command prompt as Administrator

### MongoDB Not Starting?
```bash
# Check MongoDB logs
# Usually in C:\Program Files\MongoDB\Server\5.0\log\mongod.log

# Try manual start with verbose logging
mongod --dbpath "C:\data\db" --logpath "C:\mongodb.log" --verbose
```

## 🌐 MongoDB Atlas (Recommended for Production)

### Benefits:
- No local installation needed
- Always available
- Free tier available
- Automatic backups
- Scalable

### Setup Steps:
1. Create account at mongodb.com/atlas
2. Create free cluster
3. Create database user
4. Whitelist IP addresses (0.0.0.0/0 for all)
5. Get connection string
6. Update .env file

## 🎯 Next Steps

1. **Choose an option above** to get MongoDB running
2. **Start both backends** once MongoDB is available
3. **Test the setup** with the provided test scripts
4. **Update your Expo app** to use the correct backend URL

Your backend separation is ready - you just need MongoDB running! 🚀
