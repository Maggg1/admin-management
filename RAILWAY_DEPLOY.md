# Railway Deployment Guide

## Fixed Issues
✅ **Missing imports**: Added express, mongoose, cors, morgan, dotenv
✅ **Server variable**: Fixed server.close() reference
✅ **Process handling**: Added proper graceful shutdown
✅ **Database connection**: Added retry logic with exponential backoff
✅ **Environment variables**: Added .env.example for Railway configuration

## Railway Setup Steps

1. **Connect your GitHub repository** to Railway
2. **Set environment variables** in Railway dashboard:
   - `MONGO_URI`: Your MongoDB connection string (use MongoDB Atlas)
   - `JWT_SECRET`: A strong random string (min 32 chars)
   - `ALLOWED_ORIGINS`: Your frontend domain(s)
   - `PORT`: Railway will set this automatically

3. **Deploy** - Railway will automatically:
   - Install dependencies from package.json
   - Start the server using `npm start`
   - Use the PORT environment variable

## Environment Variables for Railway
```
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/admin_backend?retryWrites=true&w=majority
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
JWT_EXPIRES_IN=7d
ALLOWED_ORIGINS=https://your-frontend-domain.com,https://your-admin-dashboard.com
DB_NAME=admin_backend
```

## Health Check Endpoints
- `/health` - Basic health check
- `/ready` - Database connection status

## Troubleshooting
- Check Railway logs for any startup errors
- Ensure MongoDB Atlas allows connections from Railway IP
- Verify all environment variables are set correctly
