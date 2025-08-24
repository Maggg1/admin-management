# Unified Backend Setup - Next Steps

## ✅ Completed Changes

1. **Updated main index.js** to include all routes:
   - User authentication (`/api/auth`) with registration enabled
   - Admin authentication (`/api/admin/auth`) 
   - User management (`/api/users`)
   - Admin management (`/api/admin`)
   - Activities (`/api/activities`)
   - Feedback (`/api/feedbacks`)
   - Rewards (`/api/rewards`)

2. **Fixed pagination** on GET `/api/admin/shakes` endpoint

3. **Created unified documentation** in `UNIFIED_GUIDE.md`

## 🚀 Immediate Actions

1. **Stop any separate servers** if they are running:
   ```bash
   # Stop admin server (port 4000)
   npx kill-port 4000
   
   # Stop user server (port 4001)  
   npx kill-port 4001
   ```

2. **Start the unified server**:
   ```bash
   npm run dev
   # Server will run on http://localhost:3000
   ```

3. **Update your Expo app** to use the unified server:
   ```javascript
   // Change from port 4001 to 3000
   const API_BASE_URL = 'http://localhost:3000/api';
   ```

## 📋 Verification Checklist

- [ ] User registration works at `POST /api/auth/register`
- [ ] Admin can login at `POST /api/admin/auth/login`
- [ ] Admin can see users at `GET /api/admin/users`
- [ ] Admin can see activities at `GET /api/activities`
- [ ] Admin can see shakes with pagination at `GET /api/admin/shakes?page=1&limit=10`
- [ ] Mobile app connects to port 3000 instead of 4001

## 🔧 Configuration Notes

- The unified server uses **port 3000** by default
- User registration is **enabled** at `/api/auth/register`
- Admin endpoints require proper authentication and authorization
- All data remains in the same MongoDB database
- CORS is configured for Expo development and web admin

## 🎯 Benefits Achieved

- ✅ **Real-time monitoring**: Admin can see user activities immediately
- ✅ **Simplified deployment**: Only one server to manage
- ✅ **Shared database**: All data accessible from single interface
- ✅ **Reduced complexity**: No multiple server coordination needed

## 📞 Support

If you encounter any issues:
1. Check that MongoDB is running
2. Verify port 3000 is available
3. Review the `UNIFIED_GUIDE.md` for detailed instructions
4. Check server logs for any error messages
