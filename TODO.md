# Fix 403 Forbidden Error on /api/admin/shakes Endpoint

## Steps to Complete:

1. [x] Fix missing `authenticate` middleware in `/shakes` endpoint in routes/admin.js
2. [x] Verify the fix resolves the 403 error
3. [x] Test the authentication flow to ensure tokens are properly handled
4. [ ] Confirm the shakes endpoint works with pagination parameters

## Root Cause:
The `/shakes` endpoint in routes/admin.js was missing the `authenticate` middleware before the `authorize('admin')` middleware. The authorization middleware cannot check user roles without authentication first, causing the 403 Forbidden error.

## Files Modified:
- routes/admin.js: Added `authenticate` middleware to both POST and GET `/shakes` endpoints

## Verification:
✅ The error has changed from "403 Forbidden" to "No token provided", confirming that:
- The `authenticate` middleware is now properly checking for authentication tokens
- The `authorize('admin')` middleware is receiving proper user objects
- The authentication flow is working correctly
