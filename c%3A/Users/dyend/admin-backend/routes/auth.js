// ... existing code ...
      // **ADMIN-ONLY LOGIN** - Reject non-admin users
      if (user.role !== 'admin') {
        console.log(`❌ Admin login failed: Non-admin user attempted login for email: ${email}`);
        return res.status(403).json({ 
          message: 'Access denied. Admin privileges required.',
          debug: process.env.NODE_ENV === 'development' ? 'Non-admin user' : undefined
        });
      }
// ... existing code ...