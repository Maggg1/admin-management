'use strict';

// Load environment variables
require('dotenv').config();

// Import the Express app and database connection helper
const app = require('./app'); // This file will be added next
const { connectDB } = require('./config/db'); // This file will be added next

// Port configuration
const PORT = process.env.PORT || 4000;

// Connect to the database, then start the server
connectDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  });
