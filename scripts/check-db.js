'use strict';

require('dotenv').config();
const mongoose = require('mongoose');

const MONGO_URI = process.env.MONGO_URI;
const DB_NAME = process.env.DB_NAME || 'admin_backend';
const TIMEOUT = Number(process.env.MONGO_TIMEOUT_MS || 8000);

if (!MONGO_URI) {
  console.error('MONGO_URI is not set in .env');
  process.exit(2);
}

(async () => {
  const started = Date.now();
  try {
    await mongoose.connect(MONGO_URI, {
      dbName: DB_NAME,
      serverSelectionTimeoutMS: TIMEOUT,
      connectTimeoutMS: TIMEOUT,
      socketTimeoutMS: TIMEOUT,
    });

    // Ping the server via admin command
    const ping = await mongoose.connection.db.admin().command({ ping: 1 });

    console.log('Connected to MongoDB successfully');
    console.log(`DB Name: ${DB_NAME}`);
    console.log(`Mongoose readyState: ${mongoose.connection.readyState}`);
    console.log(`Ping result: ${JSON.stringify(ping)}`);
    console.log(`Elapsed: ${Date.now() - started}ms`);

    await mongoose.disconnect();
    process.exit(0);
  } catch (err) {
    console.error('Failed to connect to MongoDB');
    console.error(err && err.message ? err.message : err);
    if (err && err.name === 'MongoServerSelectionError') {
      console.error('Hint: Server selection failed. Check DNS SRV resolution, firewall, IP allow list, and internet connectivity.');
    }
    process.exit(1);
  }
})();
