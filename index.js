const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const morgan = require('morgan');
const { body } = require('express-validator');
require('dotenv').config();

const {
  securityHeaders,
  sanitizeInput,
  errorHandler,
  authenticate,
  authorize,
} = require('./middleware/security');
const handleValidation = require('./utils/validation');

// Import routes
const authRoutes = require('./routes/auth');
const adminAuthRoutes = require('./routes/adminAuth');
const adminRoutes = require('./routes/admin');
const userRoutes = require('./routes/users');
const rewardRoutes = require('./routes/rewards');

const app = express();

// Configuration
// const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017';
const DB_NAME = process.env.DB_NAME || 'admin_backend';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

// Retry configuration
const MAX_RETRIES = 5;
const RETRY_DELAY = 5000; // 5 seconds
const MONGO_TIMEOUT_MS = Number(process.env.MONGO_TIMEOUT_MS || 8000);

// CORS configuration for React/Expo app and general usage
const allowedOriginsEnv = process.env.ALLOWED_ORIGINS || '';
const allowedList = allowedOriginsEnv.split(',').map((s) => s.trim()).filter(Boolean);

function matchesAllowed(originStr, allowed) {
  try {
    const o = new URL(originStr);
    const oHost = o.hostname.toLowerCase();
    const oPort = (o.port || '').toLowerCase();
    const oProto = o.protocol.toLowerCase();
    const oOrigin = `${oProto}//${oHost}${oPort ? `:${oPort}` : ''}`;

    const a = (allowed || '').trim().toLowerCase();
    if (!a) return false;

    if (a === '*') return true;
    if (a === oOrigin) return true;
    if (a === oHost || a === `${oHost}:${oPort}`) return true;

    if (/^https?:\/\//.test(a)) {
      const au = new URL(a);
      const aHost = au.hostname.toLowerCase();
      const aPort = (au.port || '').toLowerCase();
      const aProto = au.protocol.toLowerCase();
      if (aHost === oHost && aProto === oProto) {
        if (aPort && aPort !== oPort) return false;
        return true;
      }
    }

    if (a.startsWith('*.')) {
      const suffix = a.slice(1);
      if (oHost.endsWith(suffix)) return true;
    }

    return false;
  } catch (_) {
    return false;
  }
}

function isAllowedOrigin(origin) {
  if (!origin) return true; // same-origin/non-CORS
  if (origin === 'null') return true; // file://, sandboxed etc.

  if (allowedList.length > 0) {
    return allowedList.some((a) => matchesAllowed(origin, a));
  }

  try {
    const u = new URL(origin);
    const expoPorts = new Set(['19000', '19001', '19002', '19006']);
    const isLocalHost = (hn) =>
      hn === 'localhost' || hn === '127.0.0.1' ||
      /^192\.(168|0)\./.test(hn) || /^10\./.test(hn);

    if (isLocalHost(u.hostname) && (expoPorts.has(u.port) || u.port === '3000' || u.port === '5173')) {
      return true;
    }
  } catch (_) {}

  if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\\d+)?$/.test(origin)) return true;
  return false;
}

const corsOptions = {
  origin: (origin, cb) => {
    if (isAllowedOrigin(origin)) return cb(null, true);
    return cb(null, false);
  },
  methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  credentials: false,
  optionsSuccessStatus: 204,
  maxAge: 86400,
};

// Security middleware
app.set('trust proxy', 1);
app.use(securityHeaders);

// Core middleware
app.use(cors(corsOptions));
app.use((req, res, next) => {
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(sanitizeInput);
app.use(morgan('dev'));

// Static admin client
app.use('/admin', express.static('public/admin'));

// Health check endpoints (no CORS restrictions)
app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));
app.get('/ready', (req, res) => {
  const ready = mongoose.connection.readyState === 1;
  res.status(ready ? 200 : 503).json({
    ready,
    dbState: mongoose.connection.readyState,
    timestamp: new Date().toISOString(),
  });
});

// MongoDB connection with retry
async function connectWithRetry(retries = 0) {
  try {
    await mongoose.connect(MONGO_URI, {
    serverSelectionTimeoutMS: MONGO_TIMEOUT_MS,
    connectTimeoutMS: MONGO_TIMEOUT_MS,
    socketTimeoutMS: 20000,
  });

    console.log(`MongoDB connected: ${DB_NAME}`);
  } catch (error) {
    console.error(`MongoDB connection error (attempt ${retries + 1}):`, error.message);
    if (retries < MAX_RETRIES) {
      console.log(`Retrying MongoDB connection in ${RETRY_DELAY}ms...`);
      setTimeout(() => connectWithRetry(retries + 1), RETRY_DELAY);
    } else {
      console.error('Max retries reached for MongoDB connection. Exiting...');
      process.exit(1);
    }
  }
}

// JWT token signing
function signToken(user) {
  return jwt.sign({ id: user._id.toString(), role: user.role }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  });
}

// Routes
app.get('/', (req, res) => res.redirect('/admin/login'));
app.get('/favicon.ico', (req, res) =>
  res.status(204).set('Cache-Control', 'public, max-age=86400').end()
);

// Mount routers
app.use('/api/auth', authRoutes);
app.use('/api/admin/auth', adminAuthRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/users', userRoutes);
app.use('/api/rewards', rewardRoutes);

// Serve Admin UI static files
app.use('/admin', express.static(path.join(__dirname, 'public', 'admin')));
app.use('/api/rewards', rewardRoutes);

// Error handling middleware
app.use(errorHandler);

// Start the server
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// Graceful shutdown
function gracefulShutdown(signal) {
  console.log(`${signal} received: starting graceful shutdown`);
  server.close(() => {
    console.log('HTTP server closed');
    mongoose.connection
      .close(false)
      .then(() => {
        console.log('MongoDB connection closed');
        process.exit(0);
      })
      .catch((err) => {
        console.error('Error closing MongoDB connection:', err?.message || err);
        process.exit(0);
      });
  });

  setTimeout(() => {
    console.warn('Forcing shutdown after timeout');
    process.exit(0);
  }, 10000).unref();
}

// Initialize services - MongoDB only
connectWithRetry();

// Handle process events
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});