require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');
const admin = require('firebase-admin');
const crypto = require('crypto');

// Import routes
const adminRoutes = require('./routes/admin');

// Import models
const User = require('./models/User');

// App setup
const app = express();

// Configuration
const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://root:local12345@cluster0.9wlemv7.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const DB_NAME = process.env.DB_NAME || 'admin_backend';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

// Retry configuration
const MAX_RETRIES = 5;
const RETRY_DELAY = 5000; // 5 seconds
const MONGO_TIMEOUT_MS = Number(process.env.MONGO_TIMEOUT_MS || 8000);

// CORS configuration
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
  if (!origin) return true;
  if (origin === 'null') return true;
  
  if (allowedList.length > 0) {
    return allowedList.some((a) => matchesAllowed(origin, a));
  }

  try {
    const u = new URL(origin);
    const expoPorts = new Set(['19000', '19001', '19002', '19006']);
    const isLocalHost = (hn) => 
      hn === 'localhost' || hn === '127.0.0.1' || 
      /^192\.(168|0)\./.test(hn) || /^10\./.test(hn);
    
    if (isLocalHost(u.hostname) && 
        (expoPorts.has(u.port) || u.port === '3000' || u.port === '5173')) {
      return true;
    }
  } catch (_) {}
  
  if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return true;
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

// Middleware setup
app.use(cors(corsOptions));
app.use((req, res, next) => {
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));
app.use('/admin', express.static('public/admin'));

// Health check endpoints (no CORS restrictions)
app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));
app.get('/ready', (req, res) => {
  const ready = mongoose.connection.readyState === 1;
  res.status(ready ? 200 : 503).json({ 
    ready, 
    dbState: mongoose.connection.readyState, 
    timestamp: new Date().toISOString() 
  });
});

// Firebase Admin initialization with retry
let firebaseReady = false;
async function initializeFirebase(retries = 0) {
  try {
    if (admin.apps.length > 0) {
      firebaseReady = true;
      return;
    }

    const FIREBASE_CREDENTIALS_FILE = process.env.FIREBASE_CREDENTIALS_FILE;
    const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID;
    const FIREBASE_CLIENT_EMAIL = process.env.FIREBASE_CLIENT_EMAIL;
    let FIREBASE_PRIVATE_KEY = process.env.FIREBASE_PRIVATE_KEY;

    if (FIREBASE_PRIVATE_KEY && FIREBASE_PRIVATE_KEY.includes('\\n')) {
      FIREBASE_PRIVATE_KEY = FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');
    }

    if (FIREBASE_CREDENTIALS_FILE) {
      const credPath = path.isAbsolute(FIREBASE_CREDENTIALS_FILE)
        ? FIREBASE_CREDENTIALS_FILE
        : path.join(process.cwd(), FIREBASE_CREDENTIALS_FILE);
      const raw = fs.readFileSync(credPath, 'utf8')
        .split(/\r?\n/)
        .filter((line) => !line.trim().startsWith('```'))
        .join('\n');
      const serviceAccount = JSON.parse(raw);
      admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
      console.log('Firebase Admin initialized from file');
    } else if (FIREBASE_PROJECT_ID && FIREBASE_CLIENT_EMAIL && FIREBASE_PRIVATE_KEY) {
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId: FIREBASE_PROJECT_ID,
          clientEmail: FIREBASE_CLIENT_EMAIL,
          privateKey: FIREBASE_PRIVATE_KEY,
        }),
      });
      console.log('Firebase Admin initialized from env');
    }

    firebaseReady = admin.apps.length > 0;
    if (!firebaseReady) {
      console.warn('Firebase Admin not configured; proceeding without Firebase auth');
    }
  } catch (error) {
    console.error(`Firebase initialization error (attempt ${retries + 1}):`, error.message);
    if (retries < MAX_RETRIES) {
      console.log(`Retrying Firebase initialization in ${RETRY_DELAY}ms...`);
      setTimeout(() => initializeFirebase(retries + 1), RETRY_DELAY);
    } else {
      console.error('Max retries reached for Firebase initialization. Continuing without Firebase.');
    }
  }
}

// MongoDB connection with retry
async function connectWithRetry(retries = 0) {
  try {
    await mongoose.connect(MONGO_URI, {
      dbName: DB_NAME,
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
  const jwt = require('jsonwebtoken');
  return jwt.sign({ id: user._id.toString(), role: user.role }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  });
}

// Auth middleware
async function authenticate(req, res, next) {
  const jwt = require('jsonwebtoken');
  const auth = req.headers.authorization || '';
  const [scheme, token] = auth.split(' ');
  
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).lean();
    if (user && user.active) {
      req.user = { id: user._id.toString(), role: user.role };
      return next();
    }
  } catch (_) {
    // Fall through to Firebase
  }

  try {
    if (!firebaseReady || admin.apps.length === 0) throw new Error('Firebase not configured');
    const fb = await admin.auth().verifyIdToken(token);
    const email = (fb.email || '').toLowerCase();
    if (!email) return res.status(401).json({ message: 'Unauthorized' });

    let user = await User.findOne({ email }).lean();
    if (!user) {
      const name = fb.name || email.split('@')[0] || 'firebase_user';
      const password = crypto.randomBytes(16).toString('hex');
      const created = new User({ name, email, password, role: 'user', active: true });
      await created.save();
      user = created.toObject();
    }
    if (!user.active) return res.status(403).json({ message: 'User is disabled' });

    req.user = { id: user._id.toString(), role: user.role };
    return next();
  } catch (err) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
}

function isAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ message: 'Forbidden' });
  }
  return next();
}

// Routes
app.get('/', (req, res) => res.redirect('/admin/login'));
app.get('/favicon.ico', (req, res) => 
  res.status(204).set('Cache-Control', 'public, max-age=86400').end()
);

// Auth routes
app.post(
  '/api/auth/register-admin',
  [
    require('express-validator').body('name').trim().notEmpty().withMessage('Name is required'),
    require('express-validator').body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
    require('express-validator').body('password').isLength({ min: 6 }).withMessage('Password min length 6'),
  ],
  require('./utils/validation'),
  async (req, res) => {
    try {
      const adminCount = await User.countDocuments({ role: 'admin' });
      if (adminCount > 0) {
        return res.status(403).json({
          message: 'Admin already exists. Login as admin and use admin user creation endpoint to add more admins.',
        });
      }

      const { name, email, password } = req.body;
      const user = new User({ name, email, password, role: 'admin', emailVerified: true });
      await user.save();

      const token = signToken(user);
      const safeUser = { 
        id: user._id, 
        name: user.name, 
        email: user.email, 
        role: user.role, 
        active: user.active 
      };
      return res.status(201).json({ token, user: safeUser });
    } catch (err) {
      if (err?.code === 11000) {
        return res.status(409).json({ message: 'Email already in use' });
      }
      console.error('register-admin error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// User registration endpoint for React Expo app
app.post(
  '/api/auth/register',
  [
    require('express-validator').body('name').trim().notEmpty().withMessage('Name is required'),
    require('express-validator').body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
    require('express-validator').body('password').isLength({ min: 6 }).withMessage('Password min length 6'),
  ],
  require('./utils/validation'),
  async (req, res) => {
    try {
      const { name, email, password } = req.body;
      const user = new User({ name, email, password, role: 'user', active: true });
      await user.save();

      const token = signToken(user);
      const safeUser = { 
        id: user._id, 
        name: user.name, 
        email: user.email, 
        role: user.role, 
        active: user.active 
      };
      return res.status(201).json({ token, user: safeUser });
    } catch (err) {
      if (err?.code === 11000) {
        return res.status(409).json({ message: 'Email already in use' });
      }
      console.error('register error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

app.post(
  '/api/auth/login',
  [
    require('express-validator').body('email').isEmail().withMessage('Valid email required'),
    require('express-validator').body('password').notEmpty().withMessage('Password required')
  ],
  require('./utils/validation'),
  async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email }).select('+password');
      if (!user) return res.status(400).json({ message: 'Invalid credentials' });
      if (!user.active) return res.status(403).json({ message: 'User is disabled' });

      const match = await user.comparePassword(password);
      if (!match) return res.status(400).json({ message: 'Invalid credentials' });
      if (user.role !== 'admin' && typeof user.emailVerified === 'boolean' && !user.emailVerified) {
        return res.status(403).json({ message: 'Email not verified' });
      }

      const token = signToken(user);
      const safeUser = { 
        id: user._id, 
        name: user.name, 
        email: user.email, 
        role: user.role, 
        active: user.active 
      };
      return res.json({ token, user: safeUser });
    } catch (err) {
      console.error('login error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password').lean();
    if (!user) return res.status(404).json({ message: 'User not found' });
    return res.json({ 
      id: user._id, 
      name: user.name, 
      email: user.email, 
      role: user.role, 
      active: user.active 
    });
  } catch (err) {
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// Mount admin routes
app.use('/api/admin', authenticate, isAdmin, adminRoutes);
app.use('/admin', authenticate, isAdmin, adminRoutes);

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Internal server error' });
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});

// Configure server timeouts
try {
  server.keepAliveTimeout = 65000;
  server.headersTimeout = 66000;
} catch (_) {}

// Graceful shutdown
function gracefulShutdown(signal) {
  console.log(`${signal} received: starting graceful shutdown`);
  server.close(() => {
    console.log('HTTP server closed');
    mongoose.connection.close(false).then(() => {
      console.log('MongoDB connection closed');
      process.exit(0);
    }).catch((err) => {
      console.error('Error closing MongoDB connection:', err?.message || err);
      process.exit(0);
    });
  });

  setTimeout(() => {
    console.warn('Forcing shutdown after timeout');
    process.exit(0);
  }, 10000).unref();
}

// Initialize services
connectWithRetry();
initializeFirebase();

// Handle process events
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});
