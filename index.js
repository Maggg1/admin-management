require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const morgan = require('morgan');
const { body, param, query, validationResult } = require('express-validator');

// App setup
const app = express();

// Early health/readiness endpoints (no CORS restrictions)
app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));
app.get('/ready', (req, res) => {
  const ready = mongoose.connection.readyState === 1; // 1 = connected
  res.status(ready ? 200 : 503).json({ ready, dbState: mongoose.connection.readyState, timestamp: new Date().toISOString() });
});

// CORS configuration to support Expo and configurable origins
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

    // Wildcard all
    if (a === '*') return true;

    // Exact full origin
    if (a === oOrigin) return true;

    // Host only or host:port
    if (a === oHost || a === `${oHost}:${oPort}`) return true;

    // Protocol+host(+optional :port)
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

    // Wildcard subdomain like *.example.com
    if (a.startsWith('*.')) {
      const suffix = a.slice(1); // keep leading dot
      if (oHost.endsWith(suffix)) return true;
    }

    return false;
  } catch (_) {
    return false;
  }
}

function isAllowedOrigin(origin) {
  // Allow non-browser clients (e.g., React Native on device often sends no Origin)
  if (!origin) return true;
  // Some environments send literal "null" as origin (e.g., file:// contexts)
  if (origin === 'null') return true;
  // If ALLOWED_ORIGINS is set, use it strictly with flexible matching
  if (allowedList.length > 0) return allowedList.some((a) => matchesAllowed(origin, a));
  // Default permissive dev behavior: allow common Expo/local dev origins
  try {
    const u = new URL(origin);
    const expoPorts = new Set(['19000', '19001', '19002', '19006']);
    const isLocalHost = (hn) => hn === 'localhost' || hn === '127.0.0.1' || /^192\.(168|0)\./.test(hn) || /^10\./.test(hn);
    if (isLocalHost(u.hostname) && (expoPorts.has(u.port) || u.port === '3000' || u.port === '5173')) return true; // include CRA/Vite ports too
  } catch (_) {}
  // Also allow generic localhost without explicit port
  if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return true;
  return false;
}
const corsOptions = {
  origin: (origin, cb) => {
    if (isAllowedOrigin(origin)) return cb(null, true);
    // Deny without throwing to avoid 500s; browser will block due to missing CORS headers
    return cb(null, false);
  },
  methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  credentials: false,
  optionsSuccessStatus: 204,
  maxAge: 86400,
};
app.use(cors(corsOptions));
// Avoid Express 5 path-to-regexp wildcard issues: handle preflight without a path pattern
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

// Config
const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://root:local12345@cluster0.9wlemv7.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const DB_NAME = process.env.DB_NAME || 'admin_backend';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

// Firebase Admin initialization (optional)
const FIREBASE_CREDENTIALS_FILE = process.env.FIREBASE_CREDENTIALS_FILE;
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID;
const FIREBASE_CLIENT_EMAIL = process.env.FIREBASE_CLIENT_EMAIL;
let FIREBASE_PRIVATE_KEY = process.env.FIREBASE_PRIVATE_KEY;
if (FIREBASE_PRIVATE_KEY && FIREBASE_PRIVATE_KEY.includes('\\n')) {
  FIREBASE_PRIVATE_KEY = FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n');
}
let firebaseReady = false;
try {
  if (!admin.apps.length && FIREBASE_CREDENTIALS_FILE) {
    const credPath = path.isAbsolute(FIREBASE_CREDENTIALS_FILE)
      ? FIREBASE_CREDENTIALS_FILE
      : path.join(process.cwd(), FIREBASE_CREDENTIALS_FILE);
    let raw = fs.readFileSync(credPath, 'utf8');
    // Remove code fences if present
    raw = raw.split(/\r?\n/).filter((line) => !line.trim().startsWith('```')).join('\n');
    const serviceAccount = JSON.parse(raw);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    firebaseReady = true;
    console.log('Firebase Admin initialized from file');
  } else if (!admin.apps.length && FIREBASE_PROJECT_ID && FIREBASE_CLIENT_EMAIL && FIREBASE_PRIVATE_KEY) {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: FIREBASE_PROJECT_ID,
        clientEmail: FIREBASE_CLIENT_EMAIL,
        privateKey: FIREBASE_PRIVATE_KEY,
      }),
    });
    firebaseReady = true;
    console.log('Firebase Admin initialized from env');
  }
} catch (e) {
  console.error('Firebase init error:', e && e.message ? e.message : e);
}

// Connect to MongoDB
// Robust connection with retry to prevent container from exiting on boot
const MONGO_TIMEOUT_MS = Number(process.env.MONGO_TIMEOUT_MS || 8000);
async function connectWithRetry() {
  try {
    await mongoose.connect(MONGO_URI, {
      dbName: DB_NAME,
      serverSelectionTimeoutMS: MONGO_TIMEOUT_MS,
      connectTimeoutMS: MONGO_TIMEOUT_MS,
      socketTimeoutMS: 20000,
    });
    console.log(`MongoDB connected: ${DB_NAME}`);
  } catch (err) {
    console.error('MongoDB connection error:', err.message);
    // Retry after short delay instead of exiting, so container stays up
    setTimeout(connectWithRetry, 5000);
  }
}
connectWithRetry();

// User model
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true, minlength: 6, select: false },
    role: { type: String, enum: ['admin', 'user'], default: 'user', index: true },
    active: { type: Boolean, default: true },
    emailVerified: { type: Boolean, default: false },
    emailVerificationToken: { type: String, select: false },
    emailVerificationExpires: { type: Date, select: false },
  },
  { timestamps: true }
);

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

userSchema.methods.comparePassword = async function (candidate) {
  return bcrypt.compare(candidate, this.password);
};


const User = mongoose.model('User', userSchema);

// Activity model (user activity / "shakes")
const activitySchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    type: { type: String, required: true, trim: true },
    details: { type: mongoose.Schema.Types.Mixed },
  },
  { timestamps: true }
);
activitySchema.index({ createdAt: -1 });
const Activity = mongoose.model('Activity', activitySchema);

// Feedback model
const feedbackSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    message: { type: String, required: true, trim: true },
    rating: { type: Number, min: 1, max: 5 },
  },
  { timestamps: true }
);
feedbackSchema.index({ createdAt: -1 });
const Feedback = mongoose.model('Feedback', feedbackSchema);

// Helpers
function signToken(user) {
  return jwt.sign({ id: user._id.toString(), role: user.role }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  });
}

function handleValidation(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
}

// Auth middleware
async function authenticate(req, res, next) {
  const auth = req.headers.authorization || '';
  const [scheme, token] = auth.split(' ');
  if (scheme !== 'Bearer' || !token) return res.status(401).json({ message: 'Unauthorized' });

  // 1) Try local JWT first
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).lean();
    if (user && user.active) {
      req.user = { id: user._id.toString(), role: user.role };
      return next();
    }
  } catch (_) {
    // fallthrough to Firebase
  }

  // 2) Try Firebase ID token
  try {
    if (!firebaseReady) throw new Error('Firebase not configured');
    const fb = await admin.auth().verifyIdToken(token);
    const email = (fb.email || '').toLowerCase();
    if (!email) return res.status(401).json({ message: 'Unauthorized' });

    let user = await User.findOne({ email }).lean();
    if (!user) {
      // Upsert user based on Firebase identity
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
  if (req.user?.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
  return next();
}

// Healthcheck
app.get('/favicon.ico', (req, res) => res.status(204).set('Cache-Control', 'public, max-age=86400').end());
app.get('/', (req, res) => res.redirect('/admin/login'));

// Auth routes
app.post(
  '/api/auth/register-admin',
  [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
    body('password').isLength({ min: 6 }).withMessage('Password min length 6'),
  ],
  handleValidation,
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
      const safeUser = { id: user._id, name: user.name, email: user.email, role: user.role, active: user.active };
      return res.status(201).json({ token, user: safeUser });
    } catch (err) {
      if (err && err.code === 11000) {
        return res.status(409).json({ message: 'Email already in use' });
      }
      console.error('register-admin error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

app.post(
  '/api/auth/login',
  [body('email').isEmail().withMessage('Valid email required'), body('password').notEmpty().withMessage('Password required')],
  handleValidation,
  async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email }).select('+password');
      if (!user) return res.status(400).json({ message: 'Invalid credentials' });
      if (!user.active) return res.status(403).json({ message: 'User is disabled' });

      const match = await user.comparePassword(password);
      if (!match) return res.status(400).json({ message: 'Invalid credentials' });
      if (user.role !== 'admin' && !user.emailVerified) return res.status(403).json({ message: 'Email not verified' });

      const token = signToken(user);
      const safeUser = { id: user._id, name: user.name, email: user.email, role: user.role, active: user.active };
      return res.json({ token, user: safeUser });
    } catch (err) {
      console.error('login error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// Current user info (no admin role required)
app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password').lean();
    if (!user) return res.status(404).json({ message: 'User not found' });
    return res.json({ id: user._id, name: user.name, email: user.email, role: user.role, active: user.active });
  } catch (err) {
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// Email verification (local auth)
app.get('/api/auth/verify-email', async (req, res) => {
  try {
    const token = (req.query.token || '').toString();
    if (!token) return res.status(400).json({ message: 'Token is required' });
    const hashed = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({
      emailVerificationToken: hashed,
      emailVerificationExpires: { $gt: new Date() },
    });
    if (!user) return res.status(400).json({ message: 'Invalid or expired token' });

    user.emailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();

    return res.json({ message: 'Email verified successfully' });
  } catch (err) {
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// User activity routes (non-admin)
app.post('/api/activity/login', authenticate, async (req, res) => {
  try {
    await Activity.create({ user: req.user.id, type: 'login', details: req.body || {} });
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ message: 'Internal server error' });
  }
});

app.post(
  '/api/activity',
  authenticate,
  [body('type').trim().notEmpty().withMessage('type is required')],
  handleValidation,
  async (req, res) => {
    try {
      const { type, details } = req.body;
      const doc = await Activity.create({ user: req.user.id, type, details });
      return res.status(201).json({ id: doc._id, type: doc.type, details: doc.details, createdAt: doc.createdAt });
    } catch (err) {
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

app.get(
  '/api/activity',
  authenticate,
  [
    query('page').optional().isInt({ min: 1 }).toInt(),
    query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
    query('type').optional().isString().trim(),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const page = req.query.page || 1;
      const limit = req.query.limit || 10;
      const type = req.query.type || '';
      const filter = { user: req.user.id };
      if (type) filter.type = type;
      const total = await Activity.countDocuments(filter);
      const data = await Activity.find(filter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean();
      return res.json({ data, page, limit, total, totalPages: Math.ceil(total / limit) });
    } catch (err) {
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// Compatibility aliases for some frontend paths
app.post(
  '/admin/users/login',
  [body('password').notEmpty().withMessage('Password required')],
  handleValidation,
  async (req, res) => {
    try {
      const emailRaw = (req.body.email || req.body.username || '').toString().trim().toLowerCase();
      const password = req.body.password;
      if (!emailRaw) return res.status(400).json({ message: 'Email required' });
      const user = await User.findOne({ email: emailRaw }).select('+password');
      if (!user) return res.status(400).json({ message: 'Invalid credentials' });
      if (!user.active) return res.status(403).json({ message: 'User is disabled' });

      const match = await user.comparePassword(password);
      if (!match) return res.status(400).json({ message: 'Invalid credentials' });
      if (user.role !== 'admin' && !user.emailVerified) return res.status(403).json({ message: 'Email not verified' });

      const token = signToken(user);
      const safeUser = { id: user._id, name: user.name, email: user.email, role: user.role, active: user.active };
      return res.json({ token, user: safeUser });
    } catch (err) {
      console.error('login error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

app.post(
  '/admin/users/register',
  [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
    body('password').isLength({ min: 6 }).withMessage('Password min length 6'),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { name, email, password } = req.body;
      const user = new User({ name, email, password, role: 'user', emailVerified: false });
      const rawToken = crypto.randomBytes(32).toString('hex');
      const hashed = crypto.createHash('sha256').update(rawToken).digest('hex');
      user.emailVerificationToken = hashed;
      user.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h
      await user.save();

      const baseUrl = process.env.PUBLIC_BASE_URL || process.env.BASE_URL || `http://localhost:${PORT}`;
      const verificationUrl = `${baseUrl}/admin/verify-email.html?token=${rawToken}`;
      console.log('Email verification link:', verificationUrl);

      return res.status(201).json({
        message: 'Registration successful. Please verify your email using the link sent to your email.',
        verificationUrl,
      });
    } catch (err) {
      if (err && err.code === 11000) {
        return res.status(409).json({ message: 'Email already in use' });
      }
      console.error('register user error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

app.get('/admin/users/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password').lean();
    if (!user) return res.status(404).json({ message: 'User not found' });
    return res.json({ id: user._id, name: user.name, email: user.email, role: user.role, active: user.active });
  } catch (err) {
    return res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/admin/activities', authenticate, async (req, res) => {
  try {
    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 10;
    const type = (req.query.type || '').toString();
    const filter = { user: req.user.id };
    if (type) filter.type = type;
    const total = await Activity.countDocuments(filter);
    const data = await Activity.find(filter)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();
    return res.json({ data, page, limit, total, totalPages: Math.ceil(total / limit) });
  } catch (err) {
    return res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/admin/activities', authenticate, async (req, res) => {
  try {
    const type = (req.body && req.body.type) || 'login';
    const details = (req.body && req.body.details) || req.body || {};
    const doc = await Activity.create({ user: req.user.id, type, details });
    return res.status(201).json({ id: doc._id, type: doc.type, details: doc.details, createdAt: doc.createdAt });
  } catch (err) {
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// Admin routes
const adminRouter = express.Router();

// Normalize ':id' param from query/body if path param is missing or 'undefined'/'null'
adminRouter.use((req, res, next) => {
  if (req.params && Object.prototype.hasOwnProperty.call(req.params, 'id')) {
    const pid = req.params.id;
    if (!pid || pid === 'undefined' || pid === 'null') {
      const fallback = req.query.id || (req.body && req.body.id);
      if (fallback) req.params.id = fallback;
    }
  }
  next();
});

adminRouter.get(
  '/users',
  [
    query('page').optional().isInt({ min: 1 }).toInt(),
    query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
    query('search').optional().isString().trim(),
    query('sort').optional().isIn(['createdAt', 'name', 'email', 'role']).withMessage('Invalid sort field'),
    query('order').optional().isIn(['asc', 'desc']).withMessage('Invalid order'),
    query('role').optional().isIn(['admin', 'user']).withMessage('Invalid role'),
    query('active').optional().isBoolean().toBoolean().withMessage('Active must be boolean'),
    query('createdFrom').optional().isISO8601().toDate().withMessage('createdFrom must be ISO date'),
    query('createdTo').optional().isISO8601().toDate().withMessage('createdTo must be ISO date'),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const page = req.query.page || 1;
      const limit = req.query.limit || 10;
      const search = req.query.search || '';
      const sortField = req.query.sort || 'createdAt';
      const sortOrder = req.query.order === 'asc' ? 1 : -1;
      const role = req.query.role;
      const active = typeof req.query.active !== 'undefined' ? req.query.active : undefined;
      const createdFrom = req.query.createdFrom;
      const createdTo = req.query.createdTo;

      const filter = {};
      if (search) {
        filter.$or = [
          { name: { $regex: search, $options: 'i' } },
          { email: { $regex: search, $options: 'i' } },
        ];
      }
      if (role) filter.role = role;
      if (typeof active !== 'undefined') filter.active = active;
      if (createdFrom || createdTo) {
        filter.createdAt = {};
        if (createdFrom) filter.createdAt.$gte = new Date(createdFrom);
        if (createdTo) filter.createdAt.$lte = new Date(createdTo);
      }

      const total = await User.countDocuments(filter);
      const data = await User.find(filter)
        .sort({ [sortField]: sortOrder })
        .skip((page - 1) * limit)
        .limit(limit)
        .select('-password')
        .lean();

      return res.json({ data, page, limit, total, totalPages: Math.ceil(total / limit) });
    } catch (err) {
      console.error('list users error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

adminRouter.post(
  '/users',
  [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email is required').normalizeEmail(),
    body('password').isLength({ min: 6 }).withMessage('Password min length 6'),
    body('role').optional().isIn(['admin', 'user']).withMessage('Invalid role'),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const { name, email, password, role = 'user' } = req.body;
      const user = new User({ name, email, password, role });
      await user.save();
      const safeUser = { id: user._id, name: user.name, email: user.email, role: user.role, active: user.active };
      return res.status(201).json(safeUser);
    } catch (err) {
      if (err && err.code === 11000) {
        return res.status(409).json({ message: 'Email already in use' });
      }
      console.error('create user error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

adminRouter.get(
  '/users/:id',
  [param('id').custom((v) => mongoose.Types.ObjectId.isValid(v)).withMessage('Invalid ID')],
  handleValidation,
  async (req, res) => {
    try {
      const user = await User.findById(req.params.id).select('-password').lean();
      if (!user) return res.status(404).json({ message: 'User not found' });
      return res.json(user);
    } catch (err) {
      console.error('get user error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

adminRouter.patch(
  '/users/:id',
  [
    param('id').custom((v) => mongoose.Types.ObjectId.isValid(v)).withMessage('Invalid ID'),
    body('email').optional().isEmail().withMessage('Valid email required').normalizeEmail(),
    body('name').optional().isString().trim(),
    body('password').optional().isLength({ min: 6 }).withMessage('Password min length 6'),
    body('role').optional().isIn(['admin', 'user']).withMessage('Invalid role'),
    body('active').optional().isBoolean().withMessage('Active must be boolean'),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const user = await User.findById(req.params.id).select('+password');
      if (!user) return res.status(404).json({ message: 'User not found' });

      const updatable = ['name', 'email', 'role', 'active'];
      for (const key of updatable) {
        if (typeof req.body[key] !== 'undefined') user[key] = req.body[key];
      }
      if (typeof req.body.password !== 'undefined' && req.body.password) {
        user.password = req.body.password; // will hash via pre-save
      }

      await user.save();
      const safeUser = { id: user._id, name: user.name, email: user.email, role: user.role, active: user.active };
      return res.json(safeUser);
    } catch (err) {
      if (err && err.code === 11000) {
        return res.status(409).json({ message: 'Email already in use' });
      }
      console.error('update user error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

adminRouter.delete(
  '/users/:id',
  [param('id').custom((v) => mongoose.Types.ObjectId.isValid(v)).withMessage('Invalid ID')],
  handleValidation,
  async (req, res) => {
    try {
      const toDelete = await User.findById(req.params.id);
      if (!toDelete) return res.status(404).json({ message: 'User not found' });

      // Prevent deleting the last admin
      if (toDelete.role === 'admin') {
        const adminCount = await User.countDocuments({ role: 'admin' });
        if (adminCount <= 1) {
          return res.status(400).json({ message: 'Cannot delete the last admin user' });
        }
      }

      await toDelete.deleteOne();
      return res.json({ success: true });
    } catch (err) {
      console.error('delete user error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// Admin: activities (shakes) list
adminRouter.get(
  '/shakes',
  [
    query('page').optional().isInt({ min: 1 }).toInt(),
    query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
    query('search').optional().isString().trim(),
    query('createdFrom').optional().isISO8601().toDate(),
    query('createdTo').optional().isISO8601().toDate(),
    query('type').optional().isString().trim(),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const page = req.query.page || 1;
      const limit = req.query.limit || 20;
      const search = req.query.search || '';
      const type = req.query.type || '';
      const createdFrom = req.query.createdFrom;
      const createdTo = req.query.createdTo;

      const filter = {};
      if (type) filter.type = type;
      if (createdFrom || createdTo) {
        filter.createdAt = {};
        if (createdFrom) filter.createdAt.$gte = new Date(createdFrom);
        if (createdTo) filter.createdAt.$lte = new Date(createdTo);
      }
      // Basic text search on type or common string subfields within details.
      // Avoid applying $regex directly to Mixed/object fields to prevent Mongo errors.
      if (search) {
        filter.$or = [
          { type: { $regex: search, $options: 'i' } },
          { 'details.message': { $regex: search, $options: 'i' } },
          { 'details.text': { $regex: search, $options: 'i' } },
          { 'details.description': { $regex: search, $options: 'i' } },
        ];
      }

      const total = await Activity.countDocuments(filter);
      const data = await Activity.find(filter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .populate('user', 'name email role')
        .lean();

      return res.json({ data, page, limit, total, totalPages: Math.ceil(total / limit) });
    } catch (err) {
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// Admin: feedback list
adminRouter.get(
  '/feedback',
  [
    query('page').optional().isInt({ min: 1 }).toInt(),
    query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
    query('search').optional().isString().trim(),
  ],
  handleValidation,
  async (req, res) => {
    try {
      const page = req.query.page || 1;
      const limit = req.query.limit || 50;
      const search = req.query.search || '';
      const filter = {};
      if (search) filter.message = { $regex: search, $options: 'i' };
      const total = await Feedback.countDocuments(filter);
      const data = await Feedback.find(filter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .populate('user', 'name email role')
        .lean();
      return res.json({ data, page, limit, total, totalPages: Math.ceil(total / limit) });
    } catch (err) {
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// Admin delete endpoints for activities (shakes) and feedback
adminRouter.delete(
  '/shakes/:id',
  [param('id').custom((v) => mongoose.Types.ObjectId.isValid(v)).withMessage('Invalid ID')],
  handleValidation,
  async (req, res) => {
    try {
      const doc = await Activity.findByIdAndDelete(req.params.id);
      if (!doc) return res.status(404).json({ message: 'Activity not found' });
      return res.json({ success: true });
    } catch (err) {
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

adminRouter.delete(
  '/feedback/:id',
  [param('id').custom((v) => mongoose.Types.ObjectId.isValid(v)).withMessage('Invalid ID')],
  handleValidation,
  async (req, res) => {
    try {
      const doc = await Feedback.findByIdAndDelete(req.params.id);
      if (!doc) return res.status(404).json({ message: 'Feedback not found' });
      return res.json({ success: true });
    } catch (err) {
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// Alternative DELETE endpoints accepting id via query or body for compatibility
adminRouter.delete('/users', async (req, res) => {
  try {
    const id = req.query.id || (req.body && req.body.id);
    if (!id || !mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: 'Invalid or missing id' });
    }
    const toDelete = await User.findById(id);
    if (!toDelete) return res.status(404).json({ message: 'User not found' });

    if (toDelete.role === 'admin') {
      const adminCount = await User.countDocuments({ role: 'admin' });
      if (adminCount <= 1) {
        return res.status(400).json({ message: 'Cannot delete the last admin user' });
      }
    }

    await toDelete.deleteOne();
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ message: 'Internal server error' });
  }
});

adminRouter.delete('/shakes', async (req, res) => {
  try {
    const id = req.query.id || (req.body && req.body.id);
    if (!id || !mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: 'Invalid or missing id' });
    }
    const doc = await Activity.findByIdAndDelete(id);
    if (!doc) return res.status(404).json({ message: 'Activity not found' });
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ message: 'Internal server error' });
  }
});

adminRouter.delete('/feedback', async (req, res) => {
  try {
    const id = req.query.id || (req.body && req.body.id);
    if (!id || !mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: 'Invalid or missing id' });
    }
    const doc = await Feedback.findByIdAndDelete(id);
    if (!doc) return res.status(404).json({ message: 'Feedback not found' });
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// Mount admin router under both /api/admin and /admin for compatibility
app.use('/api/admin', authenticate, isAdmin, adminRouter);
app.use('/admin', authenticate, isAdmin, adminRouter);

// Global error handler (fallback)
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Internal server error' });
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
});

// Optional: tune timeouts for proxies/load balancers
try {
  server.keepAliveTimeout = 65000; // 65s
  server.headersTimeout = 66000;   // 66s
} catch (_) {}

function gracefulShutdown(signal) {
  console.log(`${signal} received: starting graceful shutdown`);
  // Stop accepting new connections
  server.close(() => {
    console.log('HTTP server closed');
    // Close mongoose connection
    mongoose.connection.close(false).then(() => {
      console.log('MongoDB connection closed');
      process.exit(0);
    }).catch((err) => {
      console.error('Error closing MongoDB connection:', err && err.message ? err.message : err);
      process.exit(0);
    });
  });

  // Force exit if not closed in time
  setTimeout(() => {
    console.warn('Forcing shutdown after timeout');
    process.exit(0);
  }, 10000).unref();
}

// Handle termination signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Log unexpected errors
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});
