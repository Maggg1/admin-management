require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const morgan = require('morgan');
const { body, param, query, validationResult } = require('express-validator');

// App setup
const app = express();

// Early health/readiness endpoints (no CORS restrictions)

// CORS configuration to support Expo and configurable origins
const allowedOriginsEnv = process.env.ALLOWED_ORIGINS || '';
const allowedList = allowedOriginsEnv.split(',').map((s) => s.trim()).filter(Boolean);
function isAllowedOrigin(origin) {
  // Allow non-browser clients (e.g., React Native on device often sends no Origin)
  if (!origin) return true;
  // Some environments send literal "null" as origin (e.g., file:// contexts)
  if (origin === 'null') return true;
  // If ALLOWED_ORIGINS is set, use it strictly
  if (allowedList.length > 0) return allowedList.includes(origin);
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
    return cb(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  credentials: false,
  optionsSuccessStatus: 204,
  maxAge: 86400,
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json({ limit: '5mb' }));
app.use(morgan('dev'));
app.use('/admin', express.static('public/admin'));

// Config
const PORT = process.env.PORT || 4000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://root:local12345@cluster0.9wlemv7.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const DB_NAME = process.env.DB_NAME || 'admin_backend';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

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
  try {
    const auth = req.headers.authorization || '';
    const [scheme, token] = auth.split(' ');
    if (scheme !== 'Bearer' || !token) return res.status(401).json({ message: 'Unauthorized' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).lean();
    if (!user || !user.active) return res.status(401).json({ message: 'Unauthorized' });

    req.user = { id: user._id.toString(), role: user.role };
    next();
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
      const user = new User({ name, email, password, role: 'admin' });
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

      const token = signToken(user);
      const safeUser = { id: user._id, name: user.name, email: user.email, role: user.role, active: user.active };
      return res.json({ token, user: safeUser });
    } catch (err) {
      console.error('login error:', err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  }
);

// Admin routes
const adminRouter = express.Router();

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

app.use('/api/admin', authenticate, isAdmin, adminRouter);

// Global error handler (fallback)
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
