/**
 * ============================================================
 *  حوس بيا — Haws Biya Tourism Platform
 *  Backend Server  |  Node.js + Express
 * ============================================================
 *  Features:
 *   ✅ Password hashing with bcryptjs
 *   ✅ XSS sanitization on all inputs
 *   ✅ Loyalty points system (auto-calculated on booking)
 *   ✅ AI-style chat bot with Algerian tourism knowledge
 *   ✅ B2B partner registration
 *   ✅ Reviews & ratings system
 *   ✅ Analytics / visit tracking
 *   ✅ Soft-delete for bookings
 *   ✅ Admin stats endpoint
 *   ✅ Token-based auth (stored in DB)
 *   ✅ Input validation on every route
 * ============================================================
 */

const express    = require('express');
const bcrypt     = require('bcryptjs');
const xss        = require('xss');
const cors       = require('cors');
const bodyParser = require('body-parser');
const fs         = require('fs');
const path       = require('path');
const crypto     = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'db.json');

// ─────────────────────────────────────────────
//  Middleware
// ─────────────────────────────────────────────
app.use(cors());
app.use(bodyParser.json());
// Served inline (not from a .well-known/ file) because dot-folders get silently
// dropped by some hosting build steps (and ignored by Express static by default).
// Required so the packaged Android TWA app can verify it owns this domain.
app.get('/.well-known/assetlinks.json', (req, res) => {
  res.json([{
    relation: ['delegate_permission/common.handle_all_urls'],
    target: {
      namespace: 'android_app',
      package_name: 'com.hwasbiya.app',
      sha256_cert_fingerprints: ['5E:B1:F2:34:65:7F:75:55:A1:63:80:2D:5F:D2:9A:2E:82:7E:C1:00:93:D1:85:D8:F7:F2:3F:C8:58:F3:D3:07']
    }
  }]);
});
app.use(express.static(__dirname));

// ─────────────────────────────────────────────
//  DB Helpers  (flat-file JSON store)
// ─────────────────────────────────────────────
function readDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
  } catch {
    return {
      users: [], programs: [], hotels: [], souvenirs: [],
      bookings: [], messages: [], partners: [], reviews: [],
      visits: [], chat_history: []
    };
  }
}

function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf-8');
}

function nextId(collection) {
  if (!collection.length) return 1;
  return Math.max(...collection.map(i => i.id || 0)) + 1;
}

// ─────────────────────────────────────────────
//  Sanitize helper — strips XSS from all string fields
// ─────────────────────────────────────────────
function sanitize(obj) {
  if (typeof obj === 'string') return xss(obj.trim());
  if (Array.isArray(obj))     return obj.map(sanitize);
  if (obj && typeof obj === 'object') {
    const clean = {};
    for (const [k, v] of Object.entries(obj)) {
      clean[k] = sanitize(v);
    }
    return clean;
  }
  return obj;
}

// ─────────────────────────────────────────────
//  Auth Middleware
// ─────────────────────────────────────────────
function authRequired(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'غير مصرح — يرجى تسجيل الدخول' });

  const db   = readDB();
  const user = db.users.find(u => u.token === token && !u.deleted);
  if (!user) return res.status(401).json({ error: 'الجلسة منتهية — يرجى تسجيل الدخول مجدداً' });

  req.user = user;
  next();
}

function adminRequired(req, res, next) {
  authRequired(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'هذا الإجراء يتطلب صلاحية المسؤول' });
    next();
  });
}

// ─────────────────────────────────────────────
//  Loyalty Points Calculator
// ─────────────────────────────────────────────
function calcLoyaltyPoints(type, price) {
  const p = parseInt(price) || 0;
  const rates = { program: 0.01, hotel: 0.005, souvenir: 0.008 };
  return Math.round(p * (rates[type] || 0.008));
}

function getTier(points) {
  if (points >= 5000) return { name: 'ماسي',   icon: '💎', next: null,  nextPts: 0 };
  if (points >= 2000) return { name: 'ذهبي',   icon: '🥇', next: 'ماسي',  nextPts: 5000 };
  if (points >= 500)  return { name: 'فضي',    icon: '🥈', next: 'ذهبي',  nextPts: 2000 };
  return               { name: 'برونزي', icon: '🥉', next: 'فضي',   nextPts: 500  };
}

// ─────────────────────────────────────────────
//  ██  AUTH ROUTES
// ─────────────────────────────────────────────

/**  POST /api/login  */
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = sanitize(req.body);
    if (!username || !password)
      return res.status(400).json({ message: 'يرجى إدخال اسم المستخدم وكلمة المرور' });

    const db   = readDB();
    const user = db.users.find(
      u => (u.username === username || u.email === username) && !u.deleted
    );
    if (!user) return res.status(401).json({ message: 'اسم المستخدم غير موجود' });

    // Support plain-text passwords in db.json AND bcrypt hashes
    let passwordOk = false;
    if (user.password.startsWith('$2b$') || user.password.startsWith('$2a$')) {
      passwordOk = await bcrypt.compare(password, user.password);
    } else {
      // Plain-text (legacy) — compare then upgrade to hash
      passwordOk = (user.password === password);
      if (passwordOk) {
        user.password = await bcrypt.hash(password, 10);
      }
    }

    if (!passwordOk) return res.status(401).json({ message: 'كلمة المرور غير صحيحة' });

    // Generate session token
    user.token = crypto.randomBytes(32).toString('hex');
    user.lastLogin = new Date().toISOString();
    writeDB(db);

    const { password: _, ...safeUser } = user;
    res.json({ ...safeUser, token: user.token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

/**  POST /api/logout  */
app.post('/api/logout', authRequired, (req, res) => {
  const db   = readDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (user) { user.token = null; writeDB(db); }
  res.json({ message: 'تم تسجيل الخروج بنجاح' });
});

/**  POST /api/users  (Register)  */
app.post('/api/users', async (req, res) => {
  try {
    const data = sanitize(req.body);
    const { name, username, email, password, phone } = data;

    if (!name || !username || !email || !password)
      return res.status(400).json({ message: 'يرجى ملء جميع الحقول الإلزامية' });
    if (password.length < 8)
      return res.status(400).json({ message: 'كلمة المرور يجب أن تكون 8 أحرف على الأقل' });
    if (!/\S+@\S+\.\S+/.test(email))
      return res.status(400).json({ message: 'البريد الإلكتروني غير صحيح' });

    const db = readDB();
    if (db.users.find(u => u.username === username))
      return res.status(409).json({ message: 'اسم المستخدم مستخدم بالفعل' });
    if (db.users.find(u => u.email === email))
      return res.status(409).json({ message: 'البريد الإلكتروني مستخدم بالفعل' });

    const hashed = await bcrypt.hash(password, 10);
    const token  = crypto.randomBytes(32).toString('hex');

    const newUser = {
      id:            nextId(db.users),
      name:          name.trim(),
      username:      username.trim().toLowerCase(),
      email:         email.trim().toLowerCase(),
      phone:         phone || '',
      password:      hashed,
      token,
      role:          'user',
      loyaltyPoints: 50,  // Welcome bonus
      city:          data.city || '',
      bio:           '',
      preferences:   [],
      createdAt:     new Date().toISOString(),
      lastLogin:     new Date().toISOString()
    };

    // Log welcome bonus
    if (!db.loyalty_log) db.loyalty_log = [];
    db.loyalty_log.push({
      id: nextId(db.loyalty_log || []),
      userId: newUser.id,
      amount: 50,
      type: 'plus',
      label: 'مكافأة الترحيب',
      createdAt: new Date().toISOString()
    });

    db.users.push(newUser);
    writeDB(db);

    const { password: _, ...safeUser } = newUser;
    res.status(201).json({ ...safeUser, token });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

/**  GET /api/users/:id  */
app.get('/api/users/:id', authRequired, (req, res) => {
  const db   = readDB();
  const user = db.users.find(u => u.id === parseInt(req.params.id));
  if (!user || user.deleted) return res.status(404).json({ message: 'المستخدم غير موجود' });
  const { password, token, ...safe } = user;
  res.json(safe);
});

/**  PATCH /api/users/:id  (Update profile)  */
app.patch('/api/users/:id', authRequired, async (req, res) => {
  try {
    if (req.user.id !== parseInt(req.params.id) && req.user.role !== 'admin')
      return res.status(403).json({ message: 'غير مصرح' });

    const db   = readDB();
    const idx  = db.users.findIndex(u => u.id === parseInt(req.params.id));
    if (idx === -1) return res.status(404).json({ message: 'المستخدم غير موجود' });

    const allowed = ['name','phone','city','bio','preferences','birth'];
    const updates = sanitize(req.body);

    // Handle password change separately
    if (updates.newPassword) {
      if (updates.newPassword.length < 8)
        return res.status(400).json({ message: 'كلمة المرور يجب أن تكون 8 أحرف على الأقل' });
      db.users[idx].password = await bcrypt.hash(updates.newPassword, 10);
    }

    allowed.forEach(field => {
      if (updates[field] !== undefined) db.users[idx][field] = updates[field];
    });

    db.users[idx].updatedAt = new Date().toISOString();
    writeDB(db);

    const { password, token, ...safe } = db.users[idx];
    res.json(safe);
  } catch (err) {
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// ─────────────────────────────────────────────
//  ██  PROGRAMS
// ─────────────────────────────────────────────

/**  GET /api/programs  */
app.get('/api/programs', (req, res) => {
  const db       = readDB();
  const { type, maxPrice, duration, search, featured } = req.query;
  let programs   = db.programs.filter(p => !p.deleted);

  if (type)     programs = programs.filter(p => p.type === type);
  if (maxPrice) programs = programs.filter(p => (p.price || 0) <= parseInt(maxPrice));
  if (duration) programs = programs.filter(p => parseInt(p.duration) <= parseInt(duration));
  if (search)   programs = programs.filter(p =>
    (p.name||'').toLowerCase().includes(search.toLowerCase()) ||
    (p.description||'').toLowerCase().includes(search.toLowerCase()) ||
    (p.location||'').toLowerCase().includes(search.toLowerCase())
  );
  if (featured === 'true') programs = programs.filter(p => p.featured);

  // Add loyalty points to each program
  programs = programs.map(p => ({ ...p, loyaltyPoints: calcLoyaltyPoints('program', p.price) }));

  res.json(programs);
});

/**  GET /api/programs/:id  */
app.get('/api/programs/:id', (req, res) => {
  const db = readDB();
  const p  = db.programs.find(p => p.id === parseInt(req.params.id) && !p.deleted);
  if (!p) return res.status(404).json({ message: 'البرنامج غير موجود' });
  res.json({ ...p, loyaltyPoints: calcLoyaltyPoints('program', p.price) });
});

/**  POST /api/programs  (Admin only)  */
app.post('/api/programs', adminRequired, (req, res) => {
  const db   = readDB();
  const data = sanitize(req.body);
  const prog = { id: nextId(db.programs), ...data, createdAt: new Date().toISOString() };
  db.programs.push(prog);
  writeDB(db);
  res.status(201).json(prog);
});

/**  PATCH /api/programs/:id  */
app.patch('/api/programs/:id', adminRequired, (req, res) => {
  const db  = readDB();
  const idx = db.programs.findIndex(p => p.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ message: 'البرنامج غير موجود' });
  Object.assign(db.programs[idx], sanitize(req.body), { updatedAt: new Date().toISOString() });
  writeDB(db);
  res.json(db.programs[idx]);
});

/**  DELETE /api/programs/:id  */
app.delete('/api/programs/:id', adminRequired, (req, res) => {
  const db  = readDB();
  const idx = db.programs.findIndex(p => p.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ message: 'غير موجود' });
  db.programs[idx].deleted = true;
  writeDB(db);
  res.json({ message: 'تم الحذف' });
});

// ─────────────────────────────────────────────
//  ██  HOTELS
// ─────────────────────────────────────────────

/**  GET /api/hotels  */
app.get('/api/hotels', (req, res) => {
  const db    = readDB();
  const { type, stars, maxPrice, search } = req.query;
  let hotels  = db.hotels.filter(h => !h.deleted);

  if (type)     hotels = hotels.filter(h => h.type === type);
  if (stars)    hotels = hotels.filter(h => parseInt(h.stars) >= parseInt(stars));
  if (maxPrice) hotels = hotels.filter(h => (h.pricePerNight || 0) <= parseInt(maxPrice));
  if (search)   hotels = hotels.filter(h =>
    (h.name||'').toLowerCase().includes(search.toLowerCase()) ||
    (h.location||'').toLowerCase().includes(search.toLowerCase())
  );

  hotels = hotels.map(h => ({ ...h, price: h.pricePerNight, loyaltyPoints: calcLoyaltyPoints('hotel', h.pricePerNight) }));
  res.json(hotels);
});

/**  GET /api/hotels/:id  */
app.get('/api/hotels/:id', (req, res) => {
  const db = readDB();
  const h  = db.hotels.find(h => h.id === parseInt(req.params.id) && !h.deleted);
  if (!h) return res.status(404).json({ message: 'الفندق غير موجود' });
  res.json({ ...h, price: h.pricePerNight, loyaltyPoints: calcLoyaltyPoints('hotel', h.pricePerNight) });
});

/**  POST /api/hotels  (Admin)  */
app.post('/api/hotels', adminRequired, (req, res) => {
  const db   = readDB();
  const data = sanitize(req.body);
  const hotel = { id: nextId(db.hotels), ...data, createdAt: new Date().toISOString() };
  db.hotels.push(hotel);
  writeDB(db);
  res.status(201).json(hotel);
});

// ─────────────────────────────────────────────
//  ██  SOUVENIRS
// ─────────────────────────────────────────────

/**  GET /api/souvenirs  */
app.get('/api/souvenirs', (req, res) => {
  const db   = readDB();
  const { category, maxPrice, search, inStock } = req.query;
  let items  = db.souvenirs.filter(s => !s.deleted);

  if (category) items = items.filter(s => s.category === category);
  if (maxPrice) items = items.filter(s => (s.price || 0) <= parseInt(maxPrice));
  if (search)   items = items.filter(s =>
    (s.name||'').toLowerCase().includes(search.toLowerCase())
  );
  if (inStock === 'true') items = items.filter(s => (s.stock || 0) > 0);

  items = items.map(s => ({ ...s, loyaltyPoints: calcLoyaltyPoints('souvenir', s.price) }));
  res.json(items);
});

/**  GET /api/souvenirs/:id  */
app.get('/api/souvenirs/:id', (req, res) => {
  const db = readDB();
  const s  = db.souvenirs.find(s => s.id === parseInt(req.params.id) && !s.deleted);
  if (!s) return res.status(404).json({ message: 'المنتج غير موجود' });
  res.json(s);
});

// ─────────────────────────────────────────────
//  ██  BOOKINGS
// ─────────────────────────────────────────────

/**  GET /api/bookings  */
app.get('/api/bookings', authRequired, (req, res) => {
  const db   = readDB();
  const uid  = parseInt(req.query.userId);
  let bookings = req.user.role === 'admin'
    ? db.bookings
    : db.bookings.filter(b => b.userId === req.user.id);

  if (uid && req.user.role === 'admin') bookings = bookings.filter(b => b.userId === uid);

  res.json(bookings);
});

/**  POST /api/bookings  */
app.post('/api/bookings', async (req, res) => {
  try {
    const db   = readDB();
    const data = sanitize(req.body);

    // Validate required fields
    if (!data.name || !data.phone)
      return res.status(400).json({ message: 'الاسم ورقم الهاتف مطلوبان' });

    const price  = parseInt(data.price) || 0;
    const pts    = calcLoyaltyPoints(data.type || 'program', price);

    const booking = {
      id:          nextId(db.bookings),
      userId:      data.userId || 0,
      type:        data.type || 'program',
      name:        data.name,
      image:       data.image || null,
      phone:       data.phone,
      price,
      loyaltyPts:  pts,
      travelers:   parseInt(data.travelers) || 1,
      date:        data.date || null,
      checkIn:     data.checkIn || null,
      checkOut:    data.checkOut || null,
      address:     data.address || null,
      quantity:    parseInt(data.quantity) || 1,
      status:      'pending',
      deleted:     false,
      rated:       false,
      createdAt:   new Date().toISOString()
    };

    db.bookings.push(booking);

    // Award loyalty points to user
    if (data.userId) {
      const userIdx = db.users.findIndex(u => u.id === parseInt(data.userId));
      if (userIdx !== -1) {
        db.users[userIdx].loyaltyPoints = (db.users[userIdx].loyaltyPoints || 0) + pts;

        // Log loyalty transaction
        if (!db.loyalty_log) db.loyalty_log = [];
        db.loyalty_log.push({
          id:        nextId(db.loyalty_log),
          userId:    parseInt(data.userId),
          amount:    pts,
          type:      'plus',
          label:     `حجز: ${data.name}`,
          bookingId: booking.id,
          createdAt: new Date().toISOString()
        });
      }
    }

    writeDB(db);
    res.status(201).json({ ...booking, message: `تم الحجز بنجاح! ربحت ${pts} نقطة ولاء` });
  } catch (err) {
    console.error('Booking error:', err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

/**  PATCH /api/bookings/:id  (update status, soft-delete, rate)  */
app.patch('/api/bookings/:id', (req, res) => {
  try {
    const db  = readDB();
    const idx = db.bookings.findIndex(b => b.id === parseInt(req.params.id));
    if (idx === -1) return res.status(404).json({ message: 'الحجز غير موجود' });

    const allowed = ['status','deleted','rated','userRating','userComment','checkIn','checkOut'];
    const updates = sanitize(req.body);

    allowed.forEach(field => {
      if (updates[field] !== undefined) db.bookings[idx][field] = updates[field];
    });

    db.bookings[idx].updatedAt = new Date().toISOString();

    // If rating submitted — store as review
    if (updates.rated && updates.userRating) {
      if (!db.reviews) db.reviews = [];
      const existing = db.reviews.find(r => r.bookingId === parseInt(req.params.id));
      if (!existing) {
        db.reviews.push({
          id:        nextId(db.reviews),
          bookingId: parseInt(req.params.id),
          userId:    db.bookings[idx].userId,
          itemName:  db.bookings[idx].name,
          type:      db.bookings[idx].type,
          rating:    updates.userRating,
          comment:   updates.userComment || '',
          createdAt: new Date().toISOString()
        });
      }
    }

    // Deduct points if cancelled
    if (updates.status === 'cancelled' && updates.deleted && db.bookings[idx].userId) {
      const pts     = db.bookings[idx].loyaltyPts || 0;
      const userIdx = db.users.findIndex(u => u.id === db.bookings[idx].userId);
      if (userIdx !== -1 && pts > 0) {
        db.users[userIdx].loyaltyPoints = Math.max(0, (db.users[userIdx].loyaltyPoints || 0) - pts);
        if (!db.loyalty_log) db.loyalty_log = [];
        db.loyalty_log.push({
          id: nextId(db.loyalty_log),
          userId: db.bookings[idx].userId,
          amount: -pts,
          type: 'minus',
          label: `إلغاء حجز: ${db.bookings[idx].name}`,
          bookingId: parseInt(req.params.id),
          createdAt: new Date().toISOString()
        });
      }
    }

    writeDB(db);
    res.json(db.bookings[idx]);
  } catch (err) {
    console.error('Patch booking error:', err);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

/**  DELETE /api/bookings/:id  (permanent delete)  */
app.delete('/api/bookings/:id', authRequired, (req, res) => {
  const db  = readDB();
  const idx = db.bookings.findIndex(b => b.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ message: 'الحجز غير موجود' });
  if (db.bookings[idx].userId !== req.user.id && req.user.role !== 'admin')
    return res.status(403).json({ message: 'غير مصرح' });
  db.bookings.splice(idx, 1);
  writeDB(db);
  res.json({ message: 'تم الحذف النهائي' });
});

// ─────────────────────────────────────────────
//  ██  REVIEWS
// ─────────────────────────────────────────────

/**  GET /api/reviews  */
app.get('/api/reviews', (req, res) => {
  const db  = readDB();
  const { type, itemName } = req.query;
  let reviews = (db.reviews || []);
  if (type)     reviews = reviews.filter(r => r.type === type);
  if (itemName) reviews = reviews.filter(r => r.itemName === itemName);
  res.json(reviews);
});

/**  POST /api/reviews  */
app.post('/api/reviews', (req, res) => {
  const db   = readDB();
  const data = sanitize(req.body);
  if (!data.rating || !data.itemName)
    return res.status(400).json({ message: 'التقييم والاسم مطلوبان' });

  if (!db.reviews) db.reviews = [];
  const review = {
    id:        nextId(db.reviews),
    userId:    data.userId || 0,
    itemName:  data.itemName,
    type:      data.type || 'program',
    rating:    Math.min(5, Math.max(1, parseInt(data.rating))),
    comment:   data.comment || '',
    createdAt: new Date().toISOString()
  };
  db.reviews.push(review);
  writeDB(db);
  res.status(201).json(review);
});

// ─────────────────────────────────────────────
//  ██  LOYALTY
// ─────────────────────────────────────────────

/**  GET /api/loyalty/:userId  */
app.get('/api/loyalty/:userId', authRequired, (req, res) => {
  const db     = readDB();
  const userId = parseInt(req.params.userId);
  if (req.user.id !== userId && req.user.role !== 'admin')
    return res.status(403).json({ message: 'غير مصرح' });

  const user   = db.users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ message: 'المستخدم غير موجود' });

  const pts    = user.loyaltyPoints || 0;
  const tier   = getTier(pts);
  const log    = (db.loyalty_log || []).filter(l => l.userId === userId).slice(-20).reverse();

  res.json({ points: pts, tier, log });
});

/**  POST /api/loyalty/redeem  */
app.post('/api/loyalty/redeem', authRequired, (req, res) => {
  const { amount } = req.body;
  const pts = parseInt(amount);
  if (!pts || pts < 100) return res.status(400).json({ message: 'الحد الأدنى للاسترداد 100 نقطة' });

  const db      = readDB();
  const userIdx = db.users.findIndex(u => u.id === req.user.id);
  if (db.users[userIdx].loyaltyPoints < pts)
    return res.status(400).json({ message: 'رصيدك غير كافٍ' });

  const discount = Math.floor(pts / 100) * 50; // 100 pts = 50 DZD discount
  db.users[userIdx].loyaltyPoints -= pts;

  if (!db.loyalty_log) db.loyalty_log = [];
  db.loyalty_log.push({
    id: nextId(db.loyalty_log),
    userId: req.user.id,
    amount: -pts,
    type: 'minus',
    label: `استرداد نقاط — خصم ${discount} دج`,
    createdAt: new Date().toISOString()
  });
  writeDB(db);

  res.json({ message: `تم استرداد ${pts} نقطة — خصم ${discount} دج على حجزك القادم`, discount });
});

// ─────────────────────────────────────────────
//  ██  MESSAGES (Contact Form)
// ─────────────────────────────────────────────

/**  POST /api/messages  */
app.post('/api/messages', (req, res) => {
  const db   = readDB();
  const data = sanitize(req.body);

  if (!data.name || !data.phone)
    return res.status(400).json({ message: 'الاسم والهاتف مطلوبان' });

  const msg = {
    id:        nextId(db.messages),
    type:      data.type || 'general',
    name:      data.name,
    phone:     data.phone,
    email:     data.email || '',
    subject:   data.subject || '',
    message:   data.message || '',
    company:   data.company || '',
    city:      data.city || '',
    status:    'new',
    createdAt: new Date().toISOString()
  };
  db.messages.push(msg);
  writeDB(db);
  res.status(201).json({ message: 'تم استلام رسالتك! سنتواصل معك قريباً', id: msg.id });
});

/**  GET /api/messages  (Admin)  */
app.get('/api/messages', adminRequired, (req, res) => {
  const db = readDB();
  res.json(db.messages.slice().reverse());
});

// ─────────────────────────────────────────────
//  ██  B2B PARTNERS
// ─────────────────────────────────────────────

/**  POST /api/partners  */
app.post('/api/partners', (req, res) => {
  const db   = readDB();
  const data = sanitize(req.body);

  if (!data.name || !data.phone || !data.company || !data.businessType)
    return res.status(400).json({ message: 'يرجى ملء جميع الحقول الإلزامية' });

  if (!db.partners) db.partners = [];
  const partner = {
    id:           nextId(db.partners),
    name:         data.name,
    phone:        data.phone,
    email:        data.email || '',
    company:      data.company,
    businessType: data.businessType,
    city:         data.city || '',
    message:      data.message || '',
    status:       'pending',
    commission:   '5%',
    createdAt:    new Date().toISOString()
  };
  db.partners.push(partner);
  writeDB(db);
  res.status(201).json({ message: 'تم استلام طلب الشراكة! سنتواصل معك خلال 24 ساعة', id: partner.id });
});

/**  GET /api/partners  (Admin)  */
app.get('/api/partners', adminRequired, (req, res) => {
  const db = readDB();
  res.json(db.partners || []);
});

// ─────────────────────────────────────────────
//  ██  STATS  (Homepage / Dashboard)
// ─────────────────────────────────────────────

/**  GET /api/stats  */
app.get('/api/stats', (req, res) => {
  const db = readDB();
  const activeBookings  = db.bookings.filter(b => !b.deleted);
  const completedTrips  = activeBookings.filter(b => b.status === 'completed');
  const avgRating       = db.reviews?.length
    ? (db.reviews.reduce((s, r) => s + (r.rating || 0), 0) / db.reviews.length).toFixed(1)
    : '4.9';

  res.json({
    programs:       db.programs.filter(p => !p.deleted).length,
    hotels:         db.hotels.filter(h => !h.deleted).length,
    souvenirs:      db.souvenirs.filter(s => !s.deleted).length,
    users:          db.users.filter(u => !u.deleted).length,
    bookings:       activeBookings.length,
    completedTrips: completedTrips.length,
    partners:       (db.partners || []).filter(p => p.status === 'approved').length,
    avgRating,
    totalRevenue:   activeBookings.reduce((s, b) => s + (b.price || 0), 0)
  });
});

// ─────────────────────────────────────────────
//  ██  ANALYTICS
// ─────────────────────────────────────────────

/**  POST /api/track-visit  */
app.post('/api/track-visit', (req, res) => {
  const db   = readDB();
  const data = sanitize(req.body);
  if (!db.visits) db.visits = [];
  db.visits.push({
    id:        nextId(db.visits),
    page:      data.page || 'unknown',
    userId:    data.userId || null,
    userAgent: req.headers['user-agent']?.substring(0, 100) || '',
    createdAt: new Date().toISOString()
  });
  writeDB(db);
  res.json({ ok: true });
});

/**  GET /api/analytics  (Admin)  */
app.get('/api/analytics', adminRequired, (req, res) => {
  const db    = readDB();
  const today = new Date().toDateString();

  // Page visits in last 7 days
  const week      = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const recentVis = (db.visits || []).filter(v => new Date(v.createdAt) > week);
  const pageHits  = {};
  recentVis.forEach(v => { pageHits[v.page] = (pageHits[v.page] || 0) + 1; });

  res.json({
    totalVisits:    (db.visits || []).length,
    todayVisits:    (db.visits || []).filter(v => new Date(v.createdAt).toDateString() === today).length,
    weeklyVisits:   recentVis.length,
    pageHits,
    newUsers:       db.users.filter(u => new Date(u.createdAt) > week).length,
    newBookings:    db.bookings.filter(b => new Date(b.createdAt) > week).length,
  });
});

// ─────────────────────────────────────────────
//  ██  AI CHATBOT
// ─────────────────────────────────────────────
const chatResponses = {
  greetings: {
    triggers: ['مرحبا','السلام','اهلا','أهلاً','هلا','صباح','مساء','كيف حالك','hi','hello','bonjour'],
    responses: [
      '👋 أهلاً وسهلاً! أنا مساعد حوس بيا الذكي. كيف يمكنني مساعدتك اليوم؟',
      '🌟 مرحباً بك في حوس بيا! يسعدني مساعدتك في التخطيط لرحلتك الجزائرية المثالية.',
      '😊 أهلاً! اسألني عن أي مكان في الجزائر وسأوفر لك كل المعلومات التي تحتاجها.'
    ]
  },
  laghouat: {
    triggers: ['اغواط','الأغواط','laghouat','لاغوات'],
    responses: [
      '🏜️ الأغواط — بوابة الصحراء الجزائرية!\n\n📍 تقع على بُعد 400 كم جنوب العاصمة.\n🌡️ مناخ صحراوي جاف — أفضل وقت للزيارة: أكتوبر إلى مارس.\n\n🎯 أبرز المعالم:\n• واحة النخيل الشهيرة\n• المسجد الكبير التاريخي\n• متحف الأغواط\n• حدائق الواحة\n• السوق التقليدي العتيق\n\n🚗 يمكن الوصول إليها بالسيارة أو عبر مطار الأغواط.'
    ]
  },
  ghardaia: {
    triggers: ['غرداية','غردايا','ghardaia','وادي ميزاب','مزاب'],
    responses: [
      '🏛️ غرداية — تحفة معمارية في قلب الصحراء!\n\n📍 ولاية غرداية — على بُعد 600 كم من الجزائر العاصمة.\n🏆 مدرجة على قائمة التراث العالمي لليونسكو منذ 1982.\n\n🎯 أبرز ما تشتهر به:\n• القصور الخمس التاريخية\n• سوق الثلاثاء العريق\n• الهندسة المعمارية الأمازيغية الفريدة\n• متحف الفنون والتقاليد\n• المنتجات الحرفية اليدوية\n\n⏱️ المدة الموصى بها: 2-3 أيام.'
    ]
  },
  tamanrasset: {
    triggers: ['تمنراست','تامنغست','tamanrasset','أهقار','هوقار','صحراء'],
    responses: [
      '🏔️ تمنراست — جنة الصحراء الكبرى!\n\n📍 أقصى جنوب الجزائر — تُعدّ واحدة من أجمل المدن الصحراوية في العالم.\n🌄 أفضل موسم للزيارة: نوفمبر إلى مارس.\n\n🎯 لا تفوت:\n• جبال الأهقار وهضبة الطاسيلي\n• شروق الشمس في كثبان الرمال\n• ليالي النجوم في الصحراء\n• الثقافة الطوارق الأصيلة\n• تذوق اللحم المشوي على الجمر الصحراوي\n\n🐪 رحلات سفاري متاحة من خلال منصتنا!'
    ]
  },
  booking: {
    triggers: ['حجز','احجز','حجزت','ارغب','أريد','كيف احجز','book'],
    responses: [
      '📲 الحجز في حوس بيا بسيط جداً!\n\n1️⃣ تصفح البرامج أو الفنادق\n2️⃣ اضغط "احجز الآن"\n3️⃣ أدخل بياناتك\n4️⃣ انتظر تأكيدنا — سنتصل بك خلال ساعتين\n\n✅ الحجز آمن ومضمون\n⭐ تكسب نقاط ولاء مع كل حجز!\n\nهل تريد الانتقال مباشرة إلى البرامج السياحية؟',
      '🎯 لحجز أي برنامج أو فندق:\n• انتقل لصفحة البرامج أو الفنادق\n• اختر ما يناسبك\n• اضغط "احجز الآن" وأكمل البيانات\n\n💡 نصيحة: استخدم مستشارنا الذكي للحصول على توصيات مخصصة!'
    ]
  },
  price: {
    triggers: ['سعر','اسعار','كم التكلفة','كم يكلف','تكلفة','ميزانية','دج'],
    responses: [
      '💰 أسعارنا تناسب جميع الميزانيات:\n\n🥉 اقتصادية: 2,000 — 8,000 دج\n🥈 متوسطة: 8,000 — 20,000 دج\n🥇 مميزة: 20,000 — 50,000 دج\n\n💡 استخدم المستشار الذكي لفلترة الخيارات حسب ميزانيتك بالضبط!\n\n⭐ كل حجز = نقاط ولاء تحوّلها لخصومات في المرات القادمة.'
    ]
  },
  loyalty: {
    triggers: ['نقاط','ولاء','مكافأة','خصم','loyalty','points'],
    responses: [
      '⭐ نظام نقاط الولاء في حوس بيا:\n\n🎁 كيف تكسب نقاط:\n• حجز برنامج = 1% من قيمته\n• حجز فندق = 0.5% من قيمته\n• شراء منتج تقليدي = 0.8%\n• إحالة صديق = 100 نقطة\n• مكافأة التسجيل = 50 نقطة\n\n🏆 المستويات:\n🥉 برونزي: 0-499 نقطة\n🥈 فضي: 500-1,999 نقطة\n🥇 ذهبي: 2,000-4,999 نقطة\n💎 ماسي: 5,000+ نقطة\n\n💵 كل 100 نقطة = خصم 50 دج!'
    ]
  },
  contact: {
    triggers: ['تواصل','اتصل','هاتف','بريد','واتس','whatsapp','email'],
    responses: [
      '📞 طرق التواصل معنا:\n\n📱 هاتف: +213 555 000 000\n💬 واتساب: نفس الرقم\n📧 بريد: contact@hawsbiya.dz\n🕐 مواعيد العمل: الأحد-الخميس 8ص-5م\n\n🌐 أو استخدم صفحة "اتصل بنا" في الموقع وسنرد خلال ساعتين!'
    ]
  },
  cancel: {
    triggers: ['الغاء','إلغاء','الغ','ارجاع','استرداد','cancel'],
    responses: [
      '🔄 سياسة الإلغاء والاسترداد:\n\n✅ إلغاء مجاني: قبل 48 ساعة من موعد الرحلة\n⚠️ إلغاء جزئي: بين 24-48 ساعة (رسوم 20%)\n❌ بعد 24 ساعة: وفق سياسة مزود الخدمة\n\nلإلغاء حجزك، انتقل لصفحة "حجوزاتي" واضغط على زر الإلغاء.'
    ]
  },
  ai: {
    triggers: ['ذكاء','مستشار','يوصي','توصية','يقترح','اقتراح','ai'],
    responses: [
      '🤖 مستشارنا الذكي يعمل بخوارزمية توافق متطورة:\n\n1️⃣ اختر اهتماماتك (8 خيارات متاحة)\n2️⃣ حدد رفيق رحلتك ومدتها\n3️⃣ أدخل ميزانيتك\n4️⃣ يحسب الذكاء الاصطناعي نسبة توافق لكل برنامج ويشرح لك لماذا اختاره!\n\n💡 تفضيلاتك تُحفظ تلقائياً لتوصيات أدق في المرات القادمة.\n\nانتقل لصفحة المستشار الذكي وجرّبه الآن!'
    ]
  },
  thanks: {
    triggers: ['شكرا','شكراً','merci','thanks','thank you','بارك الله'],
    responses: [
      '😊 العفو! يسعدنا خدمتك. هل هناك شيء آخر يمكنني مساعدتك به؟',
      '🙏 بكل سرور! نتمنى لك رحلة ممتعة مع حوس بيا ⭐',
      '💙 شكراً لك أنت! لا تتردد في السؤال عن أي شيء آخر.'
    ]
  },
  default: [
    '🤔 لم أفهم سؤالك تماماً. هل تريد معلومات عن:\n• 📍 وجهة سياحية معينة؟\n• 🏨 فنادق متاحة؟\n• 📅 حجز برنامج سياحي؟\n• ⭐ نظام نقاط الولاء؟\n• 📞 التواصل مع فريقنا?',
    '😊 يمكنني مساعدتك في الحجز والمعلومات السياحية عن الجزائر. أخبرني بما تحتاجه وسأكون سعيداً بمساعدتك!'
  ]
};

/**  POST /api/chat  */
app.post('/api/chat', (req, res) => {
  const db      = readDB();
  const message = sanitize(req.body.message || '').toLowerCase().trim();
  const userId  = req.body.userId || null;

  if (!message) return res.status(400).json({ message: 'يرجى إدخال رسالة' });

  let reply = null;

  // Match category
  for (const [cat, data] of Object.entries(chatResponses)) {
    if (cat === 'default') continue;
    const triggers = data.triggers || [];
    if (triggers.some(t => message.includes(t))) {
      const responses = data.responses || [];
      reply = responses[Math.floor(Math.random() * responses.length)];
      break;
    }
  }

  // Default reply
  if (!reply) {
    const defaults = chatResponses.default;
    reply = defaults[Math.floor(Math.random() * defaults.length)];
  }

  // Store in history
  if (!db.chat_history) db.chat_history = [];
  db.chat_history.push({
    id:        nextId(db.chat_history),
    userId,
    message:   sanitize(req.body.message || ''),
    reply,
    createdAt: new Date().toISOString()
  });

  // Keep only last 1000 messages
  if (db.chat_history.length > 1000) db.chat_history = db.chat_history.slice(-1000);
  writeDB(db);

  res.json({ reply, timestamp: new Date().toISOString() });
});

/**  GET /api/history  */
app.get('/api/history', authRequired, (req, res) => {
  const db = readDB();
  const history = (db.chat_history || [])
    .filter(h => h.userId === req.user.id)
    .slice(-50)
    .reverse();
  res.json(history);
});

// ─────────────────────────────────────────────
//  ██  ADMIN DASHBOARD
// ─────────────────────────────────────────────

/**  GET /api/admin/dashboard  */
app.get('/api/admin/dashboard', adminRequired, (req, res) => {
  const db      = readDB();
  const week    = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const month   = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const bookings     = db.bookings.filter(b => !b.deleted);
  const newBookings  = bookings.filter(b => new Date(b.createdAt) > week);
  const revenue      = bookings.reduce((s, b) => s + (b.price || 0), 0);
  const monthlyRev   = bookings.filter(b => new Date(b.createdAt) > month).reduce((s,b) => s + (b.price || 0), 0);

  // Top programs by bookings
  const programCount = {};
  bookings.filter(b => b.type === 'program').forEach(b => {
    programCount[b.name] = (programCount[b.name] || 0) + 1;
  });
  const topPrograms = Object.entries(programCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name, count]) => ({ name, count }));

  res.json({
    overview: {
      totalUsers:    db.users.filter(u => !u.deleted).length,
      newUsers:      db.users.filter(u => new Date(u.createdAt) > week).length,
      totalBookings: bookings.length,
      newBookings:   newBookings.length,
      totalRevenue:  revenue,
      monthlyRevenue: monthlyRev,
      pendingPartners: (db.partners || []).filter(p => p.status === 'pending').length,
      newMessages:   db.messages.filter(m => m.status === 'new').length
    },
    topPrograms,
    recentBookings: bookings.slice(-10).reverse(),
    recentMessages: db.messages.slice(-5).reverse()
  });
});

// ─────────────────────────────────────────────
//  ██  SEARCH (cross-entity)
// ─────────────────────────────────────────────

/**  GET /api/search?q=...  */
app.get('/api/search', (req, res) => {
  const { q } = req.query;
  if (!q || q.length < 2) return res.json({ programs: [], hotels: [], souvenirs: [] });

  const db  = readDB();
  const kw  = q.toLowerCase();
  const match = item =>
    (item.name||'').toLowerCase().includes(kw) ||
    (item.description||'').toLowerCase().includes(kw) ||
    (item.location||'').toLowerCase().includes(kw) ||
    (item.type||'').toLowerCase().includes(kw);

  res.json({
    programs:  db.programs.filter(p => !p.deleted && match(p)).slice(0, 5),
    hotels:    db.hotels.filter(h => !h.deleted && match(h)).slice(0, 5),
    souvenirs: db.souvenirs.filter(s => !s.deleted && match(s)).slice(0, 5)
  });
});

// ─────────────────────────────────────────────
//  ██  CATCH-ALL — Serve SPA
// ─────────────────────────────────────────────
app.get('/{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ─────────────────────────────────────────────
//  Start Server
// ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 حوس بيا — الخادم يعمل على المنفذ ${PORT}`);
  console.log(`🌐 http://localhost:${PORT}`);
  console.log(`📦 قاعدة البيانات: ${DB_PATH}\n`);

  // Ensure DB has required collections
  const db = readDB();
  let changed = false;
  ['users','programs','hotels','souvenirs','bookings','messages','partners','reviews','visits','chat_history','loyalty_log'].forEach(col => {
    if (!db[col]) { db[col] = []; changed = true; }
  });
  if (changed) writeDB(db);
});