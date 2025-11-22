require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');

const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();

const bcrypt = require('bcryptjs');


const app = express();
const PORT = process.env.PORT || 3000;
let DB_PATH = '/var/data/app.db';
// DB_PATH = path.join(__dirname, 'app.db');

const expressLayouts = require('express-ejs-layouts');
app.use(expressLayouts);
app.set('layout', 'layout'); // layout.ejs in /views
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ----- DB -----
const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.run(`PRAGMA foreign_keys = ON`);
  db.run(`CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    is_banned INTEGER DEFAULT 0,
    balance INTEGER DEFAULT 500,
    last_faucet_date TEXT


  )`);
  db.run(`ALTER TABLE markets ADD COLUMN category TEXT`, () => {});

  db.run(`ALTER TABLE markets ADD COLUMN is_locked INTEGER DEFAULT 0`, () => {});


  db.run(`CREATE TABLE IF NOT EXISTS markets(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    creator_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    image_filename TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    is_resolved INTEGER DEFAULT 0,
    resolved_option_id INTEGER,
    is_removed INTEGER DEFAULT 0,
    FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS options(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    market_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    shares INTEGER DEFAULT 0,
    FOREIGN KEY (market_id) REFERENCES markets(id) ON DELETE CASCADE
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS trades(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    market_id INTEGER NOT NULL,
    option_id INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (market_id) REFERENCES markets(id),
    FOREIGN KEY (option_id) REFERENCES options(id)
  )`);
  db.run(`ALTER TABLE markets ADD COLUMN category TEXT`, () => {});


  // seed admin if none exists
  db.get(`SELECT COUNT(*) as c FROM users WHERE is_admin = 1`, async (err, row) => {
    if (err) return console.error(err);
    if (row.c === 0) {
      const adminUser = process.env.ADMIN_USERNAME || 'Epicwater';
      const adminPass = process.env.ADMIN_PASSWORD || 'admin123';
      const hash = await bcrypt.hash(adminPass, 10);
      db.run(
        `INSERT INTO users(username, password_hash, is_admin, balance) VALUES(?,?,1,10000)`,
        [adminUser, hash],
        (e) => {
          if (e) console.error(e);
          else console.log(`Seeded admin: ${adminUser}/${adminPass}`);
        }
      );
    }
  });
});
db.run(`ALTER TABLE users ADD COLUMN last_claim INTEGER`, () => {});



db.run(`
  CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
  )
`);

db.run(`
  CREATE TABLE IF NOT EXISTS market_tags (
    market_id INTEGER,
    tag_id INTEGER,
    FOREIGN KEY (market_id) REFERENCES markets(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
  )
`);

db.run(`ALTER TABLE users ADD COLUMN last_ip TEXT`, ()=>{});
db.run(`ALTER TABLE users ADD COLUMN banned_ip TEXT`, ()=>{});


// ----- Uploads -----
const uploadDir = '/var/data/uploads';
app.use('/uploads', express.static('/var/data/uploads'));


fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const safe = file.originalname.replace(/[^a-z0-9.\-_]/gi, '_').toLowerCase();
    const unique = Date.now() + '_' + Math.random().toString(16).slice(2) + '_' + safe;
    cb(null, unique);
  }
});
const upload = multer({ storage, limits: { fileSize: 15 * 1024 * 1024 } }); // 2MB




// ----- App config -----
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false
}));



// ---- Correct Flash Middleware ----
// ---- Correct Flash Middleware ----
app.use((req, res, next) => {
  res.locals.flash = req.session.flash || [];
  req.session.flash = []; // clear immediately so they never reappear
  next();
});



// helpers
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}
// ======================
// ADMIN Middleware
// ======================
function requireAdmin(req, res, next) {
  if (!req.session.user || !req.session.user.is_admin) {
    req.session.flash = [{ type: 'error', msg: 'Access denied. Admins only.' }];
    return res.redirect('/');
  }
  next();
}

function currentUser(req) { return req.session.user || null; }
function todayStr() { return new Date().toISOString().slice(0,10); }

// =====================
//  Gate Middleware
// =====================
function requireGate(req, res, next) {
  // If the site gate is enabled, require session flag
  if (process.env.SITE_GATE_PASSWORDS || process.env.SITE_GATE_PASSWORD) {
    if (!req.session.gateOk) {
      return res.redirect('/gate');
    }
  }
  next();
}

// ======================
// ADMIN: Remove market
// ======================
// ======================
// ADMIN: Remove Market
// ======================
// ADMIN: Remove market
app.post('/admin/remove/:id', requireAdmin, (req, res) => {
  const id = req.params.id;

  db.serialize(() => {
    db.run(`DELETE FROM trades WHERE market_id=?`, [id]);
    db.run(`DELETE FROM options WHERE market_id=?`, [id]);
    db.run(`DELETE FROM markets WHERE id=?`, [id], (err) => {
      if (err) {
        console.error(err);
        req.session.flash = [{ type: 'error', msg: 'Error deleting market.' }];
      } else {
        req.session.flash = [{ type: 'success', msg: 'Market deleted successfully.' }];
      }
      res.redirect('/admin');
    });
  });
});
// ======================
// ADMIN: Delete User
// ======================
app.post('/admin/delete-user/:id', requireAdmin, (req, res) => {
  const userId = req.params.id;

  // Prevent deleting the admin themself for safety
  if (req.session.user && req.session.user.id === parseInt(userId)) {
    req.session.flash = [{ type: 'error', msg: 'You cannot delete your own account.' }];
    return res.redirect('/admin');
  }

  db.serialize(() => {
    // Delete all user-related data first
    db.run(`DELETE FROM trades WHERE user_id = ?`, [userId]);
    db.run(`DELETE FROM markets WHERE creator_id = ?`, [userId]);
    db.run(`DELETE FROM users WHERE id = ?`, [userId], (err) => {
      if (err) {
        console.error('Error deleting user:', err);
        req.session.flash = [{ type: 'error', msg: 'Failed to delete user.' }];
      } else {
        req.session.flash = [{ type: 'success', msg: 'User deleted successfully.' }];
      }
      res.redirect('/admin');
    });
  });
});



// ---- Gate middleware ----
app.use((req, res, next) => {
  if (req.path.startsWith('/public/') || req.path.startsWith('/css/') || req.path.startsWith('/js/') || req.path.startsWith('/uploads/')) return next();
  if (req.path === '/gate' || req.path.startsWith('/api') || req.path.startsWith('/uploads/')) return next();
  if (!req.session.gateOk && req.path !== '/gate') return res.redirect('/gate');
  next();
});

app.get('/gate', (req, res) => {
  res.render('gate', { user: currentUser(req)});
;
});
app.post('/gate', (req, res) => {
  const entered = (req.body.password || '').trim();

  // Load list of valid passwords (comma-separated)
  const allowedRaw =
    process.env.SITE_GATE_PASSWORDS ||
    process.env.SITE_GATE_PASSWORD || // fallback
    'letmein';

  const allowed = allowedRaw.split(',').map(p => p.trim()).filter(Boolean);

  if (allowed.includes(entered)) {
    req.session.gateOk = true;
    (req.session.flash ||= []).push({ type: 'success', msg: 'Access granted!' });
    return res.redirect('/');
  } else {
    (req.session.flash ||= []).push({ type: 'error', msg: 'Wrong gate password.' });
    return res.redirect('/gate');
  }
});


// ---- Auth ----
app.get('/register', (req, res) => {
  res.render('register', { user: currentUser(req)});
;
});
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    (req.session.flash ||= []).push({ type: 'error', msg: 'Username and password required.' });
    return res.redirect('/register');
  }
  const hash = await bcrypt.hash(password, 10);
  db.run(`INSERT INTO users(username, password_hash) VALUES(?,?)`, [username.trim(), hash], (err) => {
    if (err) {
      (req.session.flash ||= []).push({ type: 'error', msg: 'Username taken or invalid.' });
      return res.redirect('/register');
    }
    (req.session.flash ||= []).push({ type: 'success', msg: 'Registered! Please log in.' });
    res.redirect('/login');
  });
});

app.get('/login', (req, res) => {
  res.render('login', { user: currentUser(req)});
 ;
});
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err || !user) {
      (req.session.flash ||= []).push({ type: 'error', msg: 'Invalid credentials.' });
      return res.redirect('/login');
    }
    if (user.is_banned) {
      (req.session.flash ||= []).push({ type: 'error', msg: 'Your account is banned.' });
      return res.redirect('/login');
    }
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      (req.session.flash ||= []).push({ type: 'error', msg: 'Invalid credentials.' });
      return res.redirect('/login');
    }

    // Extract real IP (Render / proxies / local dev)
const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;

// Update last_ip in DB
db.run(`UPDATE users SET last_ip=? WHERE id=?`, [ip, user.id]);

if (user.banned_ip) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;

  if (ip === user.banned_ip) {
    (req.session.flash ||= []).push({ type: 'error', msg: 'Your IP is banned.' });
    return res.redirect('/login');
  }
}


    req.session.user = { id: user.id, username: user.username, is_admin: !!user.is_admin, balance: user.balance };
    (req.session.flash ||= []).push({ type: 'success', msg: 'Welcome back!' });
    const now = Math.floor(Date.now() / 1000);

db.run(`UPDATE users SET last_claim=? WHERE id=? AND (last_claim IS NULL OR last_claim=0)`,
  [now, user.id]
);

    res.redirect('/');
  });
});
app.get('/logout', (req, res) => {
  req.session.user = null;
  (req.session.flash ||= []).push({ type: 'success', msg: 'Logged out.' });
  res.redirect('/');
});

app.post('/admin/ip-ban', requireAdmin, (req, res) => {
  const { user_id } = req.body;

  db.get(`SELECT last_ip FROM users WHERE id=?`, [user_id], (err, row) => {
    if (!row || !row.last_ip) {
      (req.session.flash ||= []).push({ type: 'error', msg: 'User has no recorded IP.' });
      return res.redirect('/admin');
    }

    db.run(`UPDATE users SET banned_ip=? WHERE id=?`, [row.last_ip, user_id], (e)=>{
      (req.session.flash ||= []).push({ type: e?'error':'success', msg: e?'Failed':'IP banned.' });
      res.redirect('/admin');
    });
  });
});
app.post('/admin/ip-unban', requireAdmin, (req, res) => {
  const { user_id } = req.body;

  db.run(`UPDATE users SET banned_ip=NULL WHERE id=?`, [user_id], (e)=>{
    (req.session.flash ||= []).push({ type: e?'error':'success', msg: e?'Failed':'IP unbanned.' });
    res.redirect('/admin');
  });
});


// Faucet
app.post('/faucet', requireLogin, (req, res) => {
  const uid = req.session.user.id;
  db.get(`SELECT last_faucet_date, balance FROM users WHERE id=?`, [uid], (err, row) => {
    if (err || !row) return res.redirect('/');
    if (row.last_faucet_date === todayStr()) {
      (req.session.flash ||= []).push({ type: 'error', msg: 'Already claimed today.' });
      return res.redirect('/');
    }
    db.run(`UPDATE users SET balance = balance + 250, last_faucet_date = ? WHERE id = ?`, [todayStr(), uid], (e) => {
      if (!e) req.session.user.balance = (row.balance || 0) + 250;
      (req.session.flash ||= []).push({ type: 'success', msg: '+250 coins added!' });
      res.redirect('/');
    });
  });
});

// Home
app.get('/', requireGate, (req, res) => {
  const filter = req.query.filter || 'all';
  const category = req.query.category || 'all';
  const search = (req.query.search || '').trim().toLowerCase();

  const uid = req.session.user ? req.session.user.id : 0;

  let query = "SELECT * FROM markets WHERE 1=1";
  const params = [];

  // FILTER: open / resolved / mine
  if (filter === "open") {
    query += " AND is_resolved = 0";
  } else if (filter === "resolved") {
    query += " AND is_resolved = 1";
  } else if (filter === "mine" && uid) {
    query += " AND creator_id = ?";
    params.push(uid);
  }

  // CATEGORY FILTER
  if (category !== "all") {
    query += " AND category = ?";
    params.push(category);
  }

  // SEARCH by title or description
  if (search.length > 0) {
    query += " AND (LOWER(title) LIKE ? OR LOWER(description) LIKE ?)";
    params.push(`%${search}%`, `%${search}%`);
  }

  // Default ordering
  query += " ORDER BY datetime(created_at) DESC";

  db.all(query, params, (err, markets) => {
    res.render("home", {
      user: currentUser(req),
      markets: markets || [],
      title: "Markets",
      filter,
      category,
      search
    });
  });
});



// Create market
app.get('/markets/new', requireLogin, (req, res) => {
  res.render('create_market', { user: currentUser(req)});

});
app.post('/markets/new', requireLogin, upload.single('image'), (req, res) => {
  const { title, description, options, tags, category } = req.body;

  const opts = (options || "")
    .split("\n")
    .map(s => s.trim())
    .filter(Boolean);

  if (!title || !description || opts.length < 2) {
    req.session.flash = [{ type: "error", msg: "Title, description, and at least two options required." }];
    return res.redirect("/markets/new");
  }

  const image_filename = req.file ? "uploads/" + req.file.filename : null;

  db.run(
    `INSERT INTO markets (creator_id, title, description, image_filename, category)
     VALUES (?, ?, ?, ?, ?)`,
    [req.session.user.id, title.trim(), description.trim(), image_filename, category],
    function (err) {
      if (err) {
        console.error("MARKET ERROR:", err);
        req.session.flash = [{ type: "error", msg: "Error creating market." }];
        return res.redirect("/markets/new");
      }

      const marketId = this.lastID;

      // Insert options
      const stmt = db.prepare(`INSERT INTO options (market_id, name, shares) VALUES (?, ?, 0)`);
      opts.forEach(name => stmt.run(marketId, name));
      stmt.finalize();

      // Tags
      const tagList = (tags || "")
        .split(",")
        .map(t => t.trim().toLowerCase())
        .filter(Boolean);

      tagList.forEach(tag => {
        db.run(`INSERT OR IGNORE INTO tags(name) VALUES (?)`, [tag], () => {
          db.get(`SELECT id FROM tags WHERE name=?`, [tag], (err2, row) => {
            if (row) {
              db.run(`INSERT INTO market_tags(market_id, tag_id) VALUES (?, ?)`, [marketId, row.id]);
            }
          });
        });
      });

      req.session.flash = [{ type: "success", msg: "Market created!" }];
      res.redirect(`/markets/${marketId}`);
    }
  );
});


db.run(`CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  market_id INTEGER,
  user_id INTEGER,
  content TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);


// ----- USER: Edit Market Page -----
app.get('/markets/:id/edit', requireLogin, (req, res) => {
  const marketId = +req.params.id;

  db.get(`SELECT * FROM markets WHERE id=?`, [marketId], (err, market) => {
    if (err || !market) return res.sendStatus(404);

    // Only creator or admin can edit
    if (market.creator_id !== req.session.user.id && !req.session.user.is_admin) {
      req.session.flash = [{ type: 'error', msg: 'You cannot edit this market.' }];
      return res.redirect(`/markets/${marketId}`);
    }

    db.all(`SELECT * FROM options WHERE market_id=?`, [marketId], (err2, options) => {
      res.render('edit_market', {
        user: currentUser(req),
        market,
        options
      });
    });
  });
});


// View / Bet
app.get('/markets/:id', (req, res) => {
  const id = req.params.id;

  db.get(`SELECT * FROM markets WHERE id=?`, [id], (err, market) => {
    if (!market) return res.sendStatus(404);

    db.all(`SELECT * FROM options WHERE market_id=?`, [id], (err2, options) => {
      db.all(`SELECT * FROM trades WHERE market_id=?`, [id], (err3, trades) => {

        const totalShares = options.reduce((sum, o) => sum + (o.shares || 0), 0);
        const probs = options.map(option => {
          const p = totalShares ? (option.shares || 0) / totalShares : 0;
          return { option, p };
        });
        const total = totalShares;

        let positions = {};
        const user = req.session.user;

        if (user) {
          trades
            .filter(t => t.user_id === user.id)
            .forEach(t => {
              positions[t.option_id] = (positions[t.option_id] || 0) + (t.shares || 0);
            });
        }

        // Load comments
        db.all(
          `SELECT c.*, u.username 
           FROM comments c 
           JOIN users u ON u.id=c.user_id 
           WHERE c.market_id=? 
           ORDER BY datetime(c.created_at) DESC`,
          [id],
          (err4, comments) => {

            // ---- STEP 5: Load Tags ----
            db.all(
              `SELECT tags.name
               FROM tags
               JOIN market_tags ON tags.id = market_tags.tag_id
               WHERE market_tags.market_id = ?`,
              [id],
              (err5, tags) => {

                res.render('market', {
                  user,
                  market,
                  options,
                  trades,
                  comments,
                  probs,
                  total,
                  positions,
                  tags    // <--- new
                });

              }
            );
          }
        );
      });
    });
  });
});





app.post('/markets/:id/bet', requireLogin, (req, res) => {
  const marketId = +req.params.id;     // MUST be first
  const optionId = +req.body.option_id;
  const amount = parseInt(req.body.amount || '0', 10);

  if (amount <= 0) {
    (req.session.flash ||= []).push({
      type: 'error',
      msg: 'Amount must be positive.'
    });
    return res.redirect(`/markets/${marketId}`);
  }

  // 🔒 Step 1: Check lock status
  db.get(`SELECT is_locked, is_resolved FROM markets WHERE id=?`, [marketId], (err, m) => {
    if (err || !m) return res.redirect(`/markets/${marketId}`);

    if (m.is_locked) {
      (req.session.flash ||= []).push({
        type: 'error',
        msg: 'This market is locked. No bets allowed.'
      });
      return res.redirect(`/markets/${marketId}`);
    }

    if (m.is_resolved) {
      (req.session.flash ||= []).push({
        type: 'error',
        msg: 'Market already resolved.'
      });
      return res.redirect(`/markets/${marketId}`);
    }

    // 🔥 Continue with ORIGINAL BET LOGIC
    db.get(`SELECT balance FROM users WHERE id=?`, [req.session.user.id], (e2, u) => {
      if (e2 || !u || u.balance < amount) {
        (req.session.flash ||= []).push({ type: 'error', msg: 'Insufficient balance.' });
        return res.redirect(`/markets/${marketId}`);
      }

      db.run(`UPDATE users SET balance = balance - ? WHERE id=?`,
        [amount, req.session.user.id],
        (e3) => {

          if (e3) return res.redirect(`/markets/${marketId}`);
          req.session.user.balance -= amount;

          db.run(`UPDATE options SET shares = shares + ? WHERE id=? AND market_id=?`,
            [amount, optionId, marketId],
            (e4) => {
              if (e4) return res.redirect(`/markets/${marketId}`);

              db.run(`INSERT INTO trades(user_id, market_id, option_id, amount) VALUES(?,?,?,?)`,
                [req.session.user.id, marketId, optionId, amount]);

              (req.session.flash ||= []).push({
                type: 'success',
                msg: `Placed ${amount} coins!`
              });

              res.redirect(`/markets/${marketId}`);
            });
        });
    });
  });
});




// Resolve (creator or admin)
// =====================
//  MARKET RESOLUTION
// =====================
app.post('/markets/:id/resolve', requireLogin, (req, res) => {
  const marketId = +req.params.id;
  const winningId = +req.body.winning_option_id;
  const uid = req.session.user.id;

  db.get(`SELECT * FROM markets WHERE id=?`, [marketId], (err, market) => {
    if (err || !market) return res.sendStatus(404);
    if (market.is_resolved) {
      (req.session.flash ||= []).push({ type: 'error', msg: 'Already resolved.' });
      return res.redirect(`/markets/${marketId}`);
    }
    if (!(market.creator_id === uid || req.session.user.is_admin)) {
      (req.session.flash ||= []).push({ type: 'error', msg: 'Only creator or admin can resolve.' });
      return res.redirect(`/markets/${marketId}`);
    }

    // Gather option data
    db.all(`SELECT id, shares FROM options WHERE market_id=?`, [marketId], (err2, opts) => {
      if (err2 || !opts.length) return res.sendStatus(500);
      const totalShares = opts.reduce((a, b) => a + (b.shares || 0), 0);
      const total = totalShares;
      const winningOpt = opts.find(o => o.id === winningId);
      const winningShares = winningOpt ? winningOpt.shares : 0;

      // Safety check
      if (totalShares <= 0) {
        db.run(`UPDATE markets SET is_resolved=1, resolved_option_id=? WHERE id=?`, [winningId, marketId], () => {
          (req.session.flash ||= []).push({ type: 'error', msg: 'No bets placed. Market resolved without payout.' });
          return res.redirect(`/markets/${marketId}`);
        });
        return;
      }

      

      if (winningShares <= 0) {
        // No one bet on winning option — no payouts
        db.run(`UPDATE markets SET is_resolved=1, resolved_option_id=? WHERE id=?`, [winningId, marketId], () => {
          (req.session.flash ||= []).push({ type: 'success', msg: 'Resolved. No winners — all coins lost to the pool.' });
          return res.redirect(`/markets/${marketId}`);
        });
        return;
      }

      // Calculate payouts
      db.all(
        `SELECT user_id, SUM(amount) as stake FROM trades WHERE market_id=? AND option_id=? GROUP BY user_id`,
        [marketId, winningId],
        (err3, winners) => {
          if (err3) return res.sendStatus(500);

          const payouts = winners.map(w => {
            const payout = Math.floor((w.stake / winningShares) * totalShares);
            return { user_id: w.user_id, payout };
          });

          // Wrap in transaction
          db.serialize(() => {
            db.run('BEGIN TRANSACTION');
            const stmt = db.prepare(`UPDATE users SET balance = balance + ? WHERE id=?`);
            payouts.forEach(p => stmt.run(p.payout, p.user_id));
            stmt.finalize();
            db.run(`UPDATE markets SET is_resolved=1, resolved_option_id=? WHERE id=?`, [winningId, marketId]);
            db.run('COMMIT', () => {
              // If the resolver is one of the winners, update their session balance
              if (payouts.some(p => p.user_id === uid)) {
                db.get(`SELECT balance FROM users WHERE id=?`, [uid], (e4, row) => {
                  if (!e4 && row) req.session.user.balance = row.balance;
                  (req.session.flash ||= []).push({ type: 'success', msg: 'Market resolved and payouts sent!' });
                  return res.redirect(`/markets/${marketId}`);
                });
              } else {
                (req.session.flash ||= []).push({ type: 'success', msg: 'Market resolved and payouts sent!' });
                return res.redirect(`/markets/${marketId}`);
              }
            });
          });
        }
      );
    });
  });
});

// ======================
//  COMMENTS
// ======================
app.post('/markets/:id/comments', requireLogin, (req, res) => {
  const marketId = +req.params.id;
  const content = (req.body.content || '').trim();
  const uid = req.session.user.id;
  if (!content) return res.redirect(`/markets/${marketId}`);

  db.run(`INSERT INTO comments (market_id, user_id, content) VALUES (?,?,?)`, [marketId, uid, content], (err) => {
    if (err) console.error(err);
    res.redirect(`/markets/${marketId}`);
  });
});

// ----- USER: Update Market -----
app.post('/markets/:id/edit', requireLogin, upload.single('image'), (req, res) => {
  const marketId = +req.params.id;
  const { title, description } = req.body;

  db.get(`SELECT * FROM markets WHERE id=?`, [marketId], (err, market) => {
    if (err || !market) return res.sendStatus(404);

    // Only creator or admin may update
    if (market.creator_id !== req.session.user.id && !req.session.user.is_admin) {
      req.session.flash = [{ type: 'error', msg: 'You cannot edit this market.' }];
      return res.redirect(`/markets/${marketId}`);
    }

    // Handle new image
    let newImage = market.image_filename;
    if (req.file) {
      newImage = 'uploads/' + req.file.filename;
    }

    db.run(
      `UPDATE markets 
       SET title=?, description=?, image_filename=? 
       WHERE id=?`,
      [title.trim(), description.trim(), newImage, marketId],
      (err2) => {
        if (err2) console.error(err2);

        req.session.flash = [{ type: 'success', msg: 'Market updated!' }];
        res.redirect(`/markets/${marketId}`);
      }
    );
  });
});

// Toggle lock/unlock (creator OR admin)
app.post('/markets/:id/toggle-lock', requireLogin, (req, res) => {
  const marketId = +req.params.id;
  const uid = req.session.user.id;

  db.get(`SELECT creator_id, is_locked FROM markets WHERE id=?`, [marketId], (err, m) => {
    if (err || !m) return res.redirect(`/markets/${marketId}`);

    // Only creator or admin can toggle lock
    if (m.creator_id !== uid && !req.session.user.is_admin) {
      (req.session.flash ||= []).push({ type: 'error', msg: 'Not authorized.' });
      return res.redirect(`/markets/${marketId}`);
    }

    const newVal = m.is_locked ? 0 : 1;

    db.run(`UPDATE markets SET is_locked=? WHERE id=?`, [newVal, marketId], () => {
      (req.session.flash ||= []).push({
        type: 'success',
        msg: newVal ? 'Market locked — betting disabled.' : 'Market unlocked — betting enabled.'
      });
      res.redirect(`/markets/${marketId}`);
    });
  });
});

// ======================
// NEWS PAGE
// ======================



app.get('/news', (req, res) => {

  // 1. Highest-volume markets
  const volumeQuery = `
    SELECT 
      m.id, 
      m.title, 
      m.created_at,
      m.is_resolved,
      SUM(t.amount) AS volume
    FROM markets m
    LEFT JOIN trades t ON t.market_id = m.id
    GROUP BY m.id
    ORDER BY volume DESC
    LIMIT 10;
  `;

  // 2. Recent bets
  const recentBetsQuery = `
    SELECT 
      t.user_id,
      u.username,
      t.market_id,
      m.title AS market_title,
      t.option_id,
      o.name AS option_name,
      t.amount,
      t.created_at
    FROM trades t
    JOIN users u ON u.id = t.user_id
    JOIN markets m ON m.id = t.market_id
    JOIN options o ON o.id = t.option_id
    ORDER BY datetime(t.created_at) DESC
    LIMIT 20;
  `;

  // 3. Recently created markets
  const newMarketsQuery = `
    SELECT id, title, created_at 
    FROM markets
    ORDER BY datetime(created_at) DESC
    LIMIT 10;
  `;

  db.all(volumeQuery, [], (err1, volumeMarkets) => {
    db.all(recentBetsQuery, [], (err2, recentBets) => {
      db.all(newMarketsQuery, [], (err3, newMarkets) => {
        res.render('news', {
          user: currentUser(req),
          volumeMarkets: volumeMarkets || [],
          recentBets: recentBets || [],
          newMarkets: newMarkets || []
        });
      });
    });
  });

});


// Admin
app.get('/admin', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM users ORDER BY id`, (e, users)=>{
    db.all(`SELECT * FROM markets ORDER BY datetime(created_at) DESC`, (e2, markets)=>{
      res.render('admin', { user: currentUser(req), users: users||[], markets: markets||[] });
    
    });
  });
});

app.post('/admin/set-balance', requireAdmin, (req, res) => {
  const uid = +req.body.user_id, bal = parseInt(req.body.balance||'0',10);
  db.run(`UPDATE users SET balance=? WHERE id=?`, [bal, uid], (e)=>{
    (req.session.flash ||= []).push({ type: e?'error':'success', msg: e?'Failed':'Balance updated.' });
    res.redirect('/admin');
  });
});
app.post('/admin/ban-toggle', requireAdmin, (req, res) => {
  const uid = +req.body.user_id;
  db.get(`SELECT is_banned FROM users WHERE id=?`, [uid], (e, row)=>{
    if (!row) return res.redirect('/admin');
    const nb = row.is_banned ? 0 : 1;
    db.run(`UPDATE users SET is_banned=? WHERE id=?`, [nb, uid], ()=>{
      (req.session.flash ||= []).push({ type: 'success', msg: nb? 'User banned.' : 'User unbanned.' });
      res.redirect('/admin');
    });
  });
});
app.post('/admin/remove-market', requireAdmin, (req, res) => {
  const mid = +req.body.market_id;
  db.run(`UPDATE markets SET is_removed=1 WHERE id=?`, [mid], ()=>{
    (req.session.flash ||= []).push({ type: 'success', msg: 'Market removed.' });
    res.redirect('/admin');
  });
});
app.post('/admin/edit-market', requireAdmin, (req, res) => {
  const mid = +req.body.market_id;
  const title = (req.body.title||'').trim();
  const description = (req.body.description||'').trim();
  db.run(`UPDATE markets SET title=COALESCE(NULLIF(?, ''), title), description=COALESCE(NULLIF(?, ''), description) WHERE id=?`,
    [title, description, mid], ()=>{
      (req.session.flash ||= []).push({ type: 'success', msg: 'Market updated.' });
      res.redirect('/admin');
    });
});
app.post('/admin/resolve-market', requireAdmin, (req, res) => {
  // reuse existing endpoint
  res.redirect(`/markets/${+req.body.market_id}`);
});


// ======================
//  USER PROFILE / HISTORY
// ======================
// ======================
//  USER PROFILE / HISTORY with stats
// ======================
app.get('/profile', requireLogin, (req, res) => {
  const uid = req.session.user.id;

  // Query for basic stats
  const statsQuery = `
    SELECT
      (SELECT COUNT(*) FROM trades WHERE user_id = ?) AS total_bets,
      (SELECT COUNT(*) FROM markets WHERE creator_id = ?) AS total_markets,
      (SELECT COALESCE(SUM(amount),0) FROM trades t
         JOIN markets m ON t.market_id = m.id
         WHERE t.user_id = ? AND m.is_resolved = 1 AND t.option_id = m.resolved_option_id) AS total_won,
      (SELECT balance FROM users WHERE id = ?) AS balance
  `;

  db.get(statsQuery, [uid, uid, uid, uid], (err, stats) => {
    if (err) stats = { total_bets: 0, total_markets: 0, total_won: 0, balance: 0 };

    const marketsQuery = `SELECT * FROM markets WHERE creator_id = ? ORDER BY datetime(created_at) DESC`;
    db.all(marketsQuery, [uid], (err1, markets) => {
      db.all(
        `SELECT t.*, m.title as market_title, o.name as option_name
         FROM trades t
         JOIN markets m ON t.market_id = m.id
         JOIN options o ON t.option_id = o.id
         WHERE t.user_id = ?
         ORDER BY datetime(t.created_at) DESC`,
        [uid],
        (err2, trades) => {
          res.render('profile', {
            user: currentUser(req),
            markets: markets || [],
            trades: trades || [],
            stats,
           
            title: 'My Profile',
          });
         
        }
      );
    });
  });
});

// ======================
// PUBLIC USER PROFILE
// ======================
// Public profile page
// ======================
// PUBLIC USER PROFILE PAGE
// ======================
app.get('/user/:id', (req, res) => {
  const uid = req.params.id;

  db.get(
    `SELECT id, username, balance FROM users WHERE id = ?`,
    [uid],
    (err, userRow) => {
      if (err || !userRow) {
        return res.status(404).render('error', {
          code: 404,
          message: 'User not found',
          user: currentUser(req)
        });
      }

      // Load user stats
      const statsQuery = `
        SELECT
          (SELECT COUNT(*) FROM trades WHERE user_id = ?) AS total_bets,
          (SELECT COUNT(*) FROM markets WHERE creator_id = ?) AS total_markets,
          (SELECT COALESCE(SUM(amount),0)
             FROM trades t JOIN markets m
             ON t.market_id = m.id
             WHERE t.user_id = ?
             AND m.is_resolved = 1
             AND t.option_id = m.resolved_option_id) AS total_won
      `;

      db.get(statsQuery, [uid, uid, uid], (err2, stats) => {
        if (err2) stats = { total_bets: 0, total_markets: 0, total_won: 0 };

        db.all(
          `SELECT t.*, m.title as market_title, o.name as option_name
           FROM trades t
           JOIN markets m ON t.market_id = m.id
           JOIN options o ON t.option_id = o.id
           WHERE t.user_id = ?
           ORDER BY datetime(t.created_at) DESC`,
          [uid],
          (err3, trades) => {
            res.render('public_profile', {
              profile: userRow,  // 👈 Public profile user
              stats,
              trades: trades || [],
              user: currentUser(req)  // logged-in user
            });
          }
        );
      });
    }
  );
});


// ======================
//  LEADERBOARD
// ======================
app.get('/leaderboard', (req, res) => {
const q = `SELECT id, username, balance FROM users WHERE is_banned = 0 ORDER BY balance DESC LIMIT 50`;

  db.all(q, [], (err, users) => {
    res.render('leaderboard', {
      user: currentUser(req),
      users: users || [],
   
      title: 'Leaderboard'
    });
   
  });
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      (req.session.flash ||= []).push({
        type: 'error',
        msg: 'Image too large. Max size is 2MB.'
      });
      return res.redirect('back');
    }
  }

  console.error(err);
  res.status(500).send("Server error");
});


// ---- Views ----
function renderFlash(req, res, next){ next(); }

// 404
app.use((req, res)=> res.status(404).render('error', { code: 404, message: 'Not found', user: currentUser(req) }));

app.listen(PORT, ()=> console.log(`California College of the Arts running on http://127.0.0.1:${PORT}`));
