require('dotenv').config();

const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 4000;
const BCRYPT_ROUNDS = 10;

// ═══════════════════════════════════════
//  1. CONFIG
// ═══════════════════════════════════════
app.set('trust proxy', 1);

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = path.join(__dirname, 'public/uploads');
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => cb(null, Date.now() + '-' + Math.round(Math.random() * 1e9) + path.extname(file.originalname))
});
const upload = multer({ storage });

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ═══════════════════════════════════════
//  2. DATABASE
// ═══════════════════════════════════════
const db = mysql.createPool({
    host: process.env.MYSQLHOST, user: process.env.MYSQLUSER,
    password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQL_DATABASE || process.env.MYSQLDATABASE,
    port: process.env.MYSQLPORT,
    waitForConnections: true, connectionLimit: 10, queueLimit: 0
});

db.query('SELECT 1', (err) => {
    if (err) return console.error('❌ DB error:', err.message);
    console.log('✅ Connected to MySQL');
    createTables();
});

function createTables() {
    // Admins
    db.query(`CREATE TABLE IF NOT EXISTS admins (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL
    )`, () => {
        db.query("SELECT * FROM admins WHERE username='admin'", (e, r) => {
            if (!e && r.length === 0) db.query("INSERT INTO admins (username,password) VALUES ('admin','123456')");
        });
    });

    // Settings
    db.query(`CREATE TABLE IF NOT EXISTS settings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        titre VARCHAR(500) DEFAULT 'انتخابات فرع الرابطة في مراكش 2026/2027',
        logo_url VARCHAR(500) DEFAULT NULL,
        date_election DATE DEFAULT NULL,
        vote_ouvert TINYINT(1) DEFAULT 1,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )`, () => {
        db.query("SELECT * FROM settings WHERE id=1", (e, r) => {
            if (!e && r.length === 0) db.query("INSERT INTO settings (id,titre) VALUES (1,'انتخابات فرع الرابطة في مراكش 2026/2027')");
        });
    });

    // Listes
    db.query(`CREATE TABLE IF NOT EXISTS listes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nom VARCHAR(255) NOT NULL,
        slogan VARCHAR(500),
        logo_url VARCHAR(500),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    // Candidats
    db.query(`CREATE TABLE IF NOT EXISTS candidats (
        id INT AUTO_INCREMENT PRIMARY KEY,
        liste_id INT NOT NULL,
        nom VARCHAR(255) NOT NULL,
        role VARCHAR(255) DEFAULT 'عضو',
        photo_url VARCHAR(500),
        ordre INT DEFAULT 0,
        FOREIGN KEY (liste_id) REFERENCES listes(id) ON DELETE CASCADE
    )`);

    // ─── Électeurs ───
    // password      : mot de passe hashé (bcrypt)
    // is_registered : 1 = compte créé via le formulaire d'inscription
    // is_eligible   : 1 = autorisé à voter (set by admin), 0 = en attente
    // has_voted     : 1 = a voté
    db.query(`CREATE TABLE IF NOT EXISTS electeurs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nom VARCHAR(255) DEFAULT NULL,
        telephone VARCHAR(20) NOT NULL UNIQUE,
        password VARCHAR(255) DEFAULT NULL,
        is_registered TINYINT(1) DEFAULT 0,
        is_eligible   TINYINT(1) DEFAULT 0,
        has_voted TINYINT(1) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`, () => {
        // Migration for existing databases
        db.query("ALTER TABLE electeurs ADD COLUMN IF NOT EXISTS password VARCHAR(255) DEFAULT NULL", () => { });
        db.query("ALTER TABLE electeurs ADD COLUMN IF NOT EXISTS is_registered TINYINT(1) DEFAULT 0", () => { });
        db.query("ALTER TABLE electeurs ADD COLUMN IF NOT EXISTS is_eligible TINYINT(1) DEFAULT 0", () => { });
    });

    // Votes
    db.query(`CREATE TABLE IF NOT EXISTS votes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        electeur_id INT NOT NULL UNIQUE,
        liste_id INT NOT NULL,
        voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (electeur_id) REFERENCES electeurs(id) ON DELETE CASCADE,
        FOREIGN KEY (liste_id) REFERENCES listes(id) ON DELETE CASCADE
    )`);
}

// ═══════════════════════════════════════
//  3. SESSION
// ═══════════════════════════════════════
const sessionStore = new MySQLStore({}, db);
const isProduction = process.env.NODE_ENV === 'production';

app.use(session({
    key: 'election_session',
    secret: process.env.SESSION_SECRET || 'election_secret_2026_marrakech',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: isProduction, sameSite: isProduction ? 'none' : 'lax', maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(express.static(path.join(__dirname, 'public')));

function isAuthenticated(req, res, next) {
    if (req.session && req.session.isAdmin) return next();
    res.status(401).json({ success: false, message: 'Non autorisé' });
}

// ═══════════════════════════════════════
//  4. PUBLIC — AUTH ÉLECTEURS
// ═══════════════════════════════════════

/**
 * INSCRIPTION — n'importe qui peut créer un compte.
 * Si le numéro existe déjà dans la table electeurs (pré-chargé par admin) → crée le compte.
 * Si le numéro n'existe pas → crée une nouvelle ligne (is_eligible=0, admin devra valider).
 */
app.post('/api/inscription', (req, res) => {
    const { telephone, password, password_confirm } = req.body;
    if (!telephone || !password) return res.status(400).json({ success: false, message: 'البيانات غير مكتملة' });
    if (password !== password_confirm) return res.json({ success: false, message: 'كلمتا المرور غير متطابقتين' });
    if (password.length < 4) return res.json({ success: false, message: 'كلمة المرور يجب أن تكون 4 أحرف على الأقل' });

    const cleaned = telephone.replace(/\s/g, '');

    db.query("SELECT * FROM electeurs WHERE telephone = ?", [cleaned], (err, results) => {
        if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });

        if (results.length > 0) {
            // Numéro connu
            const electeur = results[0];
            if (electeur.is_registered) return res.json({ success: false, message: 'هذا الحساب مسجل مسبقاً، يرجى تسجيل الدخول' });

            bcrypt.hash(password, BCRYPT_ROUNDS, (hErr, hash) => {
                if (hErr) return res.status(500).json({ success: false, message: 'Erreur hashage' });
                db.query("UPDATE electeurs SET password=?, is_registered=1 WHERE id=?", [hash, electeur.id], (err) => {
                    if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
                    req.session.electeur = { id: electeur.id, nom: electeur.nom || cleaned, telephone: cleaned, has_voted: electeur.has_voted, is_eligible: electeur.is_eligible };
                    res.json({ success: true, message: `تم التسجيل بنجاح! مرحباً`, electeur: { nom: electeur.nom || cleaned, has_voted: electeur.has_voted } });
                });
            });

        } else {
            // Numéro inconnu → créer un nouveau compte (is_eligible=0 par défaut)
            bcrypt.hash(password, BCRYPT_ROUNDS, (hErr, hash) => {
                if (hErr) return res.status(500).json({ success: false, message: 'Erreur hashage' });
                db.query("INSERT INTO electeurs (telephone, password, is_registered, is_eligible) VALUES (?,?,1,0)", [cleaned, hash], (err, result) => {
                    if (err) return res.status(500).json({ success: false, message: 'Erreur lors de l\'inscription' });
                    req.session.electeur = { id: result.insertId, nom: cleaned, telephone: cleaned, has_voted: 0, is_eligible: 0 };
                    res.json({ success: true, message: 'تم إنشاء الحساب! سيتم مراجعة طلبك من طرف الإدارة', electeur: { nom: cleaned, has_voted: 0 } });
                });
            });
        }
    });
});

/**
 * CONNEXION
 */
app.post('/api/connexion', (req, res) => {
    const { telephone, password } = req.body;
    if (!telephone || !password) return res.status(400).json({ success: false, message: 'البيانات غير مكتملة' });

    const cleaned = telephone.replace(/\s/g, '');

    db.query("SELECT * FROM electeurs WHERE telephone = ?", [cleaned], (err, results) => {
        if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
        if (results.length === 0) return res.json({ success: false, message: 'هذا الرقم غير مسجل، يرجى إنشاء حساب أولاً' });

        const electeur = results[0];
        if (!electeur.is_registered || !electeur.password) return res.json({ success: false, message: 'الحساب غير مفعل، يرجى إنشاء حساب أولاً' });

        bcrypt.compare(password, electeur.password, (err, match) => {
            if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
            if (!match) return res.json({ success: false, message: 'كلمة المرور غير صحيحة' });

            req.session.electeur = { id: electeur.id, nom: electeur.nom || cleaned, telephone: cleaned, has_voted: electeur.has_voted, is_eligible: electeur.is_eligible };
            if (electeur.has_voted) return res.json({ success: true, already_voted: true, electeur: { nom: electeur.nom || cleaned } });
            res.json({ success: true, already_voted: false, electeur: { nom: electeur.nom || cleaned } });
        });
    });
});

// ═══════════════════════════════════════
//  5. PUBLIC — LISTES, VOTE, RÉSULTATS
// ═══════════════════════════════════════

app.get('/api/listes', (req, res) => {
    db.query("SELECT vote_ouvert FROM settings WHERE id=1", (err, s) => {
        const voteOuvert = s && s[0] ? s[0].vote_ouvert : 1;

        db.query("SELECT * FROM listes ORDER BY id", (err, listes) => {
            if (err) return res.status(500).json({ error: err });
            db.query("SELECT * FROM candidats ORDER BY liste_id, ordre", (err, candidats) => {
                if (err) return res.status(500).json({ error: err });
                res.json({
                    vote_ouvert: voteOuvert,
                    listes: listes.map(l => ({ ...l, candidats: candidats.filter(c => c.liste_id === l.id) }))
                });
            });
        });
    });
});

app.post('/api/voter', (req, res) => {
    if (!req.session.electeur) return res.status(401).json({ success: false, message: 'يرجى تسجيل الدخول أولاً' });
    const electeur = req.session.electeur;
    const { liste_id } = req.body;
    if (!liste_id) return res.status(400).json({ success: false, message: 'يرجى اختيار لائحة' });

    db.query("SELECT has_voted, is_eligible FROM electeurs WHERE id=?", [electeur.id], (err, results) => {
        if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
        if (results[0].has_voted) return res.json({ success: false, message: 'لقد أدليت بصوتك مسبقاً' });
        if (!results[0].is_eligible) return res.json({ success: false, message: 'حسابك لم يتم تفعيله بعد من طرف الإدارة' });

        db.query("SELECT vote_ouvert FROM settings WHERE id=1", (err, s) => {
            if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
            if (s.length && !s[0].vote_ouvert) return res.json({ success: false, message: 'التصويت مغلق حالياً' });

            db.query("INSERT INTO votes (electeur_id, liste_id) VALUES (?,?)", [electeur.id, liste_id], (err) => {
                if (err) return res.status(500).json({ success: false, message: 'Erreur lors du vote' });
                db.query("UPDATE electeurs SET has_voted=1 WHERE id=?", [electeur.id], () => {
                    req.session.electeur.has_voted = 1;
                    res.json({ success: true, message: 'لقد أدليت بصوتك بنجاح! شكراً لمشاركتك' });
                });
            });
        });
    });
});

app.get('/api/resultats', (req, res) => {
    db.query("SELECT l.id, l.nom, l.logo_url, COUNT(v.id) as votes FROM listes l LEFT JOIN votes v ON l.id=v.liste_id GROUP BY l.id ORDER BY votes DESC", (err, results) => {
        if (err) return res.status(500).json({ error: err });
        db.query("SELECT COUNT(*) as total FROM electeurs WHERE is_eligible=1", (e, t) => {
            db.query("SELECT COUNT(*) as voted FROM electeurs WHERE has_voted=1", (e2, v) => {
                res.json({ listes: results, total_electeurs: t[0].total, total_votes: v[0].voted });
            });
        });
    });
});

app.get('/api/settings', (req, res) => {
    db.query("SELECT titre, logo_url, date_election, vote_ouvert FROM settings WHERE id=1", (err, r) => {
        if (err) return res.status(500).json({ error: err });
        res.json(r[0] || {});
    });
});

// ═══════════════════════════════════════
//  6. ADMIN AUTH
// ═══════════════════════════════════════
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false });
    db.query("SELECT * FROM admins WHERE username=? AND password=?", [username, password], (err, r) => {
        if (err || r.length === 0) return res.json({ success: false, message: 'Identifiants incorrects' });
        req.session.isAdmin = true; req.session.adminUser = r[0].username;
        res.json({ success: true });
    });
});

app.get('/api/check-auth', (req, res) => res.json({ authenticated: !!(req.session && req.session.isAdmin) }));
app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });

// ═══════════════════════════════════════
//  7. ADMIN PAGES (PROTECTED)
// ═══════════════════════════════════════
app.get('/admin.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'prive', 'admin.html')));
app.get('/gestion-listes.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'prive', 'gestion-listes.html')));

// ═══════════════════════════════════════
//  8. ADMIN API — LISTES
// ═══════════════════════════════════════
app.get('/api/admin/listes', isAuthenticated, (req, res) => {
    db.query("SELECT * FROM listes ORDER BY id", (err, listes) => {
        db.query("SELECT * FROM candidats ORDER BY liste_id, ordre", (err, candidats) => {
            res.json(listes.map(l => ({ ...l, candidats: candidats.filter(c => c.liste_id === l.id) })));
        });
    });
});

app.post('/api/admin/listes', isAuthenticated, upload.single('logo'), (req, res) => {
    const { nom, slogan } = req.body;
    if (!nom) return res.status(400).json({ success: false });
    const logo_url = req.file ? `/uploads/${req.file.filename}` : null;
    db.query("INSERT INTO listes (nom,slogan,logo_url) VALUES (?,?,?)", [nom, slogan, logo_url], (err, r) => {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true, id: r.insertId });
    });
});

app.delete('/api/admin/listes/:id', isAuthenticated, (req, res) => {
    db.query("DELETE FROM listes WHERE id=?", [req.params.id], (err) => res.json({ success: !err }));
});

// ═══════════════════════════════════════
//  9. ADMIN API — CANDIDATS
// ═══════════════════════════════════════
app.post('/api/admin/candidats', isAuthenticated, upload.single('photo'), (req, res) => {
    const { liste_id, nom, role, ordre } = req.body;
    if (!liste_id || !nom) return res.status(400).json({ success: false });
    const photo_url = req.file ? `/uploads/${req.file.filename}` : null;
    db.query("INSERT INTO candidats (liste_id,nom,role,photo_url,ordre) VALUES (?,?,?,?,?)", [liste_id, nom, role || 'عضو', photo_url, ordre || 0], (err, r) => {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true, id: r.insertId });
    });
});

app.delete('/api/admin/candidats/:id', isAuthenticated, (req, res) => {
    db.query("DELETE FROM candidats WHERE id=?", [req.params.id], (err) => res.json({ success: !err }));
});

// ═══════════════════════════════════════
//  10. ADMIN API — SETTINGS
// ═══════════════════════════════════════
app.post('/api/admin/settings', isAuthenticated, upload.single('logo'), (req, res) => {
    const { titre, date_election, vote_ouvert } = req.body;
    const logo_url = req.file ? `/uploads/${req.file.filename}` : undefined;
    let q = "UPDATE settings SET titre=?, date_election=?, vote_ouvert=?";
    let p = [titre, date_election || null, vote_ouvert === undefined ? 1 : vote_ouvert];
    if (logo_url) { q += ", logo_url=?"; p.push(logo_url); }
    q += " WHERE id=1";
    db.query(q, p, (err) => res.json({ success: !err }));
});

app.post('/api/admin/toggle-vote', isAuthenticated, (req, res) => {
    db.query("UPDATE settings SET vote_ouvert = NOT vote_ouvert WHERE id=1", () => {
        db.query("SELECT vote_ouvert FROM settings WHERE id=1", (err, r) => res.json({ success: true, vote_ouvert: r[0].vote_ouvert }));
    });
});

// ═══════════════════════════════════════
//  11. ADMIN API — STATS & ÉLECTEURS
// ═══════════════════════════════════════
app.get('/api/admin/stats', isAuthenticated, (req, res) => {
    db.query("SELECT COUNT(*) as total FROM electeurs WHERE is_eligible=1", (e, t) => {
        db.query("SELECT COUNT(*) as voted FROM electeurs WHERE has_voted=1", (e, v) => {
            db.query("SELECT COUNT(*) as listes FROM listes", (e, l) => {
                db.query("SELECT COUNT(*) as pending FROM electeurs WHERE is_registered=1 AND is_eligible=0", (e, p) => {
                    res.json({
                        total_electeurs: t[0].total, total_votes: v[0].voted,
                        total_listes: l[0].listes, pending_approval: p[0].pending,
                        taux_participation: t[0].total > 0 ? Math.round((v[0].voted / t[0].total) * 100) : 0
                    });
                });
            });
        });
    });
});

app.get('/api/admin/electeurs', isAuthenticated, (req, res) => {
    db.query(`SELECT e.id, e.nom, e.telephone, e.is_registered, e.is_eligible, e.has_voted, e.created_at,
              v.liste_id, l.nom as liste_nom
              FROM electeurs e
              LEFT JOIN votes v ON e.id=v.electeur_id
              LEFT JOIN listes l ON v.liste_id=l.id
              ORDER BY e.created_at DESC`, (err, r) => {
        if (err) return res.status(500).json({ error: err });
        res.json(r);
    });
});

// Approuver / désapprouver un électeur
app.post('/api/admin/electeurs/:id/toggle-eligible', isAuthenticated, (req, res) => {
    db.query("UPDATE electeurs SET is_eligible = NOT is_eligible WHERE id=?", [req.params.id], () => {
        db.query("SELECT is_eligible FROM electeurs WHERE id=?", [req.params.id], (err, r) => {
            res.json({ success: true, is_eligible: r[0].is_eligible });
        });
    });
});
app.get('/pv-generator.html', isAuthenticated, (req, res) =>
    res.sendFile(path.join(__dirname, 'public', 'pv-generator.html')));
// ═══════════════════════════════════════
//  12. START
// ═══════════════════════════════════════
app.listen(PORT, () => console.log(`🗳️  Serveur démarré sur http://localhost:${PORT}`));