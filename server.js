require('dotenv').config();

const express = require('express');
const { Pool } = require('pg'); // PostgreSQL
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session); // Session PostgreSQL
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
//  2. DATABASE (Supabase / Postgres)
// ═══════════════════════════════════════
const db = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Nécessaire pour Supabase
});

db.query('SELECT 1', (err) => {
    if (err) return console.error('❌ DB error:', err.message);
    console.log('✅ Connected to PostgreSQL (Supabase)');
    createTables();
});

function createTables() {
    // Session Table
    db.query(`CREATE TABLE IF NOT EXISTS "session" (
        "sid" varchar NOT NULL COLLATE "default",
        "sess" json NOT NULL,
        "expire" timestamp(6) NOT NULL,
        CONSTRAINT "session_pkey" PRIMARY KEY ("sid")
    )`);

    // Admins
    db.query(`CREATE TABLE IF NOT EXISTS admins (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL
    )`, () => {
        db.query("SELECT * FROM admins WHERE username='admin'", (e, r) => {
            if (!e && r.rows.length === 0) db.query("INSERT INTO admins (username,password) VALUES ('admin','123456')");
        });
    });

    // Settings
    db.query(`CREATE TABLE IF NOT EXISTS settings (
        id SERIAL PRIMARY KEY,
        titre VARCHAR(500) DEFAULT 'انتخابات فرع الرابطة في مراكش 2026/2027',
        logo_url VARCHAR(500) DEFAULT NULL,
        date_election DATE DEFAULT NULL,
        vote_ouvert BOOLEAN DEFAULT true,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`, () => {
        db.query("SELECT * FROM settings WHERE id=1", (e, r) => {
            if (!e && r.rows.length === 0) db.query("INSERT INTO settings (id,titre) VALUES (1,'انتخابات فرع الرابطة في مراكش 2026/2027')");
        });
    });

    // Listes
    db.query(`CREATE TABLE IF NOT EXISTS listes (
        id SERIAL PRIMARY KEY,
        nom VARCHAR(255) NOT NULL,
        slogan VARCHAR(500),
        logo_url VARCHAR(500),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    // Candidats
    db.query(`CREATE TABLE IF NOT EXISTS candidats (
        id SERIAL PRIMARY KEY,
        liste_id INT NOT NULL,
        nom VARCHAR(255) NOT NULL,
        role VARCHAR(255) DEFAULT 'عضو',
        photo_url VARCHAR(500),
        ordre INT DEFAULT 0,
        FOREIGN KEY (liste_id) REFERENCES listes(id) ON DELETE CASCADE
    )`);

    // Électeurs (SANS la colonne nom)
    db.query(`CREATE TABLE IF NOT EXISTS electeurs (
        id SERIAL PRIMARY KEY,
        telephone VARCHAR(20) NOT NULL UNIQUE,
        password VARCHAR(255) DEFAULT NULL,
        is_registered BOOLEAN DEFAULT false,
        is_eligible   BOOLEAN DEFAULT false,
        has_voted BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);

    // Votes
    db.query(`CREATE TABLE IF NOT EXISTS votes (
        id SERIAL PRIMARY KEY,
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
const isProduction = process.env.NODE_ENV === 'production';

app.use(session({
    key: 'election_session',
    secret: process.env.SESSION_SECRET || 'election_secret_2026_marrakech',
    store: new pgSession({ pool: db, tableName: 'session' }),
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
app.post('/api/inscription', (req, res) => {
    const { telephone, password, password_confirm } = req.body;
    if (!telephone || !password) return res.status(400).json({ success: false, message: 'البيانات غير مكتملة' });
    if (password !== password_confirm) return res.json({ success: false, message: 'كلمتا المرور غير متطابقتين' });
    if (password.length < 4) return res.json({ success: false, message: 'كلمة المرور يجب أن تكون 4 أحرف على الأقل' });

    const cleaned = telephone.replace(/\s/g, '');

    db.query("SELECT * FROM electeurs WHERE telephone = $1", [cleaned], (err, result) => {
        if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });

        if (result.rows.length > 0) {
            const electeur = result.rows[0];
            if (electeur.is_registered) return res.json({ success: false, message: 'هذا الحساب مسجل مسبقاً، يرجى تسجيل الدخول' });

            bcrypt.hash(password, BCRYPT_ROUNDS, (hErr, hash) => {
                if (hErr) return res.status(500).json({ success: false, message: 'Erreur hashage' });
                db.query("UPDATE electeurs SET password=$1, is_registered=true WHERE id=$2", [hash, electeur.id], (err) => {
                    if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
                    req.session.electeur = { id: electeur.id, telephone: cleaned, has_voted: electeur.has_voted, is_eligible: electeur.is_eligible };
                    res.json({ success: true, message: `تم التسجيل بنجاح! مرحباً`, electeur: { telephone: cleaned, has_voted: electeur.has_voted } });
                });
            });
        } else {
            bcrypt.hash(password, BCRYPT_ROUNDS, (hErr, hash) => {
                if (hErr) return res.status(500).json({ success: false, message: 'Erreur hashage' });
                db.query("INSERT INTO electeurs (telephone, password, is_registered, is_eligible) VALUES ($1,$2,true,false) RETURNING id", [cleaned, hash], (err, r) => {
                    if (err) return res.status(500).json({ success: false, message: 'Erreur lors de l\'inscription' });
                    req.session.electeur = { id: r.rows[0].id, telephone: cleaned, has_voted: false, is_eligible: false };
                    res.json({ success: true, message: 'تم إنشاء الحساب! سيتم مراجعة طلبك من طرف الإدارة', electeur: { telephone: cleaned, has_voted: false } });
                });
            });
        }
    });
});

app.post('/api/connexion', (req, res) => {
    const { telephone, password } = req.body;
    if (!telephone || !password) return res.status(400).json({ success: false, message: 'البيانات غير مكتملة' });

    const cleaned = telephone.replace(/\s/g, '');

    db.query("SELECT * FROM electeurs WHERE telephone = $1", [cleaned], (err, result) => {
        if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
        if (result.rows.length === 0) return res.json({ success: false, message: 'هذا الرقم غير مسجل، يرجى إنشاء حساب أولاً' });

        const electeur = result.rows[0];
        if (!electeur.is_registered || !electeur.password) return res.json({ success: false, message: 'الحساب غير مفعل، يرجى إنشاء حساب أولاً' });

        bcrypt.compare(password, electeur.password, (err, match) => {
            if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
            if (!match) return res.json({ success: false, message: 'كلمة المرور غير صحيحة' });

            req.session.electeur = { id: electeur.id, telephone: cleaned, has_voted: electeur.has_voted, is_eligible: electeur.is_eligible };
            if (electeur.has_voted) return res.json({ success: true, already_voted: true, electeur: { telephone: cleaned } });
            res.json({ success: true, already_voted: false, electeur: { telephone: cleaned } });
        });
    });
});

// ═══════════════════════════════════════
//  5. PUBLIC — LISTES, VOTE, RÉSULTATS
// ═══════════════════════════════════════
app.get('/api/listes', (req, res) => {
    db.query("SELECT vote_ouvert FROM settings WHERE id=1", (err, s) => {
        const voteOuvert = (s && s.rows && s.rows[0]) ? s.rows[0].vote_ouvert : true;

        db.query("SELECT * FROM listes ORDER BY id", (err, listesResult) => {
            if (err) return res.status(500).json({ error: err });
            db.query("SELECT * FROM candidats ORDER BY liste_id, ordre", (err, candidatsResult) => {
                if (err) return res.status(500).json({ error: err });
                const listes = listesResult.rows;
                const candidats = candidatsResult.rows;
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

    db.query("SELECT has_voted, is_eligible FROM electeurs WHERE id=$1", [electeur.id], (err, result) => {
        if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
        if (result.rows[0].has_voted) return res.json({ success: false, message: 'لقد أدليت بصوتك مسبقاً' });
        if (!result.rows[0].is_eligible) return res.json({ success: false, message: 'حسابك لم يتم تفعيله بعد من طرف الإدارة' });

        db.query("SELECT vote_ouvert FROM settings WHERE id=1", (err, s) => {
            if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
            if (s.rows.length && !s.rows[0].vote_ouvert) return res.json({ success: false, message: 'التصويت مغلق حالياً' });

            db.query("INSERT INTO votes (electeur_id, liste_id) VALUES ($1,$2)", [electeur.id, liste_id], (err) => {
                if (err) return res.status(500).json({ success: false, message: 'Erreur lors du vote' });
                db.query("UPDATE electeurs SET has_voted=true WHERE id=$1", [electeur.id], () => {
                    req.session.electeur.has_voted = true;
                    res.json({ success: true, message: 'لقد أدليت بصوتك بنجاح! شكراً لمشاركتك' });
                });
            });
        });
    });
});

app.get('/api/resultats', (req, res) => {
    db.query("SELECT l.id, l.nom, l.logo_url, COUNT(v.id)::int as votes FROM listes l LEFT JOIN votes v ON l.id=v.liste_id GROUP BY l.id ORDER BY votes DESC", (err, result) => {
        if (err) return res.status(500).json({ error: err });
        db.query("SELECT COUNT(*)::int as total FROM electeurs WHERE is_eligible=true", (e, t) => {
            db.query("SELECT COUNT(*)::int as voted FROM electeurs WHERE has_voted=true", (e2, v) => {
                res.json({ listes: result.rows, total_electeurs: t.rows[0].total, total_votes: v.rows[0].voted });
            });
        });
    });
});

app.get('/api/settings', (req, res) => {
    db.query("SELECT titre, logo_url, date_election, vote_ouvert FROM settings WHERE id=1", (err, r) => {
        if (err) return res.status(500).json({ error: err });
        res.json(r.rows[0] || {});
    });
});

// ═══════════════════════════════════════
//  6. ADMIN AUTH
// ═══════════════════════════════════════
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false });
    db.query("SELECT * FROM admins WHERE username=$1 AND password=$2", [username, password], (err, r) => {
        if (err || r.rows.length === 0) return res.json({ success: false, message: 'Identifiants incorrects' });
        req.session.isAdmin = true; req.session.adminUser = r.rows[0].username;
        res.json({ success: true });
    });
});

app.get('/api/check-auth', (req, res) => res.json({ authenticated: !!(req.session && req.session.isAdmin) }));
app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });

// ═══════════════════════════════════════
//  7. ADMIN PAGES
// ═══════════════════════════════════════
app.get('/admin.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'prive', 'admin.html')));
app.get('/gestion-listes.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'prive', 'gestion-listes.html')));

// ═══════════════════════════════════════
//  8. ADMIN API — LISTES
// ═══════════════════════════════════════
app.get('/api/admin/listes', isAuthenticated, (req, res) => {
    db.query("SELECT * FROM listes ORDER BY id", (err, listesResult) => {
        if (err) return res.status(500).json({ error: err.message });
        db.query("SELECT * FROM candidats ORDER BY liste_id, ordre", (err, candidatsResult) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(listesResult.rows.map(l => ({ ...l, candidats: candidatsResult.rows.filter(c => c.liste_id === l.id) })));
        });
    });
});

app.post('/api/admin/listes', isAuthenticated, upload.single('logo'), (req, res) => {
    const { nom, slogan } = req.body;
    if (!nom) return res.status(400).json({ success: false });
    const logo_url = req.file ? `/uploads/${req.file.filename}` : null;
    db.query("INSERT INTO listes (nom,slogan,logo_url) VALUES ($1,$2,$3) RETURNING id", [nom, slogan, logo_url], (err, r) => {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true, id: r.rows[0].id });
    });
});

app.delete('/api/admin/listes/:id', isAuthenticated, (req, res) => {
    db.query("DELETE FROM listes WHERE id=$1", [req.params.id], (err) => res.json({ success: !err }));
});

// ═══════════════════════════════════════
//  9. ADMIN API — CANDIDATS
// ═══════════════════════════════════════
app.post('/api/admin/candidats', isAuthenticated, upload.single('photo'), (req, res) => {
    const { liste_id, nom, role, ordre } = req.body;
    if (!liste_id || !nom) return res.status(400).json({ success: false });
    const photo_url = req.file ? `/uploads/${req.file.filename}` : null;
    db.query("INSERT INTO candidats (liste_id,nom,role,photo_url,ordre) VALUES ($1,$2,$3,$4,$5) RETURNING id", [liste_id, nom, role || 'عضو', photo_url, ordre || 0], (err, r) => {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true, id: r.rows[0].id });
    });
});

app.delete('/api/admin/candidats/:id', isAuthenticated, (req, res) => {
    db.query("DELETE FROM candidats WHERE id=$1", [req.params.id], (err) => res.json({ success: !err }));
});

// ═══════════════════════════════════════
//  10. ADMIN API — SETTINGS
// ═══════════════════════════════════════
app.post('/api/admin/settings', isAuthenticated, upload.single('logo'), (req, res) => {
    const { titre, date_election, vote_ouvert } = req.body;
    const logo_url = req.file ? `/uploads/${req.file.filename}` : undefined;
    let q = "UPDATE settings SET titre=$1, date_election=$2, vote_ouvert=$3";
    let p = [titre, date_election || null, vote_ouvert === undefined ? true : vote_ouvert === 'true' || vote_ouvert === true];
    if (logo_url) { q += ", logo_url=$4"; p.push(logo_url); }
    q += " WHERE id=1";
    db.query(q, p, (err) => res.json({ success: !err }));
});

app.post('/api/admin/toggle-vote', isAuthenticated, (req, res) => {
    db.query("UPDATE settings SET vote_ouvert = NOT vote_ouvert WHERE id=1", () => {
        db.query("SELECT vote_ouvert FROM settings WHERE id=1", (err, r) => res.json({ success: true, vote_ouvert: r.rows[0].vote_ouvert }));
    });
});

// ═══════════════════════════════════════
//  11. ADMIN API — STATS & ÉLECTEURS
// ═══════════════════════════════════════
app.get('/api/admin/stats', isAuthenticated, (req, res) => {
    db.query("SELECT COUNT(*)::int as total FROM electeurs WHERE is_eligible=true", (e, t) => {
        db.query("SELECT COUNT(*)::int as voted FROM electeurs WHERE has_voted=true", (e, v) => {
            db.query("SELECT COUNT(*)::int as listes FROM listes", (e, l) => {
                db.query("SELECT COUNT(*)::int as pending FROM electeurs WHERE is_registered=true AND is_eligible=false", (e, p) => {
                    const total = t.rows[0].total;
                    const voted = v.rows[0].voted;
                    res.json({
                        total_electeurs: total,
                        total_votes: voted,
                        total_listes: l.rows[0].listes,
                        pending_approval: p.rows[0].pending,
                        taux_participation: total > 0 ? Math.round((voted / total) * 100) : 0
                    });
                });
            });
        });
    });
});

app.get('/api/admin/electeurs', isAuthenticated, (req, res) => {
    db.query(`SELECT e.id, e.telephone, e.is_registered, e.is_eligible, e.has_voted, e.created_at,
              v.liste_id, l.nom as liste_nom
              FROM electeurs e
              LEFT JOIN votes v ON e.id=v.electeur_id
              LEFT JOIN listes l ON v.liste_id=l.id
              ORDER BY e.created_at DESC`, (err, r) => {
        if (err) return res.status(500).json({ error: err });
        res.json(r.rows);
    });
});

app.post('/api/admin/electeurs/:id/toggle-eligible', isAuthenticated, (req, res) => {
    db.query("UPDATE electeurs SET is_eligible = NOT is_eligible WHERE id=$1", [req.params.id], () => {
        db.query("SELECT is_eligible FROM electeurs WHERE id=$1", [req.params.id], (err, r) => {
            res.json({ success: true, is_eligible: r.rows[0].is_eligible });
        });
    });
});

// ═══════════════════════════════════════
//  11.5 ADMIN API — GÉNÉRATION DU PV
// ═══════════════════════════════════════
app.get('/api/admin/pv-data', isAuthenticated, (req, res) => {
    db.query("SELECT titre, logo_url, date_election FROM settings WHERE id=1", (err, settings) => {
        if (err) return res.status(500).json({ error: "Erreur settings" });

        db.query("SELECT COUNT(*)::int as inscrits FROM electeurs WHERE is_eligible=true", (err, inscrits) => {
            db.query("SELECT COUNT(*)::int as votants FROM electeurs WHERE has_voted=true", (err, votants) => {
                db.query(`SELECT l.id, l.nom, COUNT(v.id)::int as voix 
                          FROM listes l 
                          LEFT JOIN votes v ON l.id = v.liste_id 
                          GROUP BY l.id 
                          ORDER BY voix DESC`, (err, listes) => {

                    const totalVotants = votants.rows[0].votants;
                    const listesArray = listes.rows;

                    const listesResultats = listesArray.map(l => ({
                        ...l,
                        pourcentage: totalVotants > 0 ? ((l.voix / totalVotants) * 100).toFixed(2) : "0.00"
                    }));

                    const winningListId = listesArray.length > 0 ? listesResultats[0].id : null;

                    db.query("SELECT nom, role FROM candidats WHERE liste_id=$1 ORDER BY ordre", [winningListId], (err, candidats_gagnants) => {
                        res.json({
                            settings: settings.rows[0] || {},
                            stats: {
                                inscrits: inscrits.rows[0].inscrits,
                                votants: totalVotants,
                                taux_participation: inscrits.rows[0].inscrits > 0 ? ((totalVotants / inscrits.rows[0].inscrits) * 100).toFixed(2) : "0.00",
                                nombre_listes: listesArray.length
                            },
                            resultats: listesResultats,
                            bureau_elu: (candidats_gagnants && candidats_gagnants.rows) ? candidats_gagnants.rows : []
                        });
                    });
                });
            });
        });
    });
});

app.get('/pv-generator.html', isAuthenticated, (req, res) =>
    res.sendFile(path.join(__dirname, 'public', 'pv-generator.html')));

// ═══════════════════════════════════════
//  12. START
// ═══════════════════════════════════════
app.listen(PORT, () => console.log(`🗳️  Serveur démarré sur http://localhost:${PORT}`));