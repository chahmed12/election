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

const app = express();
const PORT = process.env.PORT || 4000;

// ═══════════════════════════════════════════════════════════════
//  1. CONFIGURATION
// ═══════════════════════════════════════════════════════════════

app.set('trust proxy', 1);

// Multer (upload photos candidats + logo)
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'public/uploads');
        if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage });

// Middlewares
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ═══════════════════════════════════════════════════════════════
//  2. BASE DE DONNÉES
// ═══════════════════════════════════════════════════════════════

const db = mysql.createPool({
    host: process.env.MYSQLHOST,
    user: process.env.MYSQLUSER,
    password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQL_DATABASE || process.env.MYSQLDATABASE,
    port: process.env.MYSQLPORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

db.query('SELECT 1', (err) => {
    if (err) {
        console.error('❌ Erreur de connexion à la base de données:', err.message);
        return;
    }
    console.log('✅ Connecté à la base de données MySQL (Pool)');
    createTables();
});

function createTables() {
    // 1. Admins
    db.query(`CREATE TABLE IF NOT EXISTS admins (
        id       INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL
    )`, (err) => {
        if (err) return console.error('Erreur table admins:', err);
        console.log("Table 'admins' vérifiée.");
        db.query("SELECT * FROM admins WHERE username = 'admin'", (err, results) => {
            if (!err && results.length === 0) {
                db.query("INSERT INTO admins (username, password) VALUES ('admin', '123456')");
                console.log("Compte admin par défaut créé (admin / 123456)");
            }
        });
    });

    // 2. Settings
    db.query(`CREATE TABLE IF NOT EXISTS settings (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        titre         VARCHAR(500) DEFAULT 'انتخابات فرع الرابطة في مراكش 2026/2027',
        logo_url      VARCHAR(500) DEFAULT NULL,
        date_election DATE DEFAULT NULL,
        vote_ouvert   TINYINT(1) DEFAULT 1,
        updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )`, (err) => {
        if (err) return console.error('Erreur table settings:', err);
        console.log("Table 'settings' vérifiée.");
        db.query("SELECT * FROM settings WHERE id = 1", (err, results) => {
            if (!err && results.length === 0) {
                db.query("INSERT INTO settings (id, titre) VALUES (1, 'انتخابات فرع الرابطة في مراكش 2026/2027')");
            }
        });
    });

    // 3. Listes candidates
    db.query(`CREATE TABLE IF NOT EXISTS listes (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        nom        VARCHAR(255) NOT NULL,
        slogan     VARCHAR(500),
        logo_url   VARCHAR(500),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
        if (err) console.error('Erreur table listes:', err);
        else console.log("Table 'listes' vérifiée.");
    });

    // 4. Candidats
    db.query(`CREATE TABLE IF NOT EXISTS candidats (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        liste_id   INT NOT NULL,
        nom        VARCHAR(255) NOT NULL,
        role       VARCHAR(255) DEFAULT 'عضو',
        photo_url  VARCHAR(500),
        ordre      INT DEFAULT 0,
        FOREIGN KEY (liste_id) REFERENCES listes(id) ON DELETE CASCADE
    )`, (err) => {
        if (err) console.error('Erreur table candidats:', err);
        else console.log("Table 'candidats' vérifiée.");
    });

    // 5. Électeurs (pré-chargés dans la DB)
    db.query(`CREATE TABLE IF NOT EXISTS electeurs (
        id               INT AUTO_INCREMENT PRIMARY KEY,
        nom              VARCHAR(255) NOT NULL,
        telephone        VARCHAR(20) NOT NULL UNIQUE,
        has_voted        TINYINT(1) DEFAULT 0,
        created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
        if (err) console.error('Erreur table electeurs:', err);
        else console.log("Table 'electeurs' vérifiée.");
    });

    // 6. Votes
    db.query(`CREATE TABLE IF NOT EXISTS votes (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        electeur_id INT NOT NULL UNIQUE,
        liste_id    INT NOT NULL,
        voted_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (electeur_id) REFERENCES electeurs(id) ON DELETE CASCADE,
        FOREIGN KEY (liste_id) REFERENCES listes(id) ON DELETE CASCADE
    )`, (err) => {
        if (err) console.error('Erreur table votes:', err);
        else console.log("Table 'votes' vérifiée.");
    });
}

// ═══════════════════════════════════════════════════════════════
//  3. SESSION
// ═══════════════════════════════════════════════════════════════

const sessionStore = new MySQLStore({}, db);
const isProduction = process.env.NODE_ENV === 'production';

app.use(session({
    key: 'election_session',
    secret: process.env.SESSION_SECRET || 'election_secret_2026_marrakech',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: isProduction,
        sameSite: isProduction ? 'none' : 'lax',
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Fichiers publics
app.use(express.static(path.join(__dirname, 'public')));

// Middleware d'authentification admin
function isAuthenticated(req, res, next) {
    if (req.session && req.session.isAdmin) {
        return next();
    }
    res.status(401).json({ success: false, message: 'Non autorisé' });
}

// ═══════════════════════════════════════════════════════════════
//  4. ROUTES PUBLIQUES
// ═══════════════════════════════════════════════════════════════

// Vérifier un numéro de téléphone (accès au site)
app.post('/api/verifier-telephone', (req, res) => {
    const { telephone } = req.body;
    if (!telephone) return res.status(400).json({ success: false, message: 'Numéro requis' });

    const cleaned = telephone.replace(/\s/g, '');
    db.query("SELECT * FROM electeurs WHERE telephone = ?", [cleaned], (err, results) => {
        if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
        if (results.length === 0) {
            return res.json({ success: false, message: 'هذا الرقم غير مسجل في قائمة الناخبين' });
        }
        const electeur = results[0];
        // Store electeur in session
        req.session.electeur = { id: electeur.id, nom: electeur.nom, telephone: electeur.telephone, has_voted: electeur.has_voted };
        res.json({ success: true, electeur: { nom: electeur.nom, has_voted: electeur.has_voted } });
    });
});

// Obtenir les listes candidates avec leurs candidats
app.get('/api/listes', (req, res) => {
    db.query("SELECT * FROM listes ORDER BY id", (err, listes) => {
        if (err) return res.status(500).json({ error: err });
        db.query("SELECT * FROM candidats ORDER BY liste_id, ordre", (err, candidats) => {
            if (err) return res.status(500).json({ error: err });
            const data = listes.map(l => ({
                ...l,
                candidats: candidats.filter(c => c.liste_id === l.id)
            }));
            res.json(data);
        });
    });
});

// Voter
app.post('/api/voter', (req, res) => {
    if (!req.session.electeur) {
        return res.status(401).json({ success: false, message: 'يرجى التحقق من رقم هاتفك أولاً' });
    }

    const electeur = req.session.electeur;
    const { liste_id } = req.body;

    if (!liste_id) return res.status(400).json({ success: false, message: 'يرجى اختيار لائحة' });

    // Vérifier si déjà voté (double check)
    db.query("SELECT has_voted FROM electeurs WHERE id = ?", [electeur.id], (err, results) => {
        if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
        if (results[0].has_voted) {
            return res.json({ success: false, message: 'لقد أدليت بصوتك مسبقاً' });
        }

        // Vérifier que le vote est ouvert
        db.query("SELECT vote_ouvert FROM settings WHERE id = 1", (err, settings) => {
            if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
            if (settings.length && !settings[0].vote_ouvert) {
                return res.json({ success: false, message: 'التصويت مغلق حالياً' });
            }

            // Enregistrer le vote
            db.query("INSERT INTO votes (electeur_id, liste_id) VALUES (?, ?)", [electeur.id, liste_id], (err) => {
                if (err) return res.status(500).json({ success: false, message: 'Erreur lors du vote' });

                db.query("UPDATE electeurs SET has_voted = 1 WHERE id = ?", [electeur.id], (err) => {
                    if (err) return res.status(500).json({ success: false, message: 'Erreur mise à jour' });
                    req.session.electeur.has_voted = 1;
                    res.json({ success: true, message: 'لقد أدليت بصوتك بنجاح! شكراً لمشاركتك' });
                });
            });
        });
    });
});

// Résultats
app.get('/api/resultats', (req, res) => {
    db.query("SELECT l.id, l.nom, l.logo_url, COUNT(v.id) as votes FROM listes l LEFT JOIN votes v ON l.id = v.liste_id GROUP BY l.id ORDER BY votes DESC", (err, results) => {
        if (err) return res.status(500).json({ error: err });
        db.query("SELECT COUNT(*) as total FROM electeurs", (err2, total) => {
            if (err2) return res.status(500).json({ error: err2 });
            db.query("SELECT COUNT(*) as voted FROM electeurs WHERE has_voted = 1", (err3, voted) => {
                if (err3) return res.status(500).json({ error: err3 });
                res.json({
                    listes: results,
                    total_electeurs: total[0].total,
                    total_votes: voted[0].voted
                });
            });
        });
    });
});

// Settings publics
app.get('/api/settings', (req, res) => {
    db.query("SELECT titre, logo_url, date_election, vote_ouvert FROM settings WHERE id = 1", (err, results) => {
        if (err) return res.status(500).json({ error: err });
        res.json(results[0] || {});
    });
});

// ═══════════════════════════════════════════════════════════════
//  5. AUTHENTIFICATION ADMIN
// ═══════════════════════════════════════════════════════════════

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: 'Identifiants manquants' });

    db.query("SELECT * FROM admins WHERE username = ? AND password = ?", [username, password], (err, results) => {
        if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
        if (results.length === 0) return res.json({ success: false, message: 'Identifiants incorrects' });

        req.session.isAdmin = true;
        req.session.adminUser = results[0].username;
        res.json({ success: true, message: 'Connecté !' });
    });
});

app.get('/api/check-auth', (req, res) => {
    res.json({ authenticated: !!(req.session && req.session.isAdmin) });
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════
//  6. PAGES ADMIN (PROTÉGÉES)
// ═══════════════════════════════════════════════════════════════

app.get('/admin.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'prive', 'admin.html')));
app.get('/gestion-listes.html', isAuthenticated, (req, res) => res.sendFile(path.join(__dirname, 'prive', 'gestion-listes.html')));

// ═══════════════════════════════════════════════════════════════
//  7. API ADMIN — LISTES
// ═══════════════════════════════════════════════════════════════

app.get('/api/admin/listes', isAuthenticated, (req, res) => {
    db.query("SELECT * FROM listes ORDER BY id", (err, listes) => {
        if (err) return res.status(500).json({ error: err });
        db.query("SELECT * FROM candidats ORDER BY liste_id, ordre", (err, candidats) => {
            if (err) return res.status(500).json({ error: err });
            const data = listes.map(l => ({ ...l, candidats: candidats.filter(c => c.liste_id === l.id) }));
            res.json(data);
        });
    });
});

app.post('/api/admin/listes', isAuthenticated, upload.single('logo'), (req, res) => {
    const { nom, slogan } = req.body;
    if (!nom) return res.status(400).json({ success: false, message: 'Nom requis' });
    const logo_url = req.file ? `/uploads/${req.file.filename}` : null;
    db.query("INSERT INTO listes (nom, slogan, logo_url) VALUES (?, ?, ?)", [nom, slogan, logo_url], (err, result) => {
        if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
        res.json({ success: true, id: result.insertId });
    });
});

app.delete('/api/admin/listes/:id', isAuthenticated, (req, res) => {
    db.query("DELETE FROM listes WHERE id = ?", [req.params.id], (err) => {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true });
    });
});

// ═══════════════════════════════════════════════════════════════
//  8. API ADMIN — CANDIDATS
// ═══════════════════════════════════════════════════════════════

app.post('/api/admin/candidats', isAuthenticated, upload.single('photo'), (req, res) => {
    const { liste_id, nom, role, ordre } = req.body;
    if (!liste_id || !nom) return res.status(400).json({ success: false, message: 'liste_id et nom requis' });
    const photo_url = req.file ? `/uploads/${req.file.filename}` : null;
    db.query("INSERT INTO candidats (liste_id, nom, role, photo_url, ordre) VALUES (?, ?, ?, ?, ?)",
        [liste_id, nom, role || 'عضو', photo_url, ordre || 0], (err, result) => {
            if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
            res.json({ success: true, id: result.insertId });
        });
});

app.delete('/api/admin/candidats/:id', isAuthenticated, (req, res) => {
    db.query("DELETE FROM candidats WHERE id = ?", [req.params.id], (err) => {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true });
    });
});

// ═══════════════════════════════════════════════════════════════
//  9. API ADMIN — SETTINGS
// ═══════════════════════════════════════════════════════════════

app.post('/api/admin/settings', isAuthenticated, upload.single('logo'), (req, res) => {
    const { titre, date_election, vote_ouvert } = req.body;
    const logo_url = req.file ? `/uploads/${req.file.filename}` : undefined;

    let query = "UPDATE settings SET titre = ?, date_election = ?, vote_ouvert = ?";
    let params = [titre, date_election || null, vote_ouvert === undefined ? 1 : vote_ouvert];

    if (logo_url) {
        query += ", logo_url = ?";
        params.push(logo_url);
    }
    query += " WHERE id = 1";

    db.query(query, params, (err) => {
        if (err) return res.status(500).json({ success: false, message: 'Erreur serveur' });
        res.json({ success: true });
    });
});

app.post('/api/admin/toggle-vote', isAuthenticated, (req, res) => {
    db.query("UPDATE settings SET vote_ouvert = NOT vote_ouvert WHERE id = 1", (err) => {
        if (err) return res.status(500).json({ success: false });
        db.query("SELECT vote_ouvert FROM settings WHERE id = 1", (err, results) => {
            if (err) return res.status(500).json({ success: false });
            res.json({ success: true, vote_ouvert: results[0].vote_ouvert });
        });
    });
});

// API Admin — Stats
app.get('/api/admin/stats', isAuthenticated, (req, res) => {
    db.query("SELECT COUNT(*) as total FROM electeurs", (err, t) => {
        if (err) return res.status(500).json({ error: err });
        db.query("SELECT COUNT(*) as voted FROM electeurs WHERE has_voted = 1", (err, v) => {
            if (err) return res.status(500).json({ error: err });
            db.query("SELECT COUNT(*) as listes FROM listes", (err, l) => {
                if (err) return res.status(500).json({ error: err });
                res.json({
                    total_electeurs: t[0].total,
                    total_votes: v[0].voted,
                    total_listes: l[0].listes,
                    taux_participation: t[0].total > 0 ? Math.round((v[0].voted / t[0].total) * 100) : 0
                });
            });
        });
    });
});

// API Admin — Électeurs (lecture seule)
app.get('/api/admin/electeurs', isAuthenticated, (req, res) => {
    db.query("SELECT e.*, v.liste_id, l.nom as liste_nom FROM electeurs e LEFT JOIN votes v ON e.id = v.electeur_id LEFT JOIN listes l ON v.liste_id = l.id ORDER BY e.created_at DESC", (err, results) => {
        if (err) return res.status(500).json({ error: err });
        res.json(results);
    });
});

// ═══════════════════════════════════════════════════════════════
//  10. DÉMARRAGE
// ═══════════════════════════════════════════════════════════════

app.listen(PORT, () => {
    console.log(`🗳️  Serveur élection démarré sur http://localhost:${PORT}`);
});
