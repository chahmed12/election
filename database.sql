-- ================================================
-- Base de données : election_db
-- Élections de branche associative Marrakech 2026/2027
-- ================================================

CREATE DATABASE IF NOT EXISTS election_db;
USE election_db;

-- 1. Admins
CREATE TABLE IF NOT EXISTS admins (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
);

-- Compte admin par défaut
INSERT IGNORE INTO admins (username, password) VALUES ('admin', '123456');

-- 2. Paramètres globaux de l'élection
CREATE TABLE IF NOT EXISTS settings (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    titre         VARCHAR(500) DEFAULT 'انتخابات فرع الرابطة في مراكش 2026/2027',
    logo_url      VARCHAR(500) DEFAULT NULL,
    date_election DATE DEFAULT NULL,
    vote_ouvert   TINYINT(1) DEFAULT 1,
    updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

INSERT IGNORE INTO settings (id, titre) VALUES (1, 'انتخابات فرع الرابطة في مراكش 2026/2027');

-- 3. Listes candidates
CREATE TABLE IF NOT EXISTS listes (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    nom        VARCHAR(255) NOT NULL,
    slogan     VARCHAR(500),
    logo_url   VARCHAR(500),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. Candidats (membres du bureau de chaque liste)
CREATE TABLE IF NOT EXISTS candidats (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    liste_id   INT NOT NULL,
    nom        VARCHAR(255) NOT NULL,
    role       VARCHAR(255) DEFAULT 'عضو',
    photo_url  VARCHAR(500),
    ordre      INT DEFAULT 0,
    FOREIGN KEY (liste_id) REFERENCES listes(id) ON DELETE CASCADE
);

-- 5. Électeurs inscrits par téléphone
CREATE TABLE IF NOT EXISTS electeurs (
    id               INT AUTO_INCREMENT PRIMARY KEY,
    nom              VARCHAR(255) NOT NULL,
    telephone        VARCHAR(20) NOT NULL UNIQUE,
    has_voted        TINYINT(1) DEFAULT 0,
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 6. Votes
CREATE TABLE IF NOT EXISTS votes (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    electeur_id INT NOT NULL UNIQUE,
    liste_id    INT NOT NULL,
    voted_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (electeur_id) REFERENCES electeurs(id) ON DELETE CASCADE,
    FOREIGN KEY (liste_id) REFERENCES listes(id) ON DELETE CASCADE
);
