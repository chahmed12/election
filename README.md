# 🗳️ Élections Associatives — Marrakech 2026/2027

Application de vote pour les élections du bureau d'une branche associative.

## Fonctionnalités

- ✅ Vérification par numéro de téléphone (pré-chargé en base)
- ✅ Listes candidates avec photos des membres du bureau
- ✅ Vote unique par électeur (protection contre le double vote)
- ✅ Résultats en temps réel avec graphiques
- ✅ Dashboard admin (gestion listes, toggle vote, upload logo)
- ✅ Design glassmorphism premium dark theme

## Démarrage rapide

```bash
# 1. Installer les dépendances
cd /home/chahmed/election
npm install

# 2. Créer la base de données
mysql -u root -pzenvour < database.sql
# Ou manuellement : CREATE DATABASE election_db;

# 3. Démarrer le serveur
npm start
# → http://localhost:4000
```

## Accès Admin

- URL : http://localhost:4000/login.html
- Identifiant : `admin`
- Mot de passe : `123456`

## Ajouter des électeurs

Les électeurs sont pré-chargés dans la base de données :

```sql
USE election_db;
INSERT INTO electeurs (nom, telephone) VALUES
('محمد أحمد', '0612345678'),
('فاطمة بنت خالد', '0698765432'),
('عبد الله ولد سيدي', '0654321098');
```

## Stack technique

Express.js · MySQL · Tailwind CSS · Chart.js · SweetAlert2
# élection
