const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwtUtils = require("jsonwebtoken");
const interceptor = require("./middleware/jwt-interceptor");

const app = express();

/*--------------------------------------------------
  CONNEXION MySQL
--------------------------------------------------*/
const connection = mysql.createConnection({
  host: "localhost",
  port: 3306,           // 3306 par défaut
  user: "root",
  // password: "",
  database: "club_canin",
});

connection.connect((err) => {
  if (err) {
    console.error("Erreur de connexion à la base de données :", err);
    return;
  }
  console.log("Connecté à la base de données MySQL");
});

app.use(cors());
app.use(express.json());

/*--------------------------------------------------
  ROUTES
--------------------------------------------------*/
app.get("/", (req, res) => {
  res.send("<h1>C'est une API, il n'y a rien à voir ici</h1>");
});

/*-------- LISTE DES COURS --------*/
app.get("/cours/liste", (req, res) => {
  connection.query(
    `SELECT c.*, t.nom_type
      FROM cours c
      JOIN type t ON c.id_type = t.id_type`,
    (err, rows) => {
      if (err) return res.sendStatus(500);
      res.json(rows);
    }
  );
});

/*-------- COURS PAR ID --------*/
app.get("/cours/:id", (req, res) => {
  connection.query(
    `SELECT c.id_cours, c.nom_cours AS nom, c.duree_cours, c.date_creation_cours, t.nom_type
      FROM cours c
      JOIN type t ON c.id_type = t.id_type
      WHERE c.id_cours = ?`,
    [req.params.id],
    (err, rows) => {
      if (err) return res.sendStatus(500);
      if (rows.length === 0) return res.sendStatus(404);
      res.json(rows[0]);
    }
  );
});

/*-------- MISE À JOUR D'UN COURS --------*/
app.put("/cours/:id", interceptor, (req, res) => {
  const c = req.body;
  const id_cours = req.params.id;
  const user = req.user;

  if (!["coach", "admin"].includes(user.role)) return res.sendStatus(403);
  if (!c.nom || c.nom.trim() === "" || c.nom.length > 20) return res.sendStatus(400);
  if (c.nom_type && c.nom_type.length > 50) return res.sendStatus(400);

  connection.query(
    "SELECT 1 FROM cours WHERE nom_cours = ? AND id_cours != ?",
    [c.nom, id_cours],
    (err, rows) => {
      if (err) return res.sendStatus(500);
      if (rows.length) return res.sendStatus(409);

      connection.query(
        "INSERT INTO type (nom_type) VALUES (?) ON DUPLICATE KEY UPDATE id_type = LAST_INSERT_ID(id_type)",
        [c.nom_type],
        (err2, typeRes) => {
          if (err2) return res.sendStatus(500);

          const id_type = typeRes.insertId || typeRes.lastInsertId;

          connection.query(
            `UPDATE cours
            SET nom_cours = ?, duree_cours = ?, id_type = ?
            WHERE id_cours = ?`,
            [c.nom, c.duree_cours, id_type, id_cours],
            (err3, result) => {
              if (err3) return res.sendStatus(500);
              if (result.affectedRows === 0) return res.sendStatus(404);

              res.status(200).json({
                id_cours,
                nom: c.nom,
                duree_cours: c.duree_cours,
                nom_type: c.nom_type,
              });
            }
          );
        }
      );
    }
  );
});




/*-------- SUPPRESSION D'UN COURS --------*/
app.delete("/cours/:id", interceptor, (req, res) => {
  const id = req.params.id;
  if (!["coach", "admin"].includes(req.user.role)) return res.sendStatus(403);

  connection.query(
    "DELETE FROM cours WHERE id_cours = ?",
    [id],
    (err, result) => {
      if (err) return res.sendStatus(500);
      if (result.affectedRows === 0) return res.sendStatus(404);
      res.sendStatus(204);
    }
  );
});

/*-------- CRÉATION D'UN COURS --------*/
app.post("/cours", interceptor, (req, res) => {
  const c = req.body;
  const user = req.user;

  if (!["coach", "admin"].includes(user.role)) return res.sendStatus(403);
  if (!c.nom || !c.duree_cours || !c.nom_type) return res.sendStatus(400);

  connection.query(
    "SELECT 1 FROM cours WHERE nom_cours = ?",
    [c.nom],
    (err, rows) => {
      if (err) return res.sendStatus(500);
      if (rows.length) return res.sendStatus(409);

      connection.query(
        "INSERT INTO type (nom_type) VALUES (?) ON DUPLICATE KEY UPDATE id_type = LAST_INSERT_ID(id_type)",
        [c.nom_type],
        (err2, typeRes) => {
          if (err2) return res.sendStatus(500);

          const id_type = typeRes.insertId || typeRes.lastInsertId;

          connection.query(
            `INSERT INTO cours (nom_cours, duree_cours, id_utilisateur, id_type, date_creation_cours)
              VALUES (?, ?, ?, ?, NOW())`,
            [c.nom, c.duree_cours, user.id, id_type],
            (err3, coursRes) => {
              if (err3) return res.sendStatus(500);

              res.status(201).json({
                id_cours: coursRes.insertId,
                nom: c.nom,
                duree_cours: c.duree_cours,
                nom_type: c.nom_type,
              });
            }
          );
        }
      );
    }
  );
});

/*-------- INSCRIPTION --------*/
app.post("/inscription", (req, res) => {
  const u = req.body;
  const hash = bcrypt.hashSync(u.password, 10);

  connection.query(
    `INSERT INTO utilisateur
      (nom, prenom, nom_utilisateur, email, mot_de_passe, id_role, date_inscription)
    VALUES (?, ?, ?, ?, ?, ?, NOW())`,
    [u.nom, u.prenom, u.nom_utilisateur, u.email, hash, 3],
    (err, result) => {
      if (err && err.code === "ER_DUP_ENTRY") return res.sendStatus(409);
      if (err) return res.sendStatus(500);

      u.id = result.insertId;
      res.json(u);
    }
  );
});


// reservation 

app.post("/reservations", interceptor, (req, res) => {
  const id_user = req.user.id;
  const { id_cours } = req.body;

  if (!id_cours) return res.sendStatus(400);

  // Étape 1 – Chercher un chien existant pour cet utilisateur
  connection.query(
    "SELECT id_chien FROM chien WHERE id_utilisateur = ? LIMIT 1",
    [id_user],
    (err, rows) => {
      if (err) { console.error("Erreur SELECT chien :", err); return res.sendStatus(500); }

      const ensureReservation = (id_chien) => {
        console.log("🐶 ID du chien utilisé pour réserver :", id_chien);
        console.log("📚 ID du cours :", id_cours);

        // Étape 2 – Vérifie si déjà réservé
        connection.query(
          "SELECT 1 FROM reservation WHERE id_chien = ? AND id_cours = ?",
          [id_chien, id_cours],
          (err2, rows2) => {
            if (err2) { console.error("Erreur SELECT reservation :", err2); return res.sendStatus(500); }
            if (rows2.length) {
              console.warn("⚠️ Ce chien a déjà réservé ce cours !");
              return res.sendStatus(409); // conflit
            }

            // Étape 3 – Création de la réservation
            connection.query(
              `INSERT INTO reservation (id_chien, id_cours, date_reservation)
              VALUES (?, ?, NOW())`,
              [id_chien, id_cours],
              (err3) => {
                if (err3) { console.error("Erreur INSERT reservation :", err3); return res.sendStatus(500); }
                console.log("✅ Réservation créée !");
                res.sendStatus(201);
              }
            );
          }
        );
      };

      if (rows.length) {
        // 👌 Un chien existe → on réserve avec lui
        ensureReservation(rows[0].id_chien);
      } else {
        // ❌ Aucun chien → on en crée un d’abord
        connection.query(
          "INSERT INTO chien (id_utilisateur, nom_chien) VALUES (?, 'Mon premier chien')",
          [id_user],
          (err4, result) => {
            if (err4) {
              console.error("Erreur INSERT chien :", err4);
              return res.sendStatus(500);
            }
            console.log("🐕‍🦺 Chien par défaut créé :", result.insertId);
            ensureReservation(result.insertId);
          }
        );
      }
    }
  );
});





/*-------- CONNEXION --------*/
app.post("/connexion", (req, res) => {
  connection.query(
    `SELECT u.id_utilisateur, u.email, u.mot_de_passe, r.nom_role
      FROM utilisateur u
      JOIN role r ON u.id_role = r.id_role
      WHERE email = ?`,
    [req.body.email],
    (err, rows) => {
      if (err) return res.sendStatus(500);
      if (rows.length === 0) return res.sendStatus(401);

      const ok = bcrypt.compareSync(req.body.password, rows[0].mot_de_passe);
      if (!ok) return res.sendStatus(401);

      res.send(
        jwtUtils.sign(
          {
            sub: req.body.email,
            role: rows[0].nom_role,
            id: rows[0].id_utilisateur,
          },
          "azerty123"
        )
      );
    }
  );
});

/*--------------------------------------------------
  DÉMARRAGE DU SERVEUR
--------------------------------------------------*/
app.listen(5000, () => console.log("Le serveur écoute sur le port 5000 !!"));
