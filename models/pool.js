// Importe la configuration de la connexion à la base de données
const connection = require("./mysqlconfig.js");

// Importe la bibliothèque de hachage bcrypt
const bcrypt = require("bcrypt");

// Nombre de tours de salage pour renforcer la sécurité du hachage
const saltRounds = 10;

/*****************Cryptage*******************/

/**************************************************************/
// Logup (Inscription)
/**************************************************************/

// Fonction d'inscription d'un nouvel utilisateur
exports.create = (user, cb) => {
    // Requête SQL pour insérer un nouvel utilisateur dans la table 'utilisateur'
    const query = "INSERT INTO utilisateur(nom, prenom, email, password) VALUES (?, ?, ?, ?)";

    // Hash du mot de passe avec bcrypt
    bcrypt.hash(user.pwd, saltRounds, function (err, hasher) {
        if (err) throw err; // Gestion d'erreur en cas de problème de hachage (peu probable)

        // Affiche le hachage du mot de passe dans la console (à des fins de débogage)
        console.log(hasher);

        // Exécution de la requête SQL pour insérer les données dans la base de données
        connection.query(
            query,
            [user.nom, user.prenom, user.email, hasher], // Utilisation du mot de passe haché
            (err, rows) => {
                if (err) {
                    console.error("Erreur lors de l'insertion dans la base de données :", err);
                    
                    // Si l'erreur est due à une entrée dupliquée (email déjà existant), renvoie une erreur spécifique
                    if (err.code == "ER_DUP_ENTRY") {
                        return cb("Email existant");
                    }

                    // Appelle la fonction de rappel avec l'erreur
                    return cb(err);
                }

                // Aucune erreur, appelle la fonction de rappel sans erreur
                cb();
            }
        );
    });
};

/**************************************************************/
// Login (Connexion)
/**************************************************************/

// Exporte la fonction log, qui prend un utilisateur (user) et un callback (cb) en paramètres
exports.log = (user, cb) => {
    // Définit la requête SQL pour sélectionner tous les champs de la table 'utilisateur' où l'email correspond
    const query = "SELECT * FROM utilisateur WHERE email = ?";
    
    // Exécute la requête avec le paramètre d'email de l'utilisateur
    connection.query(query, [user.email], (err, row) => {
        // Gère les erreurs liées à la requête SQL
        if (err) {
            // Appelle le callback avec l'erreur
            return cb(err);
        }

        // Si aucune ligne n'est retournée, cela signifie qu'aucun utilisateur n'a été trouvé avec cette adresse e-mail
        if (row.length === 0) {
            cb(null, { error: "Mauvaise adresse e-mail" });
        } else {
            // Compare le mot de passe fourni par l'utilisateur avec le mot de passe haché stocké dans la base de données
            bcrypt.compare(user.pwd, row[0].password, function (err, result) {
                // Gère les erreurs liées à la comparaison de mot de passe
                if (err) {
                    // Appelle le callback avec l'erreur
                    return cb(err);
                }

                // Si la comparaison réussit, renvoie toutes les données de l'utilisateur
                if (result) {
                    cb(null, { userData: row[0] });
                } else {
                    // Si la comparaison échoue, renvoie un message d'erreur indiquant un mot de passe incorrect
                    cb(null, { error: "Mot de passe incorrect" });
                }
            });
        }
    });
};

/**************************************************************/
// Update (Mise à jour de profil)
/**************************************************************/

// Récupère le mot de passe non haché depuis la base de données
exports.getPasswordByEmail = (email, cb) => {
    const query = "SELECT password FROM utilisateur WHERE email = ?";

    connection.query(query, [email], (err, rows) => {
        if (err) {
            console.error("Erreur lors de la récupération du mot de passe depuis la base de données :", err);
            return cb(err);
        }

        // rows[0].password contient le mot de passe non haché
        cb(null, rows[0].password);
    });
};

// Met à jour les informations du profil de l'utilisateur (nom et prénom)
exports.update = (user, cb) => {
    const query = "UPDATE utilisateur SET nom = ?, prenom = ? WHERE email = ?";

    connection.query(query, [user.nom, user.prenom, user.email], (err, row) => {
        if (err) {
            console.error("Erreur lors de la mise à jour dans la base de données :", err);
            return cb(err);
        }

        // Appelle la fonction de rappel avec les résultats de la mise à jour
        cb(row);
    });
};

// Met à jour le mot de passe du profil de l'utilisateur
exports.updatePassword = (user, hashedPassword, cb) => {
    const query = "UPDATE utilisateur SET nom = ?, prenom = ?, password = ? WHERE email = ?";

    connection.query(query, [user.nom, user.prenom, hashedPassword, user.email], (err, row) => {
        if (err) {
            console.error("Erreur lors de la mise à jour du mot de passe dans la base de données :", err);
            return cb(err);
        }

        // Appelle la fonction de rappel avec les résultats de la mise à jour du mot de passe
        cb(row);
    });
};

/**************************************************************/
// Suppression de profil
/**************************************************************/

// Supprime le profil de l'utilisateur
exports.deleteProfile = (email, cb) => {
    const query = "DELETE FROM utilisateur WHERE email = ?";

    connection.query(query, [email], (err, result) => {
        if (err) {
            console.error("Erreur lors de la suppression du profil :", err);
            return cb(err);
        }

        // Appelle la fonction de rappel avec les résultats de la suppression du profil
        cb(null, result);
    });
};
