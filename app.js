// Importation des modules requis
const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const bdd = require("./models/pool.js"); 
const bcrypt = require('bcrypt');
const saltRounds = 10; // Déclarez saltRounds ici
const app = express();
const port = 8808;

// Middleware Express
/*********************************************************************************************/
// Parse les données des formulaires URL-encoded et JSON dans req.body
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
// Sert les fichiers statiques du répertoire "public"
app.use(express.static("public"));

// Templates
/*********************************************************************************************/
// Configure le moteur de modèle EJS et définit le répertoire des vues
app.set("views", __dirname + "/views");
app.set("view engine", "ejs");

// Initialisation de la session cookie
/*********************************************************************************************/
app.use(cookieParser());

app.use(
    session({
        secret: "Mon cul c'est du poulet!", // Clé secrète utilisée pour signer la session cookie
        cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 }, // Durée de vie maximale du cookie (30 jours)
        saveUninitialized: false, // Ne pas sauvegarder les sessions non initialisées
        resave: false, // Ne pas sauvegarder la session si elle n'a pas été modifiée
    })
);

// Initialisation de la route "/index"
/**********************************************************************************************/
app.get("/", function (req, res, next) {
    const userData = req.session.userData || {}; // Utilisez un objet vide par défaut
    res.render("index", { user: userData });
});

// Routes pour la création d'un nouvel utilisateur ("logup")
/**********************************************************************************************/
// Affiche le formulaire d'inscription
app.get("/logup", (req, res) => {
    res.render("logup");
});

// Traitement du formulaire d'inscription
app.post("/create", (req, res) => {
    console.log(req.body); // Affiche les données du formulaire dans la console
    // Appelle la fonction create de l'objet bdd avec les données du formulaire
    bdd.create(req.body, (rep) => {
        if (rep) {
            // Si la création a réussi, redirige vers la page de connexion ("logup")
            res.redirect("logup");
        } else {
            // Sinon, redirige vers la page d'accueil ("/")
            res.redirect("/");
        }
    });
});

// Routes pour qu'un utilisateur se connecte ("login")
/**********************************************************************************************/
app.get("/login", (req, res) => {
    // Rend la vue "login"
    res.render("login", { error: req.query.error});
});

// Lorsqu'une requête POST est reçue pour "/log"
app.post("/log", (req, res) => {
    bdd.log(req.body, (err, result) => {
        if (err) {
            // Gestion des erreurs (par exemple, afficher un message d'erreur général)
            return res.redirect("/login");
        }

        if (result.error) {
            // Afficher un message d'erreur spécifique dans la vue login
            return res.render("login", { error: result.error });
        }

        if (result.userData && result.userData !== null) {
            // Connexion réussie, redirigez l'utilisateur avec toutes les données de l'utilisateur
            req.session.userData = result.userData;
            console.log(req.session.userData)
            return res.redirect("/profil");
        } else {
            // Identifiants incorrects (ce cas ne devrait pas se produire normalement)
            return res.redirect("/login");
        }
    });
});

// Routes pour se déconnecter ("logout")
/**********************************************************************************************/
app.get("/logout", function (req, res, next) {
    // Déconnectez l'utilisateur en détruisant la session
    req.session.destroy(function(err) {
        if (err) {
            console.error("Erreur lors de la déconnexion :", err);
        }
        // Redirigez l'utilisateur vers la page d'accueil ou toute autre page appropriée
        res.redirect("/");
    });
});

// Routes pour afficher son profil ("profil")
/**********************************************************************************************/
// Lorsqu'une requête GET est reçue pour "/profil"
app.get("/profil", (req, res) => {
    // Rend la vue "profil" en passant les données de l'utilisateur depuis la session
    const userData = req.session.userData || {}; // Utilisez un objet vide par défaut
    res.render("profil", { user: userData });
});

// Routes pour modifier son profil ("update")
/**********************************************************************************************/
app.get('/form_update', (req, res) => {
    const userData = req.session.userData || {};

    // Récupère le mot de passe non haché depuis la base de données
    bdd.getPasswordByEmail(userData.email, (err, oldPassword) => {
        if (err) {
            console.error("Erreur lors de la récupération du mot de passe :", err);
            // Transmettez l'erreur à la vue en ajoutant { error: err.message }
            return res.render("form_modif", { user: userData, oldPassword, error: "", message: "" });
        }

        // Passe le mot de passe non haché à la vue
        res.render("form_modif", { user: userData, oldPassword, error: "", message: "" });
    });
});

app.post('/update', (req, res) => {
    const user = req.session.userData;

    // Vérifie si l'ancien mot de passe correspond
    bcrypt.compare(req.body.oldPassword, user.password, function (err, result) {
        if (err || !result) {
            // Si la vérification échoue, redirige vers le profil avec une erreur
            return res.render('form_modif', { user, oldPassword: "", error: 'Le mot de passe actuel est incorrect', message: "" });
        }

        // Vérification réussie, procède à la mise à jour

        // Vérifie si un nouveau mot de passe est fourni
        if (req.body.newPassword && req.body.newPassword === req.body.confirmPassword) {
            // Hash du nouveau mot de passe
            bcrypt.hash(req.body.newPassword, saltRounds, function (err, hashedPassword) {
                if (err) {
                    console.error("Erreur lors du hachage du nouveau mot de passe :", err);
                    return res.render('form_modif', { user, oldPassword: "", error: 'Erreur lors de la mise à jour du mot de passe', message: "" });
                }

                // Met à jour le mot de passe dans la base de données
                bdd.updatePassword(user, hashedPassword, () => {
                    // Redirige vers le profil après la mise à jour
                    res.render('form_modif', { user, oldPassword: "", error: "", message: 'Modifications enregistrées avec succès' });
                });
            });
        } else {
            // Les nouveaux mots de passe ne sont pas identiques
            // Redirige vers le profil avec une erreur
            res.render('form_modif', { user, oldPassword: "", error: 'Les nouveaux mots de passe ne sont pas identiques', message: "" });
        }
    });
});

// Routes pour supprimer son profil ("delete")
/**********************************************************************************************/
// Affiche le formulaire de confirmation de suppression
app.get('/confirm_delete', (req, res) => {
    const userData = req.session.userData || {};
    res.render('confirm_delete', { user: userData, error: "", message: "" });
});

// Traite la suppression du profil
app.post('/delete', (req, res) => {
    const user = req.session.userData;

    // Vérifie si l'ancien mot de passe correspond
    bcrypt.compare(req.body.confirmPassword, user.password, function (err, result) {
        if (err || !result) {
            // Si la vérification échoue, redirige vers le profil avec une erreur
            return res.render('confirm_delete', { user, error: 'Le mot de passe actuel est incorrect', message: "" });
        }

        // Supprime le profil de la base de données
        bdd.deleteProfile(user.email, (deleteError) => {
            if (deleteError) {
                // Si la suppression échoue, redirige vers le profil avec une erreur
                res.render('confirm_delete', { user, error: 'Erreur lors de la suppression du profil', message: "" });
            } else {
                // Déconnecte l'utilisateur en détruisant la session
                req.session.destroy(function (err) {
                    if (err) {
                        console.error("Erreur lors de la déconnexion :", err);
                    }
                    // Redirige l'utilisateur vers la page d'accueil ou toute autre page appropriée
                    res.redirect('/');
                });
            }
        });
    });
});

// Listener
/************************************************************************************************/
app.listen(port, () => console.log('Vous êtes sur le port :', port))
