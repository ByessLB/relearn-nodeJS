const mysql = require('mysql2');

// module.exports met à disposition la fonction query
module.exports = {
    query: query,
};

// Connection au pool
let pool = mysql.createPoolCluster({ canRetry: true });

// Creation connection BDD
pool.add({
    host:"localhost",
    user: "root",
    password: "",
    database: "article",
});

// teste connection
pool.getConnection(function (err, _connection) {
    if (err) {
        throw new error("MySQL connection erreur" + err);
        // process.exit(1);
    }
    console.info("MySQLM connection OK!");
    _connection.release();
});

// Query
function query (sql, params, cb) {
    if (typeof params === "function") {
        cb = params;
        params = [];
    }
    // Execution de la requete SQL
    pool.getConnection (function (err, connection) {
        if (err) {
            return cb (err);
        }

        connection.query (sql, params, function (err, rows, fields) {
            connection.release ();
            cb (err, rows, fields);
        });
    });
}