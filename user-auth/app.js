import express from "express";
import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import mysql from "mysql";
import cors from "cors";

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.json());
app.use(cors());
// MySQL database connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root", // Change if needed
  password: "", // Add your database password if applicable
  database: "goal_getter_db", // Replace with your database name
});

db.connect((err) => {
  // Vérifie la connexion avec la base de données
  if (err) {
    console.error("Error connecting to the database:", err);
    return;
  }
  console.log("Connected to MySQL database");
});

// Sign-up route
app.post("/signup", async (req, res) => {
  const { name, surname, email, password } = req.body;

  // Vérifie que tous les champs sont remplis
  if (!name || !surname || !email || !password) {
    return res.status(400).json({ message: "Please fill in all fields!" });
  }

  try {
    // Hash le mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql =
      "INSERT INTO users (name, surname, email, password) VALUES (?, ?, ?, ?)";
    db.query(
      sql,
      [name, surname, email, hashedPassword],
      (err, result) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ message: "Error while registering user!" });
        }
        res.status(201).json({ message: "User registered successfully!" });
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Something went wrong during registration!" });
  }
});
//login route
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  // Verify that both email and password are provided
  if (!email || !password) {
    return res.status(400).json({ message: "Please provide email and password!" });
  }

  const sql = "SELECT * FROM users WHERE email = ?"; // Query user by email
  db.query(sql, [email], async (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "Error during login!" });
    }

    // Check if a user with the provided email exists
    if (results.length === 0) {
      return res.status(404).json({ message: "Wrong email or user does not exist!" });
    }

    const user = results[0];

    // Compare the provided password with the hashed password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Incorrect password!" });
    }

    // Send a personalized welcome message for the correct user
    res.status(200).json({ message: `Welcome back, ${user.name} ${user.surname}!` });
  });
});
// Lancement du serveur
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});