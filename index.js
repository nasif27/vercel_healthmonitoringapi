// Boilerplate code
const express = require("express");     // we want to use expressJS
const cors = require("cors");       // Cross Origin Resource Sharing
const { Pool } = require("pg");     // destructure Pool from postgres(pg) library
const { DATABASE_URL, SECRET_KEY } = process.env;
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
app.use(cors());
app.use(express.json());

// connect to Neon Console using connection string
const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: {
        require: true,
    },
});

// get PostgreSQL version used
async function getPostgresVersion() {
    const client = await pool.connect();
    try {
        const response = await client.query("SELECT version()");
        console.log(response.rows[0]);      // DB response will be returned in the form of object array {[]}
    } finally {
        client.release();
    }
}

getPostgresVersion();

// Endpoint Code

///////////////////////////////// AUTH ENDPOINT /////////////////////////////////

// signUp endpoint
   // enter username → enter email → check username & email existence →
   // enter pwd → encrypt pwd → add user into DB

app.post("/signup", async (req, res) => {
    const client = await pool.connect();

    try{
        // destructure user info from request body
        const { username, email, password } = req.body;
        // hashing pwd with cost factor of 12. Hash is a Bcrypt function
        const hashedPassword = await bcrypt.hash(password, 12);
        const userExists = await client.query(
            "SELECT * FROM users WHERE username = $1 OR email = $2", 
            [username, email]
        );

        // if user that want to be registered exists, return error
        if (userExists.rows.length > 0) {
            return res.status(400).json({ message: "Username or email already exist" });
        }

        // if not exists yet, proceed to register the user
        await client.query(
            "INSERT INTO users (username, email, password) VALUES ($1, $2, $3)", 
            [username, email, hashedPassword]
        );

        res.status(200).json({ message: "User has been registered successfully" });
    } catch (error) {
        console.log("Error:", error.message); // return error message to console
        res.status(500).json({ error: error.message }); // return error message to client
    } finally {
        client.release();
    }
});

// signin endpoint

app.post("/signin", async (req, res) => {
    const client = await pool.connect();
    const { username, email, password } = req.body;

    try {
        // 1. Check username & email
        const userExists = await client.query(
            "SELECT * FROM users WHERE username = $1 OR email = $2", 
            [username, email]
        );

        // if user exists, store in a variable
        const user = userExists.rows[0];

        // 2. If registered user not found, return error to client
        if (!user) {
            return res.status(400).json({ message: "Incorrect username or email" });
        }

        // 3. Verify password by comparing between pwd in request body & pwd exist in DB
        const passwordIsValid = await bcrypt.compare(password, user.password);  // user.password = hashedPassword 
        
        // if invalid password, return error to client & set token to null 
        if (!passwordIsValid) {
            return res.status(400).json({ auth: false, token: null });
        }

        // if valid password, pass 3 arguments to jwt.sign() method to generate JWT token
        const token = jwt.sign(
            { id: user.id, username: user.username, email: user.email },    // user info
            SECRET_KEY,
            { expiresIn: 86400 }    // expiration time in millisecond, 86400 ms = 24 hr
        );

        // after JWT token has been generated, return response to client
        res.status(200).json({ auth: true, token: token });
    } catch (error) {
        console.log("Error:", error.message);   // return error message to console
        res.status(500).json({ error: error.message });     // return error message to client
    } finally {
        client.release();
    }
});


//////////////////////////////// REQUEST ENDPOINT ////////////////////////////////

// GET all high_bp posts from specific user --endpoint
app.get("/highBP/user/:user_id", async (req, res) => {
    const { user_id } = req.params;
    const client = await pool.connect();
    
    try {
        const highBPData = await client.query(
            "SELECT * FROM high_bp WHERE high_bp.user_id = $1", 
            [user_id]
        );

        if (highBPData.rowCount > 0) {
            res.json(highBPData.rows);
        } else {
            res.status(404).json({ error: "No data found for this user" });
        }
    } catch (error) {
        console.log("Error:", error.message);
        res.status(500).json({ error: error.message });
    } finally {
        client.release();
    }
});

// GET user info --endpoint
app.get("/user/:id", async (req, res) => {
    const client = await pool.connect();
    const { id } = req.params;
    
    try {
        // Check user's existence
        const user = await client.query(
            "SELECT * FROM users WHERE id = $1", 
            [id]
        );

        if (user.rows.length > 0) {
            res.json(user.rows[0]);
        } else {
            res.status(404).json({ error: "user not found" });
        }
    } catch (error) {
        console.log("Error:", error.message);
        res.status(500).json({ error: error.message });
    } finally {
        client.release();
    }
});

// GET specific user info --endpoint
app.get("/userinfo/:id", async (req, res) => {
    const client = await pool.connect();
    const { id } = req.params;

    try {
        // Check user info existence
        const userInfo = await client.query(
            "SELECT full_name, age, gender, height, weight, ongoing_med FROM users WHERE id = $1", 
            [id]
        );

        if (userInfo.rows.length > 0) {
            res.json(userInfo.rows[0]);
        } else {
            res.status(400).json({ error: "User not found" });
        }
    } catch (error) {
        console.log("Error:", error.message);
        res.status(500).json({ error: error.message });
    } finally {
        client.release();
    }
});

// UPDATE remaining info to user info --endpoint
app.put("/userinfo/:id", async (req, res) => {
    const client = await pool.connect();
    const { id } = req.params;
    const { full_name, age, gender, height, weight, ongoing_med } = req.body;

    try {
        // Check user's existence
        const userExists = await client.query(
            "SELECT * FROM users WHERE id = $1", 
            [id]
        );

        if (userExists.rows.length > 0) {
            const userInfo = await client.query(
                "UPDATE users SET full_name = $1, age = $2, gender = $3, height = $4, weight = $5, ongoing_med = $6 WHERE id = $7 RETURNING *", 
                [full_name, age, gender, height, weight, ongoing_med, id]
            );

            res.json(userInfo.rows[0]);
        } else {
            res.status(400).json({ error: "User not found" });
        }
    } catch (error) {
        console.log("Error:", error.message);
        res.status(500).json({ error: error.message });
    } finally {
        client.release();
    }
});

// // GET high_bp data from specific user --endpoint
// app.get("/highBP/user/:id", async (req, res) => {
//     const { user_id, input_date, input_time, systolic, dystolic, pulse_rate } = req.body;
//     const client = await pool.connect();

//     try {
//         // Check user's existence
//         const highBPData = await client.query(
//             "SELECT * FROM high_bp WHERE id = $1", 
//             [user_id]
//         );

//         if (userExists.rows.length > 0) {
//             const post = await client.query(
//                 "INSERT INTO high_bp (user_id, input_date, input_time, systolic, dystolic, pulse_rate, created_at) VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP) RETURNING *", 
//                 [user_id, input_date, input_time, systolic, dystolic, pulse_rate]
//             );
    
//             res.json(post.rows[0]);
//         } else {
//             res.status(400).json({ error: "User not found" });
//         }
//     } catch (error) {
//         console.log("Error:", error.message);
//         res.status(500).json({ error: error.message });
//     } finally {
//         client.release();
//     }
// });

// POST high_bp data from specific user --endpoint
app.post("/highBP/user/:id", async (req, res) => {
    const { id } = req.params;
    const { input_date, input_time, systolic, dystolic, pulse_rate } = req.body;
    const client = await pool.connect();

    try {
        // Check user's existence
        const userExists = await client.query(
            "SELECT * FROM users WHERE id = $1", 
            [id]
        );

        if (userExists.rows.length > 0) {
            // const formattedDate = input_date.toISOString().split("T")[0];
            const post = await client.query(
                "INSERT INTO high_bp (user_id, input_date, input_time, systolic, dystolic, pulse_rate, created_at) VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP) RETURNING *", 
                [id, input_date, input_time, systolic, dystolic, pulse_rate]
            );

            // const formattedDatePost = post.rows.map(row => ({
            //     input_date: row.input_date.toISOString().split("T")[0]
            // }));

            const formattedDatePost = post.rows.map((row) => ({
                ...row, input_date: row.input_date.toISOString().split("T")[0]
            }));
    
            // res.json(post.rows[0]);
            res.json(formattedDatePost);
        } else {
            res.status(400).json({ error: "User not found" });
        }
    } catch (error) {
        console.log("Error:", error.message);
        res.status(500).json({ error: error.message });
    } finally {
        client.release();
    }
});

// UPDATE specific high_bp post --endpoint
app.put("/highBP/:id", async (req, res) => {
    const client = await pool.connect();
    const { id } = req.params;
    const { input_date, input_time, systolic, dystolic, pulse_rate } = req.body;

    try {
        // Check high_bp post's existence
        const postExists = await client.query(
            "SELECT * FROM high_bp WHERE id = $1", 
            [id]
        );

        if (postExists.rows.length > 0) {
            const updatedPost = await client.query(
                "UPDATE high_bp SET input_date = $1, input_time = $2, systolic = $3, dystolic = $4, pulse_rate = $5, updated_at = CURRENT_TIMESTAMP WHERE id = $6 RETURNING *", 
                [input_date, input_time, systolic, dystolic, pulse_rate, id]
            );
    
            res.json(updatedPost.rows[0]);
        } else {
            res.status(400).json({ error: "High blood pressure post not found" });
        }
    } catch (error) {
        console.log("Error:", error.message);
        res.status(500).json({ error: error.message });
    } finally {
        client.release();
    }
});

// DELETE specific high_bp post --endpoint
app.delete("/highBP/:id", async (req, res) => {
    const client = await pool.connect();
    const { id } = req.params;

    try {
        // Check high_bp post's existence
        const postExists = await client.query(
            "SELECT * FROM high_bp WHERE id = $1", 
            [id]
        );

        if (postExists.rows.length > 0) {
            await client.query(
                "DELETE FROM high_bp WHERE id = $1", 
                [id]
            );
    
            res.json({ message: "Successfully deleted" });
        } else {
            res.status(400).json({ error: "High blood pressure post not found" });
        }
    } catch (error) {
        console.log("Error:", error.message);
        res.status(500).json({ error: error.message })
    } finally {
        client.release();
    }
});

// Boilerplate code
app.get("/", (req, res) => {
    res.status(200).json({ message: "welcome to health monitoring app API" });
});

app.listen(PORT, () => {
    console.log(`App is listening on port ${PORT}`);
});