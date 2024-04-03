const express = require('express');
const bcrypt = require('bcryptjs');
const jsonwebtoken = require('jsonwebtoken');;
const cors = require('cors');
const dotenv = require('dotenv').config();
const { MongoClient, ObjectId } = require('mongodb')
const app = express();
const URL = process.env.DB
const shortid = require('shortid');
const secretKey = process.env.JWT_SECRET
const PORT = 4200;
const nodemailer = require("nodemailer");
const bodyParser = require('body-parser');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.mail,
        pass: process.env.pass,
    },
});
app.use(bodyParser.json());


app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors({
    origin: '*'
}));
app.get('/', (req, res) => {
    res.send(`<h1> server checking route </h1>`)
})
app.post("/short-url", async (req, res) => {
    try {
        const { originalUrl } = req.body
        const shortUrl = shortid.generate();
        const connection = await MongoClient.connect(URL)
        const db = connection.db("urls")
        const urlData = {
            originalUrl,
            shortUrl,
        }
        const result = await db.collection("urlData").insertOne(urlData)
        res.status(200).json({
            message: "URL shortend succesfully", url: {
                originalUrl,
                shortUrl,
            }
        })
        connection.close()
    } catch (error) {
        res.status(400).json({ message: "Something went wrong", error })
    }
})
app.get("/:shortUrl", async (req, res) => {
    try {
        const shortUrl = req.params.shortUrl;
        const connection = await MongoClient.connect(URL)
        const db = connection.db("urls")
        const result = await db.collection("urlData").findOne({ shortUrl })

        if (result) {
            // res.json({ result })
            res.redirect(result.originalUrl)
        } else {
            res.status(400).json({ message: "URL not found" })
        }
    } catch (error) {
        res.status(500).json({ message: "Something went wrong", error })
    }
})

app.post('/register', async (req, res) => {
    try {
        const { firstName, lastName, email, password, confirmPassword } = req.body
        const hashedPassword = await bcrypt.hash(password, 10);
        const connection = await MongoClient.connect(URL)
        const db = connection.db("users")
        const newUser = {
            firstName,
            lastName,
            email,
            password: hashedPassword,
            isActivated: false,
        }
        const result = await db.collection("Registered-users").insertOne(newUser)
        const token = jsonwebtoken.sign({ userId: result.insertedId }, secretKey, { expiresIn: '1h' });
        res.status(201).json({ message: 'Registration successful and activate link sent to your email', newUser, token });
        connection.close()
        const activateUrl = `https://url-shortern-ory6.onrender.com/activate-account/${email}/${token}`

        const info = await transporter.sendMail({
            from: process.env.mail,
            to: email,
            subject: 'Activation Link',
            text: `Click the following link to Activate your account: ${activateUrl}`
        });

        // res.status(200).json({ message: 'Password reset link sent successfully.' });

    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
})
app.get("/activate-account/:email/:token", async (req, res) => {
    try {
        const { email, token } = req.params;

        // Verify the token
        jsonwebtoken.verify(token, secretKey, async (err, decoded) => {
            if (err) {
                return res.status(401).json({ message: "Invalid or expired token" });
            }

            const connection = await MongoClient.connect(URL);
            const db = connection.db("users");

            const result = await db.collection("Registered-users").updateOne({ email, isActivated: false }, {
                $set: { isActivated: true },
            });

            if (result.modifiedCount === 1) {
                // res.status(200).json({ message: "Account activated successfully" }0);
                res.redirect(`https://main--grand-meringue-5caa6d.netlify.app`);
            } else {
                res.status(404).json({ message: "User not found or account is already activated" });
            }

            connection.close();
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body
        if (!email || !password) {
            return res.status(400).json({ message: 'Please provide email and password.' });
        }
        const connection = await MongoClient.connect(URL)
        const db = connection.db("users")
        const user = await db.collection("Registered-users").findOne({ email })
        if (!user) {
            res.status(404).json({ message: "User or password not match" })
        }

        if (!user.isActivated) {
            res.status(400).json({ message: "Please Activate your account", isActivated : user.isActivated})
        }
        const passwordValid = await bcrypt.compare(password, user.password)
        if (!passwordValid) {
            res.status(404).json({ message: "user or password not match" })
        }
        const token = jsonwebtoken.sign({ userId: user._id }, secretKey, { expiresIn: "1h" })
        res.status(200).json({ message: 'Login successful', token });
        connection.close()
    } catch (error) {
        console.log(error)
    }
})

app.post('/forget-password', async (req, res) => {
    try {
        const { email } = req.body;
        const connection = await MongoClient.connect(URL);
        const db = connection.db('users');
        const user = await db.collection('Registered-users').findOne({ email });

        if (!user) {
            res.status(404).json({ message: 'User not registered' });
        }
        const token = jsonwebtoken.sign({ id: user._id }, secretKey, { expiresIn: '1hr' });

        await db.collection('Registered-users').updateOne({ email }, {
            $set: { token }
        });

        connection.close();

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.mail,
                pass: process.env.pass,
            },
        });

        const info = await transporter.sendMail({
            from: process.env.mail,
            to: email,
            subject: 'Reset password link',
            text: `Click the following link to reset your password: https://main--grand-meringue-5caa6d.netlify.app/reset-password/${token}`
        });

        res.status(200).json({ message: 'Password reset link sent successfully.' });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'Failed to send password reset email.' });
    }
});

app.post("/reset-password/:token", async (req, res) => {
    try {
        const { password, confirmPassword } = req.body
        const token = req.params.token
        jsonwebtoken.verify(token, secretKey, async (err, decoded) => {
            try {
                if (err) {
                    res.json({
                        message: "Error with token"
                    })
                } else {
                    const hashedPassword = await bcrypt.hash(password, 10);
                    const connection = await MongoClient.connect(URL)
                    const db = connection.db("users")
                    const user = await db.collection("Registered-users").findOne({ token: token })

                    await db.collection("Registered-users").updateOne({ token }, {
                        $set: {
                            password: hashedPassword,
                            confirmPassword: hashedPassword
                        }
                    })
                    connection.close()
                    res.send({ message: "Password changed succesfully", user })
                }
            } catch (error) {
                console.log(error)
            }
        })

    } catch (error) {
        console.log(error)
    }

})
app.listen(PORT, () => {
    console.log(`server started at http://localhost:${PORT} ...`);
})