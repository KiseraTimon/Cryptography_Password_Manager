const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { Keychain } = require("./password-manager");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));


// Temporary in-memory database
const users = {};

// Default Route
app.get("/", (req, res) => {
    res.sendFile(__dirname + "/public/index.html");
});

// Signup
app.post("/signup", async (req, res) => {
    const { email, password } = req.body;

    if (users[email]) {
        console.log("Signup failed: user exists ->", email);
        return res.status(400).json({ message: "User already exists" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const keychain = await Keychain.init(password);
    const [repr, checksum] = await keychain.dump();

    users[email] = { passwordHash, keychainRepr: repr, checksum };

    console.log("Signup successful for:", email);
    console.log("Current users database:", users);

    res.json({ message: "Account created successfully" });
});



// Signin
app.post("/signin", async (req, res) => {
    const { email, password } = req.body;

    const user = users[email];
    if (!user) {
        console.log("Signin failed: user not found ->", email);
        return res.status(404).json({ message: "User not found" });
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
        console.log("Signin failed: wrong password ->", email);
        return res.status(401).json({ message: "Wrong password" });
    }

    const keychain = await Keychain.load(password, user.keychainRepr, user.checksum);
    user.sessionKeychain = keychain;

    console.log("Signin successful for:", email);
    console.log("Current users database:", users);

    res.json({ message: "Login successful" });
});



// Set Password
app.post("/set", async (req, res) => {
    const { email, domain, value } = req.body;

    const user = users[email];
    if (!user || !user.sessionKeychain)
        return res.status(401).json({ message: "Not logged in" });

    await user.sessionKeychain.set(domain, value);

    // Save updated keychain
    const [repr, checksum] = await user.sessionKeychain.dump();
    user.keychainRepr = repr;
    user.checksum = checksum;

    res.json({ message: "Password saved!" });
});


// Get Password
app.post("/get", async (req, res) => {
    const { email, domain } = req.body;

    const user = users[email];
    if (!user || !user.sessionKeychain)
        return res.status(401).json({ message: "Not logged in" });

    const value = await user.sessionKeychain.get(domain);

    res.json({ value });
});


// Debugging
app.get("/users", (req, res) => {
    res.json(users);
});



// Start server
app.listen(3000, () => console.log("Server running on port 3000"));
