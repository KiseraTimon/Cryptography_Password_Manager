const express = require("express");
const cors = require("cors");
const Keychain = require("./password-manager.js");

const app = express();
app.use(cors());
app.use(express.json());

let keychain;

// Initialize manager
app.post("/init", async (req, res) => {
    const { password } = req.body;
    keychain = await Keychain.init(password);
    res.json({ message: "Keychain initialized" });
});

// Set password
app.post("/set", async (req, res) => {
    const { domain, value } = req.body;
    await keychain.set(domain, value);
    res.json({ message: "Saved!" });
});

// Get password
app.post("/get", async (req, res) => {
    const { domain } = req.body;
    const v = await keychain.get(domain);
    res.json({ password: v });
});

// Delete
app.post("/remove", async (req, res) => {
    const { domain } = req.body;
    const done = await keychain.remove(domain);
    res.json({ removed: done });
});

app.listen(5500, () => console.log("Backend running on port 5500"));
