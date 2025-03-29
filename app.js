const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const axios = require("axios");
const path = require("path");
const config = require("./config");
const PORT = process.env.PORT || 3000;
const app = express();
app.use(cors());
app.use(bodyParser.json());

mongoose.connect(config.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  balance: { type: Number, default: 0.00 }
});
const User = mongoose.model("User", UserSchema);

const verifyToken = (req, res, next) => {
  const token = req.header("Authorization");
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  jwt.verify(token, config.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Invalid Token" });
    req.user = decoded;
    next();
  });
};

app.post("/api/auth/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "All fields are required" });

  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    res.json({ message: "Signup successful" });
  } catch (err) {
    res.status(400).json({ error: "Email already exists" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "All fields are required" });

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

  const token = jwt.sign({ id: user._id }, config.JWT_SECRET, { expiresIn: "7d" });
  res.json({ message: "Login successful", token });
});

app.get("/api/user/dashboard", verifyToken, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password");
  if (!user) return res.status(404).json({ error: "User not found" });

  res.json({ user });
});

app.post("/api/payment", verifyToken, async (req, res) => {
  const { amount, email } = req.body;
  if (!amount || !email) return res.status(400).json({ error: "Amount and email required" });

  try {
    const response = await axios.post("https://api.paystack.co/transaction/initialize", {
      email,
      amount: amount * 100
    }, {
      headers: { Authorization: `Bearer ${config.PAYSTACK_SECRET_KEY}` }
    });

    res.json(response.data);
  } catch (err) {
    res.status(400).json({ error: "Payment initialization failed" });
  }
});

app.use(express.static(path.join(__dirname, "./public")));

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "./public/docs.html"))
})

app.get("/signup", (req, res) => res.sendFile(path.join(__dirname, "./public/signup.html")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "./public/sign-in.html")));
app.get("/airtime", (req, res) => res.sendFile(path.join(__dirname, "./public/airtime.html")));
app.get("/airtime2cash", (req, res) => res.sendFile(path.join(__dirname, "./public/airtime2cash.html")));
app.get("/cable", (req, res) => res.sendFile(path.join(__dirname, "./public/cable.html")));
app.get("/changePin", (req, res) => res.sendFile(path.join(__dirname, "./public/change-pin.html")));
app.get("/crypto", (req, res) => res.sendFile(path.join(__dirname, "./public/crypto.html")));
app.get("/dashboard", (req, res) => res.sendFile(path.join(__dirname, "./public/dashboard.html")));
app.get("/data", (req, res) => res.sendFile(path.join(__dirname, "./public/data.html")));
app.get("/docs", (req, res) => res.sendFile(path.join(__dirname, "./public/docs.html")));
app.get("/electricity", (req, res) => res.sendFile(path.join(__dirname, "./public/electricity.html")));
app.get("/forgotPass", (req, res) => res.sendFile(path.join(__dirname, "./public/forgot-password.html")));
app.get("/fundWallet", (req, res) => res.sendFile(path.join(__dirname, "./public/fund-wallet.html")));
app.get("/giftcards", (req, res) => res.sendFile(path.join(__dirname, "./public/giftcards.html")));
app.get("/gotv", (req, res) => res.sendFile(path.join(__dirname, "./public/gotv.html")));
app.get("/investment", (req, res) => res.sendFile(path.join(__dirname, "./public/investment.html")));
app.get("/referrals", (req, res) => res.sendFile(path.join(__dirname, "./public/referrals.html")));
app.get("/services", (req, res) => res.sendFile(path.join(__dirname, "./public/services.html")));
app.get("/settings", (req, res) => res.sendFile(path.join(__dirname, "./public/settings.html")));
app.get("/support", (req, res) => res.sendFile(path.join(__dirname, "./public/support.html")));
app.get("/transactionDetails", (req, res) => res.sendFile(path.join(__dirname, "./public/transaction-details.html")));
app.get("/transaction", (req, res) => res.sendFile(path.join(__dirname, "./public/transaction.html")));
app.get("/updatePass", (req, res) => res.sendFile(path.join(__dirname, "./public/update-password.html")));
app.get("/virtualCard", (req, res) => res.sendFile(path.join(__dirname, "./public/virtual-card.html")));
app.get("/withdraw", (req, res) => res.sendFile(path.join(__dirname, "./public/withdraw.html")));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));