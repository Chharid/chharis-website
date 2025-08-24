const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const User = require('./models/User');

const app = express();
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));

// Session setup
app.use(session({
  secret: 'yourSecretKey',
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 24*60*60*1000 } // 1 day
}));

// MongoDB connection
mongoose.connect('mongodb://127.0.0.1:27017/userDB', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.log(err));

// Signup route
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const user = new User({ username, email, password: hashedPassword });
    await user.save();
    res.send(`<script>alert('Signup successful!'); window.location.href='/login.html';</script>`);
  } catch (err) {
    res.send(`<script>alert('Error: ${err.message}'); window.location.href='/signup.html';</script>`);
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password, remember } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.send(`<script>alert('User not found'); window.location.href='/login.html';</script>`);

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.send(`<script>alert('Incorrect password'); window.location.href='/login.html';</script>`);

  req.session.userId = user._id;
  if (remember) {
    req.session.cookie.maxAge = 7*24*60*60*1000; // 7 days
  }
  res.redirect('/dashboard.html');
});

// Route to get session user
app.get('/session-user', async (req, res) => {
  if (!req.session.userId) return res.json({});
  const user = await User.findById(req.session.userId);
  if (!user) return res.json({});
  res.json({ username: user.username });
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if(err) return res.send('Error logging out');
    res.redirect('/login.html');
  });
});

app.listen(3000, () => console.log('Server running at http://localhost:3000'));
