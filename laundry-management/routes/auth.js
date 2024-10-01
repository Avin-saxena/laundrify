const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const passport = require('passport');
const fetch = require('node-fetch');
const { body, validationResult } = require('express-validator');
const { OAuth2Client } = require('google-auth-library');

const client = new OAuth2Client('149382474145-7ik4rf3dbop4o15uactedrdmaqchu3r1.apps.googleusercontent.com');

router.post('/google-login', async (req, res) => {
  const { credential } = req.body;

  try {
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: '149382474145-7ik4rf3dbop4o15uactedrdmaqchu3r1.apps.googleusercontent.com',
    });
    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    // Check if user exists
    let user = await User.findOne({ googleId });
    if (!user) {
      // If not, create a new user
      user = new User({
        name,
        email,
        googleId,
        avatar: picture,
      });
      await user.save();
    }

      // Generate JWT token
      const token = jwt.sign(
        { userId: user._id },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
  
      res.json({ token, userId: user._id });
    } catch (error) {
      console.error('Error verifying Google ID token:', error);
      res.status(401).json({ message: 'Invalid Google ID token' });
    }
  });


router.post('/signup', [
  body('name').trim().notEmpty().withMessage('Name is required'),
  body('email').isEmail().withMessage('Enter a valid email'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
  body('captchaToken').notEmpty().withMessage('reCAPTCHA token is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const name = req.body.name.trim();
  const email = req.body.email;
  const password = req.body.password.trim(); // Add this line
  const captchaToken = req.body.captchaToken;

  try {
    // Verify reCAPTCHA
    const recaptchaResponse = await fetch(`https://www.google.com/recaptcha/api/siteverify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${process.env.RECAPTCHA_SECRET}&response=${captchaToken}`,
    });
    const recaptchaData = await recaptchaResponse.json();

    if (!recaptchaData.success) {
      return res.status(400).json({ message: 'reCAPTCHA verification failed', details: recaptchaData });
    }

    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: 'User already exists' });

    console.log('Password before hashing:', password);
    const hashedPassword = await bcrypt.hash(password, 12);
    console.log('Hashed password during signup:', hashedPassword);
    const user = new User({ name, email, password: hashedPassword });
    console.log('User object before save:', user);

    await user.save();
    console.log('User object after save:', user);

    const savedUser = await User.findOne({ email }).select('+password');
console.log('Saved user:', savedUser);

const verifyHash = await bcrypt.compare(password, savedUser.password);
console.log('Verify hash result:', verifyHash);

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ message: 'User registered successfully', token });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Server error during signup', details: error.message });
  }
});

// Login Route
router.post('/login', [
  body('email').isEmail().withMessage('Enter a valid email'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  // Validation check
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const email = req.body.email;
  const password = req.body.password.trim();
  console.log('Login attempt:', { email, password: password.replace(/./g, '*') });
  console.log('Password length:', password.length);
  

  try {
    // Find User
    const user = await User.findOne({ email }).select('+password');
    console.log('User found:', user);
    if (!user) {
      console.log('User not found');
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    if (!user.password) {
      console.error('Password field is missing in the user document');
      return res.status(500).json({ message: 'Server error: password missing' });
    }
    // Password Match
    const isMatch = await bcrypt.compare(password, user.password);
    console.log('Password received during login:', password);
console.log('Stored hashed password:', user.password);
console.log('Password match result:', isMatch);

    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    // JWT Token Generate
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token, userId: user._id });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Google Auth Route
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google Auth Callback
router.get(
  '/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    try {
      // Successful authentication
      // Generate JWT token and send to client
      const token = jwt.sign(
        { userId: req.user._id },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.redirect(`${process.env.CLIENT_URL}?token=${token}`);
    } catch (error) {
      console.error('Google auth callback error:', error);
      res.redirect('/login?error=auth_failed');
    }
  }
);

module.exports = router;