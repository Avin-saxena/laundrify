// index.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const app = express();
const session = require('express-session');
const passport = require('./config/passport');
const cors = require('cors');

// Middleware
app.use(express.json());
app.use(cors());

app.use(
    session({
      secret: 'your_session_secret',
      resave: false,
      saveUninitialized: false,
    })
  );
  app.use(passport.initialize());
  app.use(passport.session());
  

// Database Connection
const dbURI = process.env.MONGO_URI || 'mongodb://localhost:27017/laundryDB';
mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB'))
    .catch((error) => console.log('Error connecting to MongoDB:', error));


/****************routes ko server me use kiya*****************/
const authRoutes = require('./routes/auth');
app.use('/auth', authRoutes);

// index.js mein
const orderRoutes = require('./routes/orders');
app.use('/orders', orderRoutes);
/*********************************************************************** */

// Test Route
app.get('/', (req, res) => {
  res.send('Laundry Management System API');
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!', error: err.message });
});
app.use('/auth', authRoutes);
app.use('/orders', orderRoutes);


// Server Start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
