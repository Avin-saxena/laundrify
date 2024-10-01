// routes/payment.js
const express = require('express');
const router = express.Router();
const Razorpay = require('razorpay');
const auth = require('../middleware/auth');
const Order = require('../models/Order');

const razorpay = new Razorpay({
  key_id: 'YOUR_RAZORPAY_KEY_ID',
  key_secret: 'YOUR_RAZORPAY_SECRET',
});

// Create Order for Payment
router.post('/create-order', auth, async (req, res) => {
  const { orderId } = req.body;

  // Get Order Details
  const order = await Order.findById(orderId);
  if (!order) return res.status(404).send('Order not found');

  const options = {
    amount: order.totalAmount * 100, // Amount in paisa
    currency: 'INR',
    receipt: `receipt_order_${orderId}`,
  };

  try {
    const response = await razorpay.orders.create(options);
    res.send({ orderId: response.id });
  } catch (error) {
    console.log(error);
    res.status(500).send('Error creating payment order');
  }
});

module.exports = router;
