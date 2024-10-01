// routes/orders.js
const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const Order = require('../models/Order');



router.get('/', auth, async (req, res) => {
    try {
      const orders = await Order.find({ userId: req.userId }).sort({ createdAt: -1 });
      res.json(orders);
    } catch (err) {
      res.status(500).send('Server Error');
    }
  });
  
// Create Order
router.post('/', auth, async (req, res) => {
  const { items } = req.body;

  // Calculate total amount
  let totalAmount = 0;
  items.forEach(item => {
    // Assume price calculation logic here
    item.price = calculatePrice(item);
    totalAmount += item.price * item.quantity;
  });

  // Create Order
  const order = new Order({
    userId: req.userId,
    items,
    totalAmount,
  });
  await order.save();

  res.send(order);
});

// Helper function to calculate price
function calculatePrice(item) {
  // Example pricing logic
  let basePrice = 0;
  if (item.clothType === 'Shirt') basePrice = 50;
  else if (item.clothType === 'Pant') basePrice = 60;
  // Service Type adjustment
  if (item.serviceType === 'Dry Cleaning') basePrice += 20;
  else if (item.serviceType === 'Ironing') basePrice += 10;
  return basePrice;
}

// routes/orders.js mein continue karte hain
const PDFDocument = require('pdfkit');
const nodemailer = require('nodemailer');

// After order.save()
router.post('/', auth, async (req, res) => {
  // ... existing code ...

  // Generate PDF Invoice
  const doc = new PDFDocument();
  let buffers = [];
  doc.on('data', buffers.push.bind(buffers));
  doc.on('end', async () => {
    let pdfData = Buffer.concat(buffers);

    // Send Email with PDF
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'your_email@example.com',
        pass: 'your_email_password',
      },
    });

    // Find User Email
    const user = await User.findById(req.userId);

    const mailOptions = {
      from: 'your_email@example.com',
      to: user.email,
      subject: 'Your Laundry Invoice',
      text: 'Please find attached your invoice.',
      attachments: [
        {
          filename: 'invoice.pdf',
          content: pdfData,
        },
      ],
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
        return res.status(500).send('Error sending email');
      }
      console.log('Email sent: ' + info.response);
      res.send(order);
    });
  });

  // Create PDF Content
  doc.fontSize(25).text('Laundry Invoice', { align: 'center' });
  doc.moveDown();

  items.forEach(item => {
    doc.fontSize(14).text(
      `${item.quantity} x ${item.clothType} (${item.serviceType}) - Rs. ${item.price * item.quantity}`
    );
  });

  doc.moveDown();
  doc.fontSize(16).text(`Total Amount: Rs. ${totalAmount}`, { align: 'right' });

  doc.end();
});



module.exports = router;
