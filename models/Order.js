// models/Order.js

const mongoose = require('mongoose');

// We define the schema for nested objects first
const customerSchema = new mongoose.Schema({
    fullName: String,
    phone: String,
    wilaya: String,
    deliveryMethod: String,
    address: String
}, { _id: false }); // _id: false prevents Mongoose from creating an id for this sub-document

const itemSchema = new mongoose.Schema({
    id: String,
    name: String,
    price: Number,
    image: String,
    isPack: Boolean,
    quantity: Number
}, { _id: false });

// Now we define the main order schema
const orderSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User', 
        required: false 
    },
    customer: customerSchema,
    items: [itemSchema],
    total: String,
    status: { // <-- ADD THIS WHOLE BLOCK
        type: String,
        required: true,
        default: 'New', // Automatically set the status of new orders to 'New'
        enum: ['New', 'Processing', 'Shipped', 'Completed', 'Canceled'] // Optional: Restricts the status to only these values
    },
    createdAt: {
        type: Date,
        default: Date.now
    } 


});

module.exports = mongoose.model('Order', orderSchema);