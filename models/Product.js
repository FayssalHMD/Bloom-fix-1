// models/Product.js

const mongoose = require('mongoose');

const reviewSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'User'
    },
    name: {
        type: String,
        required: true
    },
    rating: {
        type: Number,
        required: true,
        min: 1,
        max: 5
    },
    comment: {
        type: String,
        required: true
    }
}, {
    timestamps: true
});

const productSchema = new mongoose.Schema({
    id: { // This is the slug for the URL
        type: String,
        required: true,
        unique: true
    },
    name: {
        type: String,
        required: true
    },
    short_description: {
        type: String,
        required: true
    },
    description: {
        type: String,
        required: true
    },
    price: {
        type: Number,
        required: true
    },
    // ==================================================
    //                 START OF CHANGES
    // ==================================================
    mainImage: {
        type: String,
        required: true // The main image is now mandatory
    },
    gallery: [String], // An array of strings for additional images
    // ==================================================
    //                  END OF CHANGES
    // ==================================================
    ingredients: [String],
    how_to_use: [String],
    reviews: [reviewSchema]
});

module.exports = mongoose.model('Product', productSchema);