// models/Pack.js

const mongoose = require('mongoose');

const packSchema = new mongoose.Schema({
    id: {
        type: String,
        required: true,
        unique: true
    },
    name: {
        type: String,
        required: true
    },
    contents: {
        type: String,
        required: true
    },
    description: {
        type: String,
        required: true
    },
    originalPrice: {
        type: Number,
        required: true
    },
    discountedPrice: {
        type: Number,
        required: true
    },
    // ==================================================
    //                 START OF CHANGES
    // ==================================================
    mainImage: {
        type: String,
        required: true
    },
    gallery: [String],
    // ==================================================
    //                  END OF CHANGES
    // ==================================================
});

// We no longer need imageSrc, so it has been removed.

module.exports = mongoose.model('Pack', packSchema);