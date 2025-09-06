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
        url: { type: String, required: true },
        public_id: { type: String, required: true }
    },
    gallery: [
        {
            url: { type: String, required: true },
            public_id: { type: String, required: true }
        }
    ],
    // ==================================================
    //                  END OF CHANGES
    // ==================================================
});

// We no longer need imageSrc, so it has been removed.

module.exports = mongoose.model('Pack', packSchema);