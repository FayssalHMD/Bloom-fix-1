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
    ingredients: [String],
    how_to_use: [String],
    reviews: [reviewSchema]
});

productSchema.virtual('mainImageUrl').get(function() {
    return this.mainImage ? this.mainImage.url : '/images/placeholder.jpg';
});

module.exports = mongoose.model('Product', productSchema);