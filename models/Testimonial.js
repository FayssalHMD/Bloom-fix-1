// models/Testimonial.js

const mongoose = require('mongoose');

const imageSchema = {
    url: { type: String, required: true },
    public_id: { type: String, required: true }
};

const testimonialSchema = new mongoose.Schema({
    type: {
        type: String,
        required: true,
        enum: ['before-after', 'instagram'],
        default: 'instagram'
    },
    beforeImage: {
        type: imageSchema,
        // Required only if type is 'before-after'
        required: function() { return this.type === 'before-after'; }
    },
    afterImage: {
        type: imageSchema,
        // Required only if type is 'before-after'
        required: function() { return this.type === 'before-after'; }
    },
    instagramImage: {
        type: imageSchema,
        // Required only if type is 'instagram'
        required: function() { return this.type === 'instagram'; }
    },
    quote: {
        type: String,
        trim: true
    },
    story: {
        type: String,
        trim: true
    },
    featuredProducts: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product'
    }]
}, {
    timestamps: true // Adds createdAt and updatedAt timestamps
});

module.exports = mongoose.model('Testimonial', testimonialSchema);