// models/FAQItem.js
const mongoose = require('mongoose');

const faqItemSchema = new mongoose.Schema({
    question: {
        type: String,
        required: [true, 'La question est requise.'],
        trim: true
    },
    answer: {
        type: String,
        required: [true, 'La réponse est requise.'],
        trim: true
    },
    category: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'FAQCategory', // This is the crucial link to the other model
        required: [true, 'La catégorie est requise.']
    },
    sortOrder: {
        type: Number,
        default: 0 // We can implement sorting later if needed
    }
}, {
    timestamps: true
});

const FAQItem = mongoose.model('FAQItem', faqItemSchema);

module.exports = FAQItem;