// models/FAQCategory.js
const mongoose = require('mongoose');

const faqCategorySchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Le nom de la catégorie est requis.'],
        unique: true,
        trim: true
    }
}, {
    timestamps: true
});

const FAQCategory = mongoose.model('FAQCategory', faqCategorySchema);

module.exports = FAQCategory;