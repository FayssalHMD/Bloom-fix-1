// models/User.js

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// --- NEW: Define a schema for items within the user's cart ---
const cartItemSchema = new mongoose.Schema({
    // We use productId and packId to reference the original product/pack
    productId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product' // Reference to the Product model
    },
    packId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Pack' // Reference to the Pack model
    },
    quantity: {
        type: Number,
        required: true,
        min: 1,
        default: 1
    },
    // Store key details directly in the cart for easier display
    name: String,
    price: Number,
    image: String,
    isPack: Boolean
}, { _id: false }); // _id: false is good practice for subdocuments if not needed



// --- DEFINITIVE FIX: A much simpler schema for the wishlist ---
const wishlistItemSchema = new mongoose.Schema({
    productId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product'
    },
    packId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Pack'
    }
}, { _id: false });




const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Le nom est requis.'],
        trim: true
    },
    email: {
        type: String,
        required: [true, "L'email est requis."],
        unique: true, 
        lowercase: true,
        trim: true,
        match: [/\S+@\S+\.\S+/, "Veuillez utiliser une adresse email valide."]
    },
    password: {
        type: String,
        required: [true, 'Le mot de passe est requis.'],
        minlength: [6, 'Le mot de passe doit contenir au moins 6 caractères.']
    },
    
    // --- MODIFICATION START: Add fields for email verification ---
    isVerified: {
        type: Boolean,
        default: false
    },
    emailVerificationToken: String,
    // --- MODIFICATION END ---

    shippingInfo: {
        fullName: { type: String, trim: true },
        phone: { type: String, trim: true },
        wilaya: { type: String, trim: true },
        address: { type: String, trim: true } 
    },

    cart: [cartItemSchema],

    wishlist: [wishlistItemSchema],

    passwordResetToken: String,
    passwordResetExpires: Date,

    createdAt: {
        type: Date,
        default: Date.now
    }
});


userSchema.pre('save', async function(next) {
    // This function remains unchanged
    const user = this;
    if (!user.isModified('password')) {
        return next();
    }
    try {
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(user.password, salt);
        user.password = hash;
        next();
    } catch (error) {
        next(error);
    }
});


userSchema.methods.comparePassword = async function(candidatePassword) {
    // This function remains unchanged
    return bcrypt.compare(candidatePassword, this.password);
};


module.exports = mongoose.model('User', userSchema);