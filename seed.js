// seed.js

require('dotenv').config(); // To access environment variables
const mongoose = require('mongoose');

// Import the models
const Product = require('./models/Product');
const Pack = require('./models/Pack');

// Import the data from JSON files
const productsData = require('./data/products.json');
const packsData = require('./data/packs.json');

const seedDatabase = async () => {
    try {
        // 1. Connect to the database
        await mongoose.connect(process.env.DATABASE_URL);
        console.log('MongoDB Connected for seeding...');

        // 2. Clear existing data (optional, but good for clean slate)
        await Product.deleteMany({});
        await Pack.deleteMany({});
        console.log('Cleared existing products and packs.');

        // 3. Insert the new data
        await Product.insertMany(productsData);
        console.log('Products have been seeded!');

        await Pack.insertMany(packsData);
        console.log('Packs have been seeded!');

    } catch (error) {
        console.error('Error while seeding the database:', error);
    } finally {
        // 4. Disconnect from the database
        mongoose.connection.close();
        console.log('MongoDB connection closed.');
    }
};

// Run the seeding function
seedDatabase();