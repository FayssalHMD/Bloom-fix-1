require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const session = require('express-session');
const { body, validationResult } = require('express-validator');
const slugify = require('slugify');
const flash = require('connect-flash');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// --- MODEL IMPORTS ---
const Product = require('./models/Product');
const Pack = require('./models/Pack');
const Order = require('./models/Order');
const User = require('./models/User');
const ContactSubmission = require('./models/ContactSubmission');
const Testimonial = require('./models/Testimonial');
const {
  sendNewOrderNotification,
  sendPasswordResetEmail,
  sendContactFormEmail,
  sendVerificationEmail,
} = require('./services/emailService');

const app = express();
app.set('trust proxy', 1);
const port = process.env.PORT || 3000;

// ==================================================
//         VIEW ENGINE & CORE MIDDLEWARE
// ==================================================
app.set('view engine', 'ejs');
app.set('views', 'views');
app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==================================================
//         SESSION & TEMPLATE LOCALS
// ==================================================
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);

app.use(flash());

app.use((req, res, next) => {
  res.locals.messages = req.flash();
  next();
});

app.use(async (req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.isAdmin = req.session.isAdmin || false;
  res.locals.maskEmail = maskEmail;
  if (req.session.user) {
    try {
      res.locals.userDetails = await User.findById(req.session.user.id);
    } catch (error) {
      console.error('Error fetching user details for locals:', error);
      res.locals.userDetails = null;
    }
  } else {
    res.locals.userDetails = null;
  }
  next();
});

// ==================================================
//         SECURITY MIDDLEWARE (HELMET & RATE LIMIT)
// ==================================================
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('hex');
  next();
});
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          'https://kit.fontawesome.com',
          'https://cdn.jsdelivr.net',
          (req, res) => `'nonce-${res.locals.nonce}'`,
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          'https://fonts.googleapis.com',
          'https://cdn.jsdelivr.net',
        ],
        fontSrc: [
          "'self'",
          'https://fonts.gstatic.com',
          'https://ka-f.fontawesome.com',
          'data:',
        ],
        connectSrc: ["'self'", 'https://ka-f.fontawesome.com'],
        imgSrc: ["'self'", 'data:', 'blob:'],
      },
    },
  })
);

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Trop de tentatives. Veuillez réessayer dans 15 minutes.',
});

app.use('/api/', apiLimiter);
app.use('/contact', apiLimiter);
app.use('/create-order', apiLimiter);
app.use('/create-direct-order', apiLimiter);
app.use('/login', authLimiter);
app.use('/register', authLimiter);
app.use('/forgot-password', authLimiter);
app.use('/reset-password', authLimiter);

// ==================================================
//         MULTER CONFIGURATION
// ==================================================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dest = 'public/images/products';
    fs.mkdirSync(dest, { recursive: true });
    cb(null, dest);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(
      null,
      file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname)
    );
  },
});
const fileFilter = (req, file, cb) =>
  file.mimetype.startsWith('image')
    ? cb(null, true)
    : cb(new Error('Not an image!'), false);
const upload = multer({ storage, fileFilter });
const productUpload = upload.fields([
  { name: 'mainImage', maxCount: 1 },
  { name: 'gallery', maxCount: 5 },
]);
const testimonialUpload = upload.fields([
  { name: 'beforeImage', maxCount: 1 },
  { name: 'afterImage', maxCount: 1 },
  { name: 'instagramImage', maxCount: 1 },
]);

// ==================================================
//      FORM VALIDATION RULES
// ==================================================
const productValidationRules = [
  body('name', 'Le nom du produit est requis.').not().isEmpty().trim().escape(),
  body('price', 'Le prix doit être un nombre valide.')
    .isFloat({ gt: 0 })
    .trim(),
  body('short_description', 'La description courte est requise.')
    .not()
    .isEmpty()
    .trim()
    .escape(),
  body('description', 'La description complète est requise.')
    .not()
    .isEmpty()
    .trim()
    .escape(),
];
const packValidationRules = [
  body('name', 'Le nom du pack est requis.').not().isEmpty().trim().escape(),
  body('contents', 'Le contenu du pack est requis.')
    .not()
    .isEmpty()
    .trim()
    .escape(),
  body('originalPrice', 'Le prix original doit être un nombre valide.')
    .isFloat({ gt: 0 })
    .trim(),
  body('discountedPrice', 'Le prix réduit doit être un nombre valide.')
    .isFloat({ gt: 0 })
    .trim()
    .custom((value, { req }) => {
      if (parseFloat(value) >= parseFloat(req.body.originalPrice)) {
        throw new Error('Le prix réduit doit être inférieur au prix original.');
      }
      return true;
    }),
  body('description', 'La description complète est requise.')
    .not()
    .isEmpty()
    .trim()
    .escape(),
];

// --- HELPER FUNCTIONS ---
const maskEmail = (email) => {
  if (!email) return '';
  const [name, domain] = email.split('@');
  if (name.length <= 3) {
    return `${name.slice(0, 1)}***@${domain}`;
  }
  return `${name.slice(0, 3)}***@${domain}`;
};
const deleteFile = (filePath) => {
  const fullPath = path.join(__dirname, 'public', filePath);
  if (fs.existsSync(fullPath)) {
    fs.unlink(fullPath, (err) => {
      if (err) {
        console.error(`Failed to delete file: ${fullPath}`, err);
      }
    });
  }
};

// --- DATABASE CONNECTION ---
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.DATABASE_URL);
    console.log('MongoDB Connected successfully!');
  } catch (error) {
    console.error('MongoDB connection FAILED:', error);
    process.exit(1);
  }
};
connectDB();

// --- ROUTE MIDDLEWARE ---
const authMiddleware = (req, res, next) => {
  if (req.session.isAdmin) {
    next();
  } else {
    res.redirect('/admin');
  }
};
const userAuthMiddleware = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
     if (req.originalUrl.startsWith('/api/')) {
        return res.status(401).json({ success: false, message: 'Veuillez vous connecter.' });
    }
    res.redirect('/login');
  }
};

// ==================================================
//      API & PUBLIC ROUTES
// ==================================================
// (All routes from here down to the admin section are unchanged)
app.get('/api/shipping-info', (req, res) => {
    try {
        const shippingInfoPath = path.join(__dirname, 'data', 'shippingInfo.json');
        const shippingData = fs.readFileSync(shippingInfoPath, 'utf8');
        res.setHeader('Content-Type', 'application/json');
        res.send(shippingData);
    } catch (error) {
        console.error('FATAL: Could not read shippingInfo.json.', error);
        res.status(500).json({ success: false, message: 'Could not load shipping information.' });
    }
});

app.post('/create-order',
    [
        body('customer.fullName', 'Le nom complet est requis').not().isEmpty().trim().escape(),
        body('customer.phone', 'Un numéro de téléphone valide est requis').isMobilePhone('any', { strictMode: false }).trim(),
        body('customer.wilaya', 'La wilaya est requise').not().isEmpty()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ success: false, message: 'Données invalides.', errors: errors.array() });
        }
        try {
            const { customer, items, shippingCost } = req.body;
            if (!items || items.length === 0) {
                return res.status(400).json({ success: false, message: 'Le panier est vide.' });
            }
            const productIds = items.filter(item => !item.isPack).map(item => item.productId);
            const packIds = items.filter(item => item.isPack).map(item => item.packId);
            const [productsFromDB, packsFromDB] = await Promise.all([Product.find({ '_id': { $in: productIds } }), Pack.find({ '_id': { $in: packIds } })]);
            let serverCalculatedSubtotal = 0;
            const verifiedItems = [];
            for (const clientItem of items) {
                let dbItem = null, priceFromDB = 0;
                if (clientItem.isPack) {
                    dbItem = packsFromDB.find(p => p._id.toString() === clientItem.packId);
                    if (dbItem) priceFromDB = dbItem.discountedPrice;
                } else {
                    dbItem = productsFromDB.find(p => p._id.toString() === clientItem.productId);
                    if (dbItem) priceFromDB = dbItem.price;
                }
                if (dbItem) {
                    verifiedItems.push({
                        productId: clientItem.isPack ? null : dbItem._id, packId: clientItem.isPack ? dbItem._id : null, name: dbItem.name,
                        quantity: clientItem.quantity, price: priceFromDB, isPack: clientItem.isPack, image: dbItem.mainImage
                    });
                    serverCalculatedSubtotal += priceFromDB * clientItem.quantity;
                } else { console.warn(`Item with ID ${clientItem.productId || clientItem.packId} not found in DB. Skipping.`); }
            }
            if (verifiedItems.length === 0) return res.status(400).json({ success: false, message: 'Aucun article valide dans le panier.' });
            const serverCalculatedTotal = serverCalculatedSubtotal + parseFloat(shippingCost || 0);
            const orderData = { customer, items: verifiedItems, subtotal: serverCalculatedSubtotal, shipping: parseFloat(shippingCost || 0), total: serverCalculatedTotal.toFixed(2) + " DA" };
            if (req.session.user) orderData.user = req.session.user.id;
            const newOrder = new Order(orderData);
            await newOrder.save();
            try { await sendNewOrderNotification(newOrder); }
            catch (emailError) { console.error(`CRITICAL: Order ${newOrder._id} was saved, but email notification failed.`, emailError); }
            res.json({ success: true, message: 'Order received successfully!' });
        } catch (error) {
            console.error('ERROR: Failed to save the order to database.', error);
            res.status(500).json({ success: false, message: 'Could not process the order.' });
        }
    }
);

app.post('/create-direct-order', [
    body('customer.fullName', 'Le nom complet est requis').not().isEmpty().trim().escape(),
    body('customer.phone', 'Un numéro de téléphone valide est requis').isMobilePhone('any', { strictMode: false }).trim(),
    body('customer.wilaya', 'La wilaya est requise').not().isEmpty().trim().escape(),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, message: 'Données invalides.', errors: errors.array() });
    }

    try {
        const { customer, item } = req.body;
        if (!item || !item.id || !item.quantity) {
            return res.status(400).json({ success: false, message: 'Article invalide.' });
        }

        let dbItem;
        let priceFromDB;
        let verifiedItem;

        if (item.isPack) {
            dbItem = await Pack.findById(item.id);
            if (dbItem) priceFromDB = dbItem.discountedPrice;
        } else {
            dbItem = await Product.findById(item.id);
            if (dbItem) priceFromDB = dbItem.price;
        }

        if (!dbItem) {
            return res.status(404).json({ success: false, message: 'Article non trouvé.' });
        }

        verifiedItem = {
            productId: item.isPack ? null : dbItem._id,
            packId: item.isPack ? dbItem._id : null,
            name: dbItem.name,
            quantity: item.quantity,
            price: priceFromDB,
            isPack: item.isPack,
            image: dbItem.mainImage
        };

        const shippingInfoPath = path.join(__dirname, 'data', 'shippingInfo.json');
        const shippingData = JSON.parse(fs.readFileSync(shippingInfoPath, 'utf8'));
        const wilayaData = shippingData.find(w => w.name === customer.wilaya);

        if (!wilayaData) {
            return res.status(400).json({ success: false, message: 'Wilaya de livraison invalide.' });
        }

        let shippingCost = 0;
        if (customer.deliveryMethod === 'home') {
            shippingCost = wilayaData.homePrice;
        } else if (customer.deliveryMethod === 'stopdesk' && wilayaData.hasStopdesk) {
            shippingCost = wilayaData.stopdeskPrice;
        } else {
            shippingCost = wilayaData.homePrice;
        }

        const subtotal = priceFromDB * item.quantity;
        const total = subtotal + shippingCost;

        const orderData = {
            customer,
            items: [verifiedItem],
            subtotal: subtotal,
            shipping: shippingCost,
            total: total.toFixed(2) + " DA"
        };

        if (req.session.user) {
            orderData.user = req.session.user.id;
        }

        const newOrder = new Order(orderData);
        await newOrder.save();

        try {
            await sendNewOrderNotification(newOrder);
        } catch (emailError) {
            console.error(`CRITICAL: Direct Order ${newOrder._id} was saved, but email notification failed.`, emailError);
        }

        res.json({ success: true, message: 'Direct order received successfully!' });

    } catch (error) {
        console.error('ERROR: Failed to save direct order to database.', error);
        res.status(500).json({ success: false, message: 'Could not process the direct order.' });
    }
});

app.get('/api/search', async (req, res) => {
    const query = req.query.q;
    if (!query || query.trim().length < 2) return res.json([]);
    try {
        const regex = new RegExp(query, 'i');
        const productsPromise = Product.find({ $or: [{ name: regex }, { short_description: regex }] }).limit(5);
        const packsPromise = Pack.find({ $or: [{ name: regex }, { contents: regex }] }).limit(5);
        const [products, packs] = await Promise.all([productsPromise, packsPromise]);
        const productResults = products.map(p => ({ name: p.name, url: `/produit/${p.id}`, image: p.mainImage })).filter(p => !p.url.endsWith('undefined'));
        const packResults = packs.map(p => ({ name: p.name, url: `/packs/${p.id}`, image: p.mainImage })).filter(p => !p.url.endsWith('undefined'));
        res.json([...productResults, ...packResults]);
    } catch (error) {
        console.error('API Search Error:', error);
        res.status(500).json({ message: 'Error during search.' });
    }
});

app.post('/api/cart/sync', async (req, res) => {
    try {
        const clientCartItems = req.body.items;
        if (!clientCartItems || !Array.isArray(clientCartItems) || clientCartItems.length === 0) {
            return res.json({ success: true, cart: [] });
        }
        const productIds = [], packIds = [];
        clientCartItems.forEach(item => item.isPack ? packIds.push(item.id) : productIds.push(item.id));
        const [productsFromDB, packsFromDB] = await Promise.all([
            Product.find({ '_id': { $in: productIds } }).lean(),
            Pack.find({ '_id': { $in: packIds } }).lean()
        ]);
        const masterDataMap = new Map();
        productsFromDB.forEach(p => masterDataMap.set(p._id.toString(), { ...p, type: 'Product' }));
        packsFromDB.forEach(p => masterDataMap.set(p._id.toString(), { ...p, type: 'Pack' }));
        const syncedCart = clientCartItems.map(clientItem => {
            const dbItem = masterDataMap.get(clientItem.id);
            if (!dbItem) return null;
            const price = dbItem.type === 'Pack' ? dbItem.discountedPrice : dbItem.price;
            return {
                productId: dbItem.type === 'Product' ? dbItem._id : undefined,
                packId: dbItem.type === 'Pack' ? dbItem._id : undefined,
                name: dbItem.name, price, image: dbItem.mainImage, isPack: dbItem.type === 'Pack',
                quantity: clientItem.quantity
            };
        }).filter(item => item !== null);
        res.json({ success: true, cart: syncedCart });
    } catch (error) {
        console.error('API Cart Sync Error:', error);
        res.status(500).json({ success: false, message: 'Failed to synchronize cart.' });
    }
});

const validateMongoId = (req, res, next) => {
    const id = req.body.productId || req.body.packId;
    if (id && !mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ success: false, message: 'Invalid item ID.' });
    }
    next();
};

app.post('/api/cart', userAuthMiddleware, validateMongoId, async (req, res) => {
    try {
        const { productId, packId, quantity, name, price, image, isPack } = req.body;
        const user = await User.findById(req.session.user.id);
        const existingItemIndex = user.cart.findIndex(item => (isPack && item.packId?.toString() === packId) || (!isPack && item.productId?.toString() === productId));
        if (existingItemIndex > -1) {
            user.cart[existingItemIndex].quantity += quantity;
        } else {
            user.cart.push({ productId, packId, quantity, name, price, image, isPack });
        }
        await user.save();
        res.json({ success: true, message: 'Cart updated.', cart: user.cart });
    } catch (error) {
        console.error('API Cart Update Error:', error);
        res.status(500).json({ success: false, message: 'Failed to update cart.' });
    }
});

app.put('/api/cart', userAuthMiddleware, validateMongoId, async (req, res) => {
    try {
        const { productId, packId, quantity, isPack } = req.body;
        const user = await User.findById(req.session.user.id);
        const existingItemIndex = user.cart.findIndex(item => (isPack && item.packId?.toString() === packId) || (!isPack && item.productId?.toString() === productId));
        if (existingItemIndex > -1) {
            if (quantity > 0) user.cart[existingItemIndex].quantity = quantity;
            else user.cart.splice(existingItemIndex, 1);
            await user.save();
            res.json({ success: true, message: 'Cart quantity updated.', cart: user.cart });
        } else {
            res.status(404).json({ success: false, message: 'Item not found in cart.' });
        }
    } catch (error) {
        console.error('API Cart Quantity Update Error:', error);
        res.status(500).json({ success: false, message: 'Failed to update cart quantity.' });
    }
});

app.delete('/api/cart', userAuthMiddleware, validateMongoId, async (req, res) => {
    try {
        const { productId, packId, isPack } = req.body;
        await User.updateOne({ _id: req.session.user.id }, { $pull: { cart: isPack ? { packId: packId } : { productId: productId } } });
        res.json({ success: true, message: 'Item removed from cart.' });
    } catch (error) {
        console.error('API Cart Delete Error:', error);
        res.status(500).json({ success: false, message: 'Failed to remove item.' });
    }
});

app.delete('/api/cart/clear', userAuthMiddleware, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.session.user.id, { $set: { cart: [] } });
        res.json({ success: true, message: 'Cart cleared.' });
    } catch (error) {
        console.error('API Clear Cart Error:', error);
        res.status(500).json({ success: false, message: 'Failed to clear cart.' });
    }
});

app.post('/api/wishlist/toggle', userAuthMiddleware, async (req, res) => {
    try {
        const { itemId, itemType } = req.body;
        const user = await User.findById(req.session.user.id);
        const isProduct = itemType === 'Product';
        const queryKey = isProduct ? 'productId' : 'packId';
        const itemIndex = user.wishlist.findIndex(item => item[queryKey]?.toString() === itemId);
        let added;
        if (itemIndex > -1) {
            user.wishlist.splice(itemIndex, 1);
            added = false;
        } else {
            user.wishlist.push({ [queryKey]: itemId });
            added = true;
        }
        await user.save();
        res.json({ success: true, action: added ? 'added' : 'removed' });
    } catch (error) {
        console.error('API Wishlist Toggle Error:', error);
        res.status(500).json({ success: false, message: 'Failed to update wishlist.' });
    }
});

app.post('/api/products/:id/reviews', userAuthMiddleware, [
    body('rating', 'La note est requise.').isInt({ min: 1, max: 5 }),
    body('comment', 'Le commentaire ne peut pas être vide.').not().isEmpty().trim().escape()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, message: errors.array()[0].msg });

    try {
        const product = await Product.findById(req.params.id);
        if (!product) return res.status(404).json({ success: false, message: 'Produit non trouvé.' });
        const alreadyReviewed = product.reviews.some(review => review.user.toString() === req.session.user.id);
        if (alreadyReviewed) return res.status(400).json({ success: false, message: 'Vous avez déjà laissé un avis pour ce produit.' });

        const review = {
            user: req.session.user.id,
            name: req.session.user.name,
            rating: Number(req.body.rating),
            comment: req.body.comment,
        };
        product.reviews.unshift(review);
        await product.save();
        res.status(201).json({ success: true, message: 'Avis ajouté!', review: product.reviews[0] });
    } catch (error) {
        console.error('API Add Review Error:', error);
        res.status(500).json({ success: false, message: 'Erreur du serveur.' });
    }
});

app.delete('/api/reviews/:reviewId', userAuthMiddleware, async (req, res) => {
    try {
        const product = await Product.findOne({ "reviews._id": req.params.reviewId });
        if (!product) return res.status(404).json({ success: false, message: 'Avis non trouvé.' });

        const review = product.reviews.id(req.params.reviewId);
        if (review.user.toString() !== req.session.user.id) return res.status(403).json({ success: false, message: 'Action non autorisée.' });
        
        product.reviews.pull({ _id: req.params.reviewId });
        await product.save();
        res.json({ success: true, message: 'Avis supprimé.' });
    } catch (error) {
        console.error('API User Delete Review Error:', error);
        res.status(500).json({ success: false, message: 'Erreur du serveur.' });
    }
});

app.delete('/api/admin/reviews/:productId/:reviewId', authMiddleware, async (req, res) => {
    try {
        const { productId, reviewId } = req.params;
        const product = await Product.findById(productId);
        if (!product) return res.status(404).json({ success: false, message: 'Produit non trouvé.' });
        product.reviews.pull({ _id: reviewId });
        await product.save();
        res.json({ success: true, message: 'Avis supprimé avec succès.' });
    } catch (error) {
        console.error('API Admin Delete Review Error:', error);
        res.status(500).json({ success: false, message: 'Erreur du serveur.' });
    }
});

app.get('/', async (req, res) => {
  try {
    const products = await Product.find({});
    const packs = await Pack.find({});
    res.render('index', {
      pageTitle: 'Bloom - Douce au Naturelle',
      products: products,
      packs: packs,
      pageType: 'home',
    });
  } catch (error) {
    console.error('Error fetching data for homepage:', error);
    res.status(500).send('Error loading page.');
  }
});

app.get('/boutique', async (req, res) => {
  try {
    const [products, packs] = await Promise.all([
      Product.find({}).sort({ createdAt: -1 }),
      Pack.find({}).sort({ createdAt: -1 }),
    ]);
    res.render('boutique', {
      pageTitle: 'Notre Collection Complète - Bloom',
      pageType: 'boutique',
      products: products,
      packs: packs,
    });
  } catch (error) {
    console.error('Error fetching data for boutique page:', error);
    res.status(500).render('admin-error', {
      pageType: 'error',
      message: 'Impossible de charger notre collection.',
    });
  }
});

app.get('/produit/:id', async (req, res) => {
  try {
    const productSlug = req.params.id;
    const reviewPage = parseInt(req.query.reviewPage) || 1;
    const reviewsLimit = 3;
    const reviewsSkip = (reviewPage - 1) * reviewsLimit;
    const product = await Product.findOne({ id: productSlug });
    if (!product) {
      return res.status(404).send('Product not found');
    }
    const paginatedReviewsResult = await Product.findOne(
      { id: productSlug },
      {
        reviews: { $slice: [reviewsSkip, reviewsLimit] },
      }
    ).populate({
      path: 'reviews.user',
      select: 'email',
    });
    const totalReviews = product.reviews.length;
    const totalReviewPages = Math.ceil(totalReviews / reviewsLimit);
    res.render('product', {
      pageTitle: product.name,
      product: product,
      reviews: paginatedReviewsResult.reviews,
      pageType: 'product',
      currentReviewPage: reviewPage,
      totalReviewPages: totalReviewPages,
      totalReviewsCount: totalReviews,
    });
  } catch (error) {
    console.error('Error fetching product page:', error);
    res.status(500).send('Error loading product page.');
  }
});

app.get('/packs/:id', async (req, res) => {
  try {
    const pack = await Pack.findOne({ id: req.params.id });
    if (pack) {
      res.render('pack', {
        pageTitle: pack.name,
        pack: pack,
        pageType: 'product',
      });
    } else {
      res.status(404).send('Pack not found');
    }
  } catch (error) {
    console.error('Error fetching pack:', error);
    res.status(500).send('Error loading pack page.');
  }
});

app.get('/panier', (req, res) => {
  res.render('panier', {
    pageTitle: 'Votre Panier',
    pageType: 'cart',
  });
});

app.get('/contact', (req, res) => {
  res.render('contact', {
    pageTitle: 'Contactez-nous - Bloom',
    pageType: 'contact',
    errors: [],
    successMessage: null,
    oldInput: {},
  });
});

app.post(
  '/contact',
  [
    body('name', 'Le nom et prénom sont requis.')
      .not()
      .isEmpty()
      .trim()
      .escape(),
    body('email', 'Veuillez fournir une adresse email valide.')
      .isEmail()
      .normalizeEmail(),
    body('subject', 'Le sujet est requis.').not().isEmpty().trim().escape(),
    body('message', 'Le message ne peut pas être vide.')
      .not()
      .isEmpty()
      .trim()
      .escape(),
    body('comment').trim().escape(),
  ],
  async (req, res) => {
    if (req.body.comment) {
      return res.redirect('/contact?status=success');
    }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('contact', {
        pageTitle: 'Contactez-nous - Bloom',
        pageType: 'contact',
        successMessage: null,
        errors: errors.array(),
        oldInput: req.body,
      });
    }
    const { name, email, subject, message } = req.body;
    const ip = req.ip;
    const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);
    try {
      const lastSubmission = await ContactSubmission.findOne({
        ipAddress: ip,
      }).sort({ createdAt: -1 });
      if (lastSubmission && lastSubmission.createdAt > thirtyMinutesAgo) {
        const timeLeft = Math.round(
          (lastSubmission.createdAt.getTime() + 30 * 60 * 1000 - Date.now()) /
            60000
        );
        const errorMessage = `Vous avez déjà envoyé un message récemment. Veuillez patienter encore ${
          timeLeft || 1
        } minute(s).`;
        return res.status(429).render('contact', {
          pageTitle: 'Contactez-nous - Bloom',
          pageType: 'contact',
          successMessage: null,
          errors: [{ msg: errorMessage }],
          oldInput: req.body,
        });
      }
      const newSubmission = new ContactSubmission({
        name,
        email,
        subject,
        message,
        ipAddress: ip,
      });
      await newSubmission.save();
      try {
        await sendContactFormEmail(name, email, subject, message);
      } catch (emailError) {
        console.error(
          `Contact submission ${newSubmission._id} saved, but email notification failed.`,
          emailError
        );
      }
      req.flash('success', 'Merci ! Votre message a bien été envoyé.');
      res.redirect('/contact');
    } catch (dbError) {
      console.error('Contact form submission DB error:', dbError);
      res.status(500).render('contact', {
        pageTitle: 'Contactez-nous - Bloom',
        pageType: 'contact',
        successMessage: null,
        errors: [
          { msg: 'Une erreur serveur est survenue. Veuillez réessayer.' },
        ],
        oldInput: req.body,
      });
    }
  }
);

app.get('/resultats', async (req, res) => {
  try {
    const testimonials = await Testimonial.find({})
      .populate('featuredProducts')
      .sort({ createdAt: -1 });
    const beforeAfters = testimonials.filter((t) => t.type === 'before-after');
    const instagrams = testimonials.filter((t) => t.type === 'instagram');
    res.render('resultats', {
      pageTitle: 'Nos Résultats - Bloom',
      pageType: 'results',
      beforeAfters: beforeAfters,
      instagrams: instagrams,
    });
  } catch (error) {
    console.error('Error fetching data for results page:', error);
    res.status(500).render('admin-error', {
      pageType: 'error',
      message: 'Impossible de charger la page des résultats.',
    });
  }
});

app.get('/politique-de-confidentialite', (req, res) => {
  res.render('privacy', {
    pageTitle: 'Politique de Confidentialité - Bloom',
    pageType: 'legal',
  });
});

app.get('/conditions-generales-de-vente', (req, res) => {
  res.render('terms', {
    pageTitle: 'Conditions Générales de Vente - Bloom',
    pageType: 'legal',
  });
});

// ==================================================
//                 AUTH ROUTES
// ==================================================
app.get('/register', (req, res) => {
  res.render('register', {
    pageTitle: 'Inscription - Bloom',
    pageType: 'auth',
    errors: [],
    oldInput: {},
  });
});

app.post(
  '/register',
  [
    body('name', 'Le nom complet est requis.').not().isEmpty().trim().escape(),
    body('email', 'Veuillez fournir une adresse email valide.')
      .isEmail()
      .normalizeEmail(),
    body(
      'password',
      'Le mot de passe doit contenir au moins 6 caractères.'
    ).isLength({ min: 6 }),
    body('confirmPassword').custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Les mots de passe ne correspondent pas.');
      }
      return true;
    }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('register', {
        pageTitle: 'Inscription - Bloom',
        pageType: 'auth',
        errors: errors.array(),
        oldInput: { name: req.body.name, email: req.body.email },
      });
    }
    try {
      const { name, email, password } = req.body;
      const existingUser = await User.findOne({ email: email });
      if (existingUser) {
        return res.status(400).render('register', {
          pageTitle: 'Inscription - Bloom',
          pageType: 'auth',
          errors: [{ msg: 'Un compte avec cet email existe déjà.' }],
          oldInput: { name: req.body.name, email: req.body.email },
        });
      }
      const user = new User({ name, email, password });
      const verificationToken = crypto.randomBytes(20).toString('hex');
      user.emailVerificationToken = verificationToken;
      await user.save();
      await sendVerificationEmail(user.email, verificationToken);
      res.redirect('/check-email');
    } catch (error) {
      console.error('Error during registration:', error);
      res.status(500).render('register', {
        pageTitle: 'Inscription - Bloom',
        pageType: 'auth',
        errors: [{ msg: 'Une erreur est survenue. Veuillez réessayer.' }],
        oldInput: { name: req.body.name, email: req.body.email },
      });
    }
  }
);

app.get('/check-email', (req, res) => {
  res.render('check-email', {
    pageTitle: 'Vérifiez votre boîte mail - Bloom',
    pageType: 'auth',
  });
});

app.get('/verify-email/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const user = await User.findOne({ emailVerificationToken: token });
    if (!user) {
      req.flash(
        'error',
        'Lien de vérification invalide ou expiré. Veuillez vous inscrire à nouveau.'
      );
      return res.redirect('/register');
    }
    user.isVerified = true;
    user.emailVerificationToken = undefined;
    await user.save();
    req.flash(
      'success',
      'Email vérifié avec succès ! Vous pouvez maintenant vous connecter.'
    );
    res.redirect('/login');
  } catch (error) {
    console.error('Email Verification Error:', error);
    req.flash(
      'error',
      'Une erreur est survenue lors de la vérification. Veuillez réessayer.'
    );
    res.redirect('/register');
  }
});

app.get('/login', (req, res) => {
  res.render('login', {
    pageTitle: 'Connexion - Bloom',
    pageType: 'auth',
  });
});

app.post(
  '/login',
  [
    body('email', 'Veuillez fournir une adresse email valide.')
      .isEmail()
      .normalizeEmail(),
    body('password', 'Le mot de passe est requis.').not().isEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      req.flash('error', errors.array()[0].msg);
      return res.redirect('/login');
    }
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email: email });
      if (!user) {
        req.flash('error', 'Email ou mot de passe incorrect.');
        return res.redirect('/login');
      }
      const isMatch = await user.comparePassword(password);
      if (!isMatch) {
        req.flash('error', 'Email ou mot de passe incorrect.');
        return res.redirect('/login');
      }
      if (!user.isVerified) {
        req.flash(
          'error',
          'Veuillez vérifier votre adresse email avant de vous connecter.'
        );
        return res.redirect('/login');
      }
      req.session.regenerate(function (err) {
        if (err) {
          console.error('Session regeneration error:', err);
          req.flash('error', 'Une erreur est survenue. Veuillez réessayer.');
          return res.redirect('/login');
        }
        req.session.user = { id: user._id, name: user.name, email: user.email };
        res.redirect('/compte');
      });
    } catch (error) {
      console.error('Error during login:', error);
      req.flash('error', 'Une erreur est survenue. Veuillez réessayer.');
      res.redirect('/login');
    }
  }
);

app.get('/forgot-password', (req, res) => {
  res.render('forgot-password', {
    pageTitle: 'Mot de passe oublié',
    pageType: 'auth',
  });
});

app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (user) {
      const token = crypto.randomBytes(20).toString('hex');
      user.passwordResetToken = token;
      user.passwordResetExpires = Date.now() + 3600000; // 1 hour
      await user.save();
      await sendPasswordResetEmail(user.email, token);
    }
    req.flash(
      'success',
      'Si un compte avec cet email existe, un lien de réinitialisation a été envoyé.'
    );
    res.redirect('/forgot-password');
  } catch (error) {
    console.error('Forgot Password Error:', error);
    req.flash('error', 'Une erreur est survenue. Veuillez réessayer.');
    res.redirect('/forgot-password');
  }
});

app.get('/reset-password/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const user = await User.findOne({
      passwordResetToken: token,
      passwordResetExpires: { $gt: Date.now() },
    });
    if (!user) {
      req.flash(
        'error',
        'Le lien de réinitialisation est invalide ou a expiré. Veuillez en demander un nouveau.'
      );
      return res.redirect('/forgot-password');
    }
    res.render('reset-password', {
      pageTitle: 'Réinitialiser le mot de passe',
      pageType: 'auth',
      token: token,
    });
  } catch (error) {
    console.error('Reset Password GET Error:', error);
    res.status(500).send('Une erreur est survenue.');
  }
});

app.post(
  '/reset-password/:token',
  [
    body(
      'password',
      'Le mot de passe doit contenir au moins 6 caractères.'
    ).isLength({ min: 6 }),
    body('confirmPassword').custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Les mots de passe ne correspondent pas.');
      }
      return true;
    }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      req.flash('error', errors.array()[0].msg);
      return res.redirect(`/reset-password/${req.params.token}`);
    }
    try {
      const { token } = req.params;
      const user = await User.findOne({
        passwordResetToken: token,
        passwordResetExpires: { $gt: Date.now() },
      });
      if (!user) {
        req.flash(
          'error',
          'Le lien de réinitialisation est invalide ou a expiré.'
        );
        return res.redirect('/forgot-password');
      }
      user.password = req.body.password;
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save();
      req.flash(
        'success',
        'Votre mot de passe a été réinitialisé avec succès. Vous pouvez maintenant vous connecter.'
      );
      res.redirect('/login');
    } catch (error) {
      console.error('Reset Password POST Error:', error);
      req.flash('error', 'Une erreur est survenue.');
      res.redirect(`/reset-password/${req.params.token}`);
    }
  }
);

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Session destruction error:', err);
    }
    res.redirect('/');
  });
});

// ==================================================
//                 ACCOUNT ROUTES
// ==================================================
app.get('/compte', userAuthMiddleware, async (req, res) => {
  try {
    const view = req.query.view || 'dashboard';
    const userId = req.session.user.id;
    const shippingInfoPath = path.join(__dirname, 'data', 'shippingInfo.json');
    const shippingData = JSON.parse(fs.readFileSync(shippingInfoPath, 'utf8'));
    const wilayas = shippingData.map((w) => w.name);
    const currentUser = await User.findById(userId).populate([
      { path: 'wishlist.productId', model: 'Product' },
      { path: 'wishlist.packId', model: 'Pack' },
    ]);
    if (!currentUser) {
      return res.redirect('/logout');
    }
    const userOrders = await Order.find({ user: userId }).sort({
      createdAt: -1,
    });
    res.render('account', {
      pageTitle: 'Mon Compte',
      pageType: 'account',
      orders: userOrders,
      currentView: view,
      userDetails: currentUser,
      wishlistItems: currentUser.wishlist,
      successMessage: req.query.success || null,
      wilayas: wilayas,
    });
  } catch (error) {
    console.error('Error fetching account data:', error);
    res
      .status(500)
      .send('Erreur lors du chargement de la page de votre compte.');
  }
});

app.post(
  '/compte/details',
  userAuthMiddleware,
  [
    body('fullName', 'Le nom complet est requis')
      .not()
      .isEmpty()
      .trim()
      .escape(),
    body('phone', 'Un numéro de téléphone valide est requis')
      .isMobilePhone('any', { strictMode: false })
      .trim(),
    body('wilaya', 'La wilaya est requise').not().isEmpty().trim().escape(),
    body('address', "L'adresse est requise pour la livraison à domicile")
      .optional({ checkFalsy: true })
      .trim()
      .escape(),
  ],
  async (req, res) => {
    try {
      const userId = req.session.user.id;
      const { fullName, phone, wilaya, address } = req.body;
      await User.findByIdAndUpdate(userId, {
        'shippingInfo.fullName': fullName,
        'shippingInfo.phone': phone,
        'shippingInfo.wilaya': wilaya,
        'shippingInfo.address': address,
      });
      res.redirect('/compte?view=details&success=true');
    } catch (error) {
      console.error('Error updating account details:', error);
      res.redirect('/compte?view=details');
    }
  }
);

app.get('/compte/commande/:orderId', userAuthMiddleware, async (req, res) => {
  try {
    const { orderId } = req.params;
    const userId = req.session.user.id;
    if (!mongoose.Types.ObjectId.isValid(orderId)) {
      return res.status(404).send('Commande non trouvée.');
    }
    const order = await Order.findOne({ _id: orderId, user: userId }).populate(
      'items.productId'
    );
    if (!order) {
      return res.status(404).send('Commande non trouvée.');
    }
    res.render('order-details', {
      pageTitle: `Détails de la Commande #${order._id
        .toString()
        .slice(-6)
        .toUpperCase()}`,
      pageType: 'account',
      order: order,
    });
  } catch (error) {
    console.error('Error fetching order details:', error);
    res
      .status(500)
      .send('Erreur lors du chargement des détails de la commande.');
  }
});

// ==================================================
//                 ADMIN GET ROUTES
// ==================================================
app.get('/admin', (req, res) => {
  // Pass a dummy csrfToken to prevent EJS from crashing if the variable is used
  res.render('admin-login', { error: null, csrfToken: '' });
});

app.get('/admin/dashboard', authMiddleware, async (req, res) => {
  try {
    const statusFilter = req.query.status;
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const skip = (page - 1) * limit;
    let filter = {};
    if (statusFilter) {
      filter.status = statusFilter;
    }
    const totalOrders = await Order.countDocuments(filter);
    const totalPages = Math.ceil(totalOrders / limit);
    const orders = await Order.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);
    res.render('admin-dashboard', {
      orders,
      currentStatus: statusFilter,
      pageType: 'admin',
      currentPage: page,
      totalPages,
      baseUrl: '/admin/dashboard',
    });
  } catch (error) {
    console.error('ERROR: Could not fetch orders for dashboard.', error);
    res.status(500).send('Could not load the orders data.');
  }
});

app.get('/admin/products', authMiddleware, async (req, res) => {
  try {
    const products = await Product.find({});
    const packs = await Pack.find({});
    res.render('admin-products', { products, packs, pageType: 'admin' });
  } catch (error) {
    console.error('Error fetching products for admin page:', error);
    res.status(500).send('Failed to load product management page.');
  }
});

app.get('/admin/products/add', authMiddleware, (req, res) => {
  res.render('admin-add-product', {
    pageType: 'admin',
    errors: [],
    oldInput: {},
    // Pass a dummy csrfToken to prevent EJS from crashing
    csrfToken: '' 
  });
});

app.get('/admin/products/edit/:id', authMiddleware, async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).send('Product not found.');
    res.render('admin-edit-product', {
      product,
      pageType: 'admin',
      errors: [],
      oldInput: {},
      csrfToken: ''
    });
  } catch (error) {
    console.error('Error fetching product for edit:', error);
    res.status(500).send('Failed to load edit page.');
  }
});

app.get('/admin/packs/add', authMiddleware, (req, res) => {
  res.render('admin-add-pack', { pageType: 'admin', errors: [], oldInput: {}, csrfToken: '' });
});

app.get('/admin/packs/edit/:id', authMiddleware, async (req, res) => {
  try {
    const pack = await Pack.findById(req.params.id);
    if (!pack) return res.status(404).send('Pack not found.');
    res.render('admin-edit-pack', {
      pack,
      pageType: 'admin',
      errors: [],
      oldInput: {},
      csrfToken: ''
    });
  } catch (error) {
    console.error('Error fetching pack for edit:', error);
    res.status(500).send('Failed to load edit page.');
  }
});

app.get('/admin/reviews', authMiddleware, async (req, res) => {
  try {
    const productsWithReviews = await Product.find({
      'reviews.0': { $exists: true },
    })
      .populate('reviews.user', 'email')
      .sort({ 'reviews.createdAt': -1 });
    res.render('admin-reviews', {
      pageTitle: 'Gestion des Avis',
      pageType: 'admin',
      products: productsWithReviews,
    });
  } catch (error) {
    console.error('Error fetching reviews for admin page:', error);
    res.status(500).send('Failed to load review management page.');
  }
});

app.get('/admin/testimonials', authMiddleware, async (req, res) => {
  try {
    const testimonials = await Testimonial.find({})
      .populate('featuredProducts', 'name')
      .sort({ createdAt: -1 });
    res.render('admin-testimonials', {
      pageTitle: 'Gestion des Témoignages',
      pageType: 'admin',
      testimonials,
    });
  } catch (error) {
    console.error('Error fetching testimonials for admin page:', error);
    res
      .status(500)
      .render('admin-error', {
        pageType: 'admin',
        message: 'Failed to load testimonial management page.',
      });
  }
});

app.get('/admin/testimonials/add', authMiddleware, async (req, res) => {
  try {
    const products = await Product.find({}, 'id name');
    res.render('admin-add-testimonial', {
      pageTitle: 'Ajouter un Témoignage',
      pageType: 'admin',
      products,
      errors: [],
      oldInput: {},
      csrfToken: ''
    });
  } catch (error) {
    console.error('Error loading add testimonial page:', error);
    res
      .status(500)
      .render('admin-error', {
        pageType: 'admin',
        message: 'Failed to load the page.',
      });
  }
});

app.get('/admin/testimonials/edit/:id', authMiddleware, async (req, res) => {
  try {
    const testimonial = await Testimonial.findById(req.params.id);
    if (!testimonial) {
      req.flash('error', 'Témoignage non trouvé.');
      return res.redirect('/admin/testimonials');
    }
    const products = await Product.find({}, 'id name');
    res.render('admin-edit-testimonial', {
      pageTitle: 'Modifier le Témoignage',
      pageType: 'admin',
      testimonial,
      products,
      errors: [],
      oldInput: testimonial,
      csrfToken: ''
    });
  } catch (error) {
    console.error('Error fetching testimonial for edit:', error);
    res
      .status(500)
      .render('admin-error', {
        pageType: 'admin',
        message: 'Failed to load edit page.',
      });
  }
});

app.get('/admin/messages', authMiddleware, async (req, res) => {
  try {
    const messages = await ContactSubmission.find({}).sort({ createdAt: -1 });
    res.render('admin-messages', {
      pageTitle: 'Gestion des Messages - Admin Bloom',
      pageType: 'admin',
      messages,
    });
  } catch (error) {
    console.error('Error fetching contact messages for admin:', error);
    res.status(500).send('Failed to load messages page.');
  }
});

app.get('/admin/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.redirect('/admin/dashboard');
    }
    res.redirect('/');
  });
});

// ==================================================
//                 ADMIN POST ROUTES
// ==================================================
app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === process.env.ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    res.redirect('/admin/dashboard');
  } else {
    res.render('admin-login', {
      error: 'Mot de passe incorrect. Veuillez réessayer.',
      csrfToken: ''
    });
  }
});

app.post(
  '/admin/products/edit/:id',
  authMiddleware,
  productUpload,
  productValidationRules,
  async (req, res) => {
    const productId = req.params.id;
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      const product = await Product.findById(productId);
      return res.status(400).render('admin-edit-product', {
        pageType: 'admin',
        product: product,
        errors: errors.array(),
        oldInput: req.body,
        csrfToken: ''
      });
    }
    try {
      const {
        name,
        price,
        short_description,
        description,
        ingredients,
        how_to_use,
        existingMainImagePath,
        existingGalleryPaths,
      } = req.body;
      const product = await Product.findById(productId);
      if (!product) {
        return res.status(404).send('Product not found.');
      }

      const updatedData = {
        name,
        price,
        short_description,
        description,
        ingredients: ingredients
          ? ingredients.split(',').map((item) => item.trim())
          : [],
        how_to_use: how_to_use
          ? how_to_use.split(',').map((item) => item.trim())
          : [],
      };

      if (req.files.mainImage) {
        updatedData.mainImage =
          '/images/products/' + req.files.mainImage[0].filename;
        if (product.mainImage) deleteFile(product.mainImage);
      } else {
        updatedData.mainImage = existingMainImagePath;
      }

      const keptGalleryPaths = existingGalleryPaths
        ? JSON.parse(existingGalleryPaths)
        : [];
      let newGalleryPaths = [...keptGalleryPaths];
      if (req.files.gallery) {
        newGalleryPaths.push(
          ...req.files.gallery.map(
            (file) => '/images/products/' + file.filename
          )
        );
      }
      updatedData.gallery = newGalleryPaths;

      const originalGallery = product.gallery || [];
      originalGallery.forEach((originalImagePath) => {
        if (!keptGalleryPaths.includes(originalImagePath))
          deleteFile(originalImagePath);
      });

      await Product.findByIdAndUpdate(productId, updatedData);
      req.flash(
        'success',
        `Le produit "${updatedData.name}" a été mis à jour avec succès.`
      );
      res.redirect('/admin/products');
    } catch (error) {
      console.error('Error updating product:', error);
      res.status(500).render('admin-error', {
        pageType: 'admin',
        message: 'Erreur lors de la mise à jour du produit.',
      });
    }
  }
);

app.post(
  '/admin/products/add',
  authMiddleware,
  productUpload,
  productValidationRules,
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('admin-add-product', {
        pageType: 'admin',
        errors: errors.array(),
        oldInput: req.body,
        csrfToken: ''
      });
    }
    try {
      const {
        name,
        price,
        short_description,
        description,
        ingredients,
        how_to_use,
      } = req.body;
      if (!req.files || !req.files.mainImage) {
        return res.status(400).render('admin-add-product', {
          pageType: 'admin',
          errors: [{ msg: "L'image principale est requise." }],
          oldInput: req.body,
          csrfToken: ''
        });
      }
      const baseSlug = slugify(name, { lower: true, strict: true });
      const uniqueSlug = `${baseSlug}-${crypto.randomBytes(4).toString('hex')}`;
      const mainImagePath =
        '/images/products/' + req.files.mainImage[0].filename;
      const galleryPaths = req.files.gallery
        ? req.files.gallery.map((file) => '/images/products/' + file.filename)
        : [];
      const ingredientsArray = ingredients
        ? ingredients.split(',').map((item) => item.trim())
        : [];
      const howToUseArray = how_to_use
        ? how_to_use.split(',').map((item) => item.trim())
        : [];
      const newProduct = new Product({
        id: uniqueSlug,
        name,
        price,
        short_description,
        description,
        mainImage: mainImagePath,
        gallery: galleryPaths,
        ingredients: ingredientsArray,
        how_to_use: howToUseArray,
      });
      await newProduct.save();
      req.flash(
        'success',
        `Le produit "${newProduct.name}" a été créé avec succès.`
      );
      res.redirect('/admin/products');
    } catch (error) { // <-- CORRECTED SYNTAX HERE
      console.error('Error adding new product:', error);
      res.status(500).render('admin-error', {
        pageType: 'admin',
        message: 'Erreur lors de la création du produit.',
      });
    }
  }
);

app.post('/admin/products/delete/:id', authMiddleware, async (req, res) => {
  try {
    const deletedProduct = await Product.findByIdAndDelete(req.params.id);
    if (deletedProduct) {
      if (deletedProduct.mainImage) deleteFile(deletedProduct.mainImage);
      if (deletedProduct.gallery && deletedProduct.gallery.length > 0) {
        deletedProduct.gallery.forEach((imagePath) => deleteFile(imagePath));
      }
      req.flash(
        'success',
        `Le produit "${deletedProduct.name}" a été supprimé.`
      );
    }
    res.redirect('/admin/products');
  } catch (error) {
    console.error('Error deleting product:', error);
    req.flash('error', 'Erreur lors de la suppression du produit.');
    res.redirect('/admin/products');
  }
});

app.post(
  '/admin/packs/add',
  authMiddleware,
  productUpload,
  packValidationRules,
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('admin-add-pack', {
        pageType: 'admin',
        errors: errors.array(),
        oldInput: req.body,
        csrfToken: ''
      });
    }
    try {
      const { name, contents, description, originalPrice, discountedPrice } =
        req.body;
      if (!req.files || !req.files.mainImage) {
        return res.status(400).render('admin-add-pack', {
          pageType: 'admin',
          errors: [{ msg: "L'image principale est requise." }],
          oldInput: req.body,
          csrfToken: ''
        });
      }
      const baseSlug = slugify(name, { lower: true, strict: true });
      const uniqueSlug = `${baseSlug}-${crypto.randomBytes(4).toString('hex')}`;
      const mainImagePath =
        '/images/products/' + req.files.mainImage[0].filename;
      const galleryPaths = req.files.gallery
        ? req.files.gallery.map((file) => '/images/products/' + file.filename)
        : [];
      const newPack = new Pack({
        id: uniqueSlug,
        name,
        contents,
        description,
        originalPrice,
        discountedPrice,
        mainImage: mainImagePath,
        gallery: galleryPaths,
      });
      await newPack.save();
      req.flash('success', `Le pack "${newPack.name}" a été créé avec succès.`);
      res.redirect('/admin/products');
    } catch (error) {
      console.error('Error adding new pack:', error);
      res.status(500).render('admin-error', {
        pageType: 'admin',
        message: 'Erreur lors de la création du pack.',
      });
    }
  }
);

app.post(
  '/admin/packs/edit/:id',
  authMiddleware,
  productUpload,
  packValidationRules,
  async (req, res) => {
    const packId = req.params.id;
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      const pack = await Pack.findById(packId);
      return res.status(400).render('admin-edit-pack', {
        pageType: 'admin',
        pack: pack,
        errors: errors.array(),
        oldInput: req.body,
        csrfToken: ''
      });
    }
    try {
      const {
        name,
        contents,
        description,
        originalPrice,
        discountedPrice,
        existingMainImagePath,
        existingGalleryPaths,
      } = req.body;
      const pack = await Pack.findById(packId);
      if (!pack) {
        return res.status(404).send('Pack not found.');
      }
      const updatedData = {
        name,
        contents,
        description,
        originalPrice,
        discountedPrice,
      };
      if (req.files.mainImage) {
        updatedData.mainImage =
          '/images/products/' + req.files.mainImage[0].filename;
        if (pack.mainImage) deleteFile(pack.mainImage);
      } else {
        updatedData.mainImage = existingMainImagePath;
      }
      const keptGalleryPaths = existingGalleryPaths
        ? JSON.parse(existingGalleryPaths)
        : [];
      let newGalleryPaths = [...keptGalleryPaths];
      if (req.files.gallery) {
        newGalleryPaths.push(
          ...req.files.gallery.map(
            (file) => '/images/products/' + file.filename
          )
        );
      }
      updatedData.gallery = newGalleryPaths;
      const originalGallery = pack.gallery || [];
      originalGallery.forEach((originalImagePath) => {
        if (!keptGalleryPaths.includes(originalImagePath))
          deleteFile(originalImagePath);
      });
      await Pack.findByIdAndUpdate(packId, updatedData);
      req.flash(
        'success',
        `Le pack "${updatedData.name}" a été mis à jour avec succès.`
      );
      res.redirect('/admin/products');
    } catch (error) {
      console.error('Error updating pack:', error);
      res.status(500).render('admin-error', {
        pageType: 'admin',
        message: 'Erreur lors de la mise à jour du pack.',
      });
    }
  }
);

app.post('/admin/packs/delete/:id', authMiddleware, async (req, res) => {
  try {
    const deletedPack = await Pack.findByIdAndDelete(req.params.id);
    if (deletedPack) {
      if (deletedPack.mainImage) deleteFile(deletedPack.mainImage);
      if (deletedPack.gallery && deletedPack.gallery.length > 0) {
        deletedPack.gallery.forEach((imagePath) => deleteFile(imagePath));
      }
      req.flash('success', `Le pack "${deletedPack.name}" a été supprimé.`);
    }
    res.redirect('/admin/products');
  } catch (error) {
    console.error('Error deleting pack:', error);
    req.flash('error', 'Erreur lors de la suppression du pack.');
    res.redirect('/admin/products');
  }
});

app.post(
  '/admin/testimonials/add',
  authMiddleware,
  testimonialUpload,
  async (req, res) => {
    try {
      const { type, quote, story, featuredProducts } = req.body;
      const newTestimonialData = { type, quote, story, featuredProducts };
      if (type === 'before-after') {
        if (req.files && req.files.beforeImage)
          newTestimonialData.beforeImage =
            '/images/products/' + req.files.beforeImage[0].filename;
        if (req.files && req.files.afterImage)
          newTestimonialData.afterImage =
            '/images/products/' + req.files.afterImage[0].filename;
      } else if (type === 'instagram') {
        if (req.files && req.files.instagramImage)
          newTestimonialData.instagramImage =
            '/images/products/' + req.files.instagramImage[0].filename;
      }
      const testimonial = new Testimonial(newTestimonialData);
      await testimonial.save();
      req.flash('success', 'Le témoignage a été ajouté avec succès.');
      res.redirect('/admin/testimonials');
    } catch (error) {
      if (error.name === 'ValidationError') {
        const products = await Product.find({}, 'id name');
        const validationErrors = Object.values(error.errors).map((err) => ({
          msg: err.message,
        }));
        return res.status(400).render('admin-add-testimonial', {
          pageTitle: 'Ajouter un Témoignage',
          pageType: 'admin',
          products,
          errors: validationErrors,
          oldInput: req.body,
          csrfToken: ''
        });
      }
      console.error('Error adding new testimonial:', error);
      res.status(500).render('admin-error', {
        pageType: 'admin',
        message: 'Erreur lors de la création du témoignage.',
      });
    }
  }
);

app.post(
  '/admin/testimonials/edit/:id',
  authMiddleware,
  testimonialUpload,
  async (req, res) => {
    const testimonialId = req.params.id;
    try {
      const { type, quote, story, featuredProducts } = req.body;
      const testimonial = await Testimonial.findById(testimonialId);
      if (!testimonial) {
        req.flash('error', 'Témoignage non trouvé.');
        return res.redirect('/admin/testimonials');
      }
      const updatedData = {
        type,
        quote,
        story,
        featuredProducts: featuredProducts || [],
      };
      if (type === 'before-after') {
        if (req.files.beforeImage) {
          deleteFile(testimonial.beforeImage);
          updatedData.beforeImage =
            '/images/products/' + req.files.beforeImage[0].filename;
        }
        if (req.files.afterImage) {
          deleteFile(testimonial.afterImage);
          updatedData.afterImage =
            '/images/products/' + req.files.afterImage[0].filename;
        }
        updatedData.instagramImage = undefined;
        if (testimonial.instagramImage) deleteFile(testimonial.instagramImage);
      } else if (type === 'instagram') {
        if (req.files.instagramImage) {
          deleteFile(testimonial.instagramImage);
          updatedData.instagramImage =
            '/images/products/' + req.files.instagramImage[0].filename;
        }
        updatedData.beforeImage = undefined;
        updatedData.afterImage = undefined;
        if (testimonial.beforeImage) deleteFile(testimonial.beforeImage);
        if (testimonial.afterImage) deleteFile(testimonial.afterImage);
      }
      await Testimonial.findByIdAndUpdate(testimonialId, updatedData, {
        runValidators: true,
      });
      req.flash('success', 'Le témoignage a été mis à jour avec succès.');
      res.redirect('/admin/testimonials');
    } catch (error) {
      if (error.name === 'ValidationError') {
        const products = await Product.find({}, 'id name');
        const validationErrors = Object.values(error.errors).map((err) => ({
          msg: err.message,
        }));
        const currentData = await Testimonial.findById(testimonialId);
        return res.status(400).render('admin-edit-testimonial', {
          pageTitle: 'Modifier le Témoignage',
          pageType: 'admin',
          products,
          testimonial: currentData,
          errors: validationErrors,
          oldInput: req.body,
          csrfToken: ''
        });
      }
      console.error('Error updating testimonial:', error);
      res.status(500).render('admin-error', {
        pageType: 'admin',
        message: 'Erreur lors de la mise à jour du témoignage.',
      });
    }
  }
);

app.post('/admin/testimonials/delete/:id', authMiddleware, async (req, res) => {
  try {
    const testimonial = await Testimonial.findByIdAndDelete(req.params.id);
    if (testimonial) {
      if (testimonial.beforeImage) deleteFile(testimonial.beforeImage);
      if (testimonial.afterImage) deleteFile(testimonial.afterImage);
      if (testimonial.instagramImage) deleteFile(testimonial.instagramImage);
      req.flash('success', 'Le témoignage a été supprimé avec succès.');
    } else {
      req.flash('error', 'Témoignage non trouvé.');
    }
    res.redirect('/admin/testimonials');
  } catch (error) {
    console.error('Error deleting testimonial:', error);
    req.flash('error', 'Erreur lors de la suppression du témoignage.');
    res.redirect('/admin/testimonials');
  }
});

app.post('/admin/messages/delete/:id', authMiddleware, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).send('Invalid message ID.');
    }
    await ContactSubmission.findByIdAndDelete(req.params.id);
    res.sendStatus(200);
  } catch (error) {
    console.error('Error deleting contact message:', error);
    res.status(500).send('Failed to delete message.');
  }
});

app.post('/admin/order/update-status/:id', authMiddleware, async (req, res) => {
  try {
    await Order.findByIdAndUpdate(req.params.id, { status: req.body.status });
    res.redirect('/admin/dashboard');
  } catch (error) {
    console.error('Error updating order status:', error);
    res.status(500).send('Failed to update order status.');
  }
});

// ==================================================
//                 ERROR HANDLING
// ==================================================
app.use((err, req, res, next) => {
  // We no longer need the EBADCSRFTOKEN check
  console.error(err.stack);
  res.status(500).render('admin-error', {
    pageType: 'error',
    message: 'Une erreur interne est survenue.',
  });
});

// 404 Handler - MUST be the last route handler
app.use((req, res, next) => {
    res.status(404).render('404', { pageTitle: 'Page Non Trouvée', pageType: 'error' });
});

app.listen(port, () => {
  console.log(`Bloom server is running at http://localhost:${port}`);
});