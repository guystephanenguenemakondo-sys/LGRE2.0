// LGRE² Backend Server
// Node.js + Express + MongoDB

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'lgre2-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/lgre2', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('✅ Connecté à MongoDB');
}).catch(err => {
    console.error('❌ Erreur de connexion MongoDB:', err);
});

// ==================== MODELS ====================

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    phone: { type: String, required: true },
    role: { type: String, enum: ['buyer', 'seller', 'admin'], default: 'buyer' },
    location: String,
    verified: { type: Boolean, default: false },
    orangeMoneyNumber: String,
    mtnMoneyNumber: String,
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Product Schema
const productSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String, required: true },
    price: { type: Number, required: true },
    category: { 
        type: String, 
        enum: ['electronics', 'fashion', 'food', 'home', 'services', 'other'],
        required: true 
    },
    seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    images: [String],
    stock: { type: Number, default: 1 },
    location: String,
    rating: { type: Number, default: 0 },
    reviews: { type: Number, default: 0 },
    active: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const Product = mongoose.model('Product', productSchema);

// Order Schema
const orderSchema = new mongoose.Schema({
    buyer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    items: [{
        product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
        quantity: Number,
        price: Number
    }],
    totalAmount: { type: Number, required: true },
    paymentMethod: { 
        type: String, 
        enum: ['orange_money', 'mtn_mobile_money', 'card'],
        required: true 
    },
    paymentStatus: { 
        type: String, 
        enum: ['pending', 'completed', 'failed', 'refunded'],
        default: 'pending'
    },
    transactionId: String,
    phoneNumber: String,
    deliveryAddress: String,
    status: { 
        type: String, 
        enum: ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'],
        default: 'pending'
    },
    createdAt: { type: Date, default: Date.now }
});

const Order = mongoose.model('Order', orderSchema);

// Review Schema
const reviewSchema = new mongoose.Schema({
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    rating: { type: Number, required: true, min: 1, max: 5 },
    comment: String,
    createdAt: { type: Date, default: Date.now }
});

const Review = mongoose.model('Review', reviewSchema);

// ==================== MIDDLEWARE ====================

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Token requis' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Token invalide' });
        }
        req.user = user;
        next();
    });
};

// Admin Middleware
const isAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Accès refusé - Admin uniquement' });
    }
    next();
};

// File Upload Configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/products/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
    fileFilter: function (req, file, cb) {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Seulement les images sont autorisées'));
        }
    }
});

// ==================== ROUTES ====================

// ===== AUTH ROUTES =====

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, phone, location } = req.body;

        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email déjà utilisé' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const user = new User({
            name,
            email,
            password: hashedPassword,
            phone,
            location
        });

        await user.save();

        // Generate token
        const token = jwt.sign(
            { id: user._id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({
            message: 'Inscription réussie',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Email ou mot de passe incorrect' });
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Email ou mot de passe incorrect' });
        }

        // Generate token
        const token = jwt.sign(
            { id: user._id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Connexion réussie',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== PRODUCT ROUTES =====

// Get all products
app.get('/api/products', async (req, res) => {
    try {
        const { category, search, minPrice, maxPrice, location } = req.query;
        let query = { active: true };

        if (category && category !== 'all') {
            query.category = category;
        }

        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } }
            ];
        }

        if (minPrice || maxPrice) {
            query.price = {};
            if (minPrice) query.price.$gte = Number(minPrice);
            if (maxPrice) query.price.$lte = Number(maxPrice);
        }

        if (location) {
            query.location = { $regex: location, $options: 'i' };
        }

        const products = await Product.find(query)
            .populate('seller', 'name location')
            .sort({ createdAt: -1 });

        res.json(products);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get single product
app.get('/api/products/:id', async (req, res) => {
    try {
        const product = await Product.findById(req.params.id)
            .populate('seller', 'name email phone location');
        
        if (!product) {
            return res.status(404).json({ error: 'Produit non trouvé' });
        }

        res.json(product);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create product (seller only)
app.post('/api/products', authenticateToken, upload.array('images', 5), async (req, res) => {
    try {
        const { name, description, price, category, stock, location } = req.body;

        const images = req.files ? req.files.map(file => `/uploads/products/${file.filename}`) : [];

        const product = new Product({
            name,
            description,
            price: Number(price),
            category,
            seller: req.user.id,
            images,
            stock: Number(stock) || 1,
            location
        });

        await product.save();

        // Update user role to seller if not already
        await User.findByIdAndUpdate(req.user.id, { role: 'seller' });

        res.status(201).json({
            message: 'Produit créé avec succès',
            product
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update product
app.put('/api/products/:id', authenticateToken, async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);

        if (!product) {
            return res.status(404).json({ error: 'Produit non trouvé' });
        }

        // Check if user is the seller or admin
        if (product.seller.toString() !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Non autorisé' });
        }

        const updatedProduct = await Product.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true }
        );

        res.json({
            message: 'Produit mis à jour',
            product: updatedProduct
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete product
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);

        if (!product) {
            return res.status(404).json({ error: 'Produit non trouvé' });
        }

        if (product.seller.toString() !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Non autorisé' });
        }

        await Product.findByIdAndUpdate(req.params.id, { active: false });

        res.json({ message: 'Produit supprimé' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== ORDER ROUTES =====

// Create order
app.post('/api/orders', authenticateToken, async (req, res) => {
    try {
        const { items, paymentMethod, phoneNumber, deliveryAddress } = req.body;

        // Calculate total
        let totalAmount = 0;
        const orderItems = [];

        for (let item of items) {
            const product = await Product.findById(item.productId);
            if (!product || product.stock < item.quantity) {
                return res.status(400).json({ 
                    error: `Stock insuffisant pour ${product?.name || 'le produit'}` 
                });
            }

            orderItems.push({
                product: product._id,
                quantity: item.quantity,
                price: product.price
            });

            totalAmount += product.price * item.quantity;
        }

        // Create order
        const order = new Order({
            buyer: req.user.id,
            items: orderItems,
            totalAmount,
            paymentMethod,
            phoneNumber,
            deliveryAddress
        });

        await order.save();

        // Update product stock
        for (let item of orderItems) {
            await Product.findByIdAndUpdate(item.product, {
                $inc: { stock: -item.quantity }
            });
        }

        // Simulate payment processing
        if (paymentMethod === 'orange_money' || paymentMethod === 'mtn_mobile_money') {
            // In production, integrate with actual Orange Money / MTN Mobile Money API
            order.transactionId = 'TXN' + Date.now();
            order.paymentStatus = 'completed';
            order.status = 'confirmed';
            await order.save();
        }

        res.status(201).json({
            message: 'Commande créée avec succès',
            order,
            paymentInstructions: {
                method: paymentMethod,
                amount: totalAmount,
                phone: phoneNumber,
                reference: order._id
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get user orders
app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        const orders = await Order.find({ buyer: req.user.id })
            .populate('items.product')
            .sort({ createdAt: -1 });

        res.json(orders);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get single order
app.get('/api/orders/:id', authenticateToken, async (req, res) => {
    try {
        const order = await Order.findById(req.params.id)
            .populate('items.product')
            .populate('buyer', 'name email phone');

        if (!order) {
            return res.status(404).json({ error: 'Commande non trouvée' });
        }

        // Check authorization
        if (order.buyer._id.toString() !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Non autorisé' });
        }

        res.json(order);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== REVIEW ROUTES =====

// Add review
app.post('/api/reviews', authenticateToken, async (req, res) => {
    try {
        const { productId, rating, comment } = req.body;

        // Check if user already reviewed
        const existingReview = await Review.findOne({
            product: productId,
            user: req.user.id
        });

        if (existingReview) {
            return res.status(400).json({ error: 'Vous avez déjà évalué ce produit' });
        }

        const review = new Review({
            product: productId,
            user: req.user.id,
            rating: Number(rating),
            comment
        });

        await review.save();

        // Update product rating
        const reviews = await Review.find({ product: productId });
        const avgRating = reviews.reduce((sum, r) => sum + r.rating, 0) / reviews.length;

        await Product.findByIdAndUpdate(productId, {
            rating: avgRating,
            reviews: reviews.length
        });

        res.status(201).json({
            message: 'Avis ajouté',
            review
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get product reviews
app.get('/api/products/:id/reviews', async (req, res) => {
    try {
        const reviews = await Review.find({ product: req.params.id })
            .populate('user', 'name')
            .sort({ createdAt: -1 });

        res.json(reviews);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== ADMIN ROUTES =====

// Get all users (admin only)
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get all orders (admin only)
app.get('/api/admin/orders', authenticateToken, isAdmin, async (req, res) => {
    try {
        const orders = await Order.find()
            .populate('buyer', 'name email')
            .populate('items.product')
            .sort({ createdAt: -1 });

        res.json(orders);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Dashboard statistics (admin only)
app.get('/api/admin/stats', authenticateToken, isAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const totalProducts = await Product.countDocuments({ active: true });
        const totalOrders = await Order.countDocuments();
        const totalRevenue = await Order.aggregate([
            { $match: { paymentStatus: 'completed' } },
            { $group: { _id: null, total: { $sum: '$totalAmount' } } }
        ]);

        res.json({
            users: totalUsers,
            products: totalProducts,
            orders: totalOrders,
            revenue: totalRevenue[0]?.total || 0
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== PAYMENT WEBHOOK ROUTES =====

// Orange Money Webhook (to be configured with Orange Money API)
app.post('/api/webhooks/orange-money', async (req, res) => {
    try {
        // Verify webhook signature (in production)
        const { transactionId, status, orderId } = req.body;

        const order = await Order.findById(orderId);
        if (order) {
            order.paymentStatus = status === 'SUCCESS' ? 'completed' : 'failed';
            order.transactionId = transactionId;
            if (status === 'SUCCESS') {
                order.status = 'confirmed';
            }
            await order.save();
        }

        res.json({ received: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// MTN Mobile Money Webhook
app.post('/api/webhooks/mtn-mobile-money', async (req, res) => {
    try {
        const { transactionId, status, orderId } = req.body;

        const order = await Order.findById(orderId);
        if (order) {
            order.paymentStatus = status === 'SUCCESSFUL' ? 'completed' : 'failed';
            order.transactionId = transactionId;
            if (status === 'SUCCESSFUL') {
                order.status = 'confirmed';
            }
            await order.save();
        }

        res.json({ received: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== SERVER START ====================

// Serve static files (frontend)
app.use(express.static('public'));

// Root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`
    ╔═══════════════════════════════════════════════╗
    ║          🦁 LGRE² Server Started 🦁          ║
    ╠═══════════════════════════════════════════════╣
    ║  Port: ${PORT}                                  ║
    ║  Environment: ${process.env.NODE_ENV || 'development'}            ║
    ║  API: http://localhost:${PORT}/api              ║
    ╚═══════════════════════════════════════════════╝
    `);
});

module.exports = app;