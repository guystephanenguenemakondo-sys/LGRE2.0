// LGRE² Backend Server - Version 2.0
// Marketplace complète avec messagerie et gestion produits/services
// Par Guy Stephane NGUENE Makondo

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'lgre2-secret-key-change-in-production';

// Middleware
// CORS Configuration optimisée
const corsOptions = {
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
            'http://localhost:3000',
            'http://localhost:5000',
            process.env.FRONTEND_URL,
        ].filter(Boolean);
        
        if (allowedOrigins.includes(origin) || process.env.NODE_ENV === 'development') {
            callback(null, true);
        } else {
            callback(null, true);
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));

// Middleware de logging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));

// Email Configuration
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST || 'smtp.gmail.com',
    port: process.env.EMAIL_PORT || 587,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER || 'guystephanenguenemakondo@gmail.com',
        pass: process.env.EMAIL_PASSWORD
    }
});
// MongoDB Connection optimisé pour Atlas
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/lgre2';

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 10000,
    socketTimeoutMS: 45000,
})
.then(() => {
    console.log('✅ Connecté à MongoDB');
    console.log(`📍 Database: ${mongoose.connection.name}`);
})
.catch(err => {
    console.error('❌ Erreur de connexion MongoDB:', err.message);
});


// ==================== MODELS ====================

// User Schema - Amélioré avec pseudo et validation stricte
const userSchema = new mongoose.Schema({
    pseudo: { type: String, required: true, unique: true, trim: true },
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true }, // Min 10 caractères avec lettres, chiffres et caractères spéciaux
    phone: { type: String, required: true },
    location: String,
    bio: String,
    profileImage: String,
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    verified: { type: Boolean, default: false },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Listing Schema - Pour produits ET services
const listingSchema = new mongoose.Schema({
    type: { type: String, enum: ['product', 'service'], required: true },
    title: { type: String, required: true },
    description: { type: String, required: true },
    price: { type: Number, required: true },
    category: { 
        type: String, 
        enum: ['electronics', 'fashion', 'food', 'home', 'services', 'education', 'health', 'transport', 'handwork', 'exclusivities', 'other'],
        required: true 
    },
    condition: { 
        type: String, 
        enum: ['new', 'like-new', 'good', 'fair', 'for-parts', 'custom-order'],
        default: 'new'
    },
    seller: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    images: [String],
    location: { type: String, required: true },
    contactPhone: String,
    available: { type: Boolean, default: true },
    views: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});

const Listing = mongoose.model('Listing', listingSchema);

// Message Schema - Pour la messagerie
const messageSchema = new mongoose.Schema({
    conversation: { type: String, required: true }, // Format: "userId1_userId2" (triés alphabétiquement)
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    listingRef: { type: mongoose.Schema.Types.ObjectId, ref: 'Listing' }, // Référence à l'annonce
    content: { type: String, required: true },
    read: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

messageSchema.index({ conversation: 1, createdAt: -1 });

const Message = mongoose.model('Message', messageSchema);

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
        const uploadPath = file.fieldname === 'profileImage' ? 'uploads/profiles/' : 'uploads/listings/';
        cb(null, uploadPath);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB max
    fileFilter: function (req, file, cb) {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Seulement les images sont autorisées'));
        }
    }
});

// Validation du mot de passe
function validatePassword(password) {
    // Au moins 10 caractères, 1 lettre, 1 chiffre, 1 caractère spécial
    const minLength = password.length >= 10;
    const hasLetter = /[a-zA-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
    
    return minLength && hasLetter && hasNumber && hasSpecial;
}

// ==================== ROUTES ====================

// ===== AUTH ROUTES =====

// Register
app.post('/api/auth/register', async (req, res) => {
    try {
        console.log('📝 Tentative inscription:', { 
            pseudo: req.body.pseudo, 
            email: req.body.email 
        });

        const { pseudo, name, email, password, phone, location } = req.body;

        if (!pseudo || !name || !email || !password || !phone) {
            console.log('❌ Champs manquants');
            return res.status(400).json({ error: 'Tous les champs sont requis' });
        }

        if (!validatePassword(password)) {
            console.log('❌ Mot de passe invalide');
            return res.status(400).json({ 
                error: 'Le mot de passe doit contenir au moins 10 caractères, incluant des lettres, des chiffres et des caractères spéciaux' 
            });
        }

        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            console.log('❌ Email déjà utilisé:', email);
            return res.status(400).json({ error: 'Email déjà utilisé' });
        }

        const existingPseudo = await User.findOne({ pseudo });
        if (existingPseudo) {
            console.log('❌ Pseudo déjà utilisé:', pseudo);
            return res.status(400).json({ error: 'Pseudo déjà utilisé' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const user = new User({
            pseudo,
            name,
            email,
            password: hashedPassword,
            phone,
            location
        });

        await user.save();
        console.log('✅ Utilisateur créé:', user._id);

        const token = jwt.sign(
            { id: user._id, email: user.email, pseudo: user.pseudo, role: user.role },
            JWT_SECRET,
            { expiresIn: '30d' }
        );

        res.status(201).json({
            message: 'Inscription réussie',
            token,
            user: {
                id: user._id,
                pseudo: user.pseudo,
                name: user.name,
                email: user.email,
                phone: user.phone,
                role: user.role
            }
        });
    } catch (error) {
        console.error('❌ Erreur inscription:', error);
        res.status(500).json({ 
            error: error.message || 'Erreur serveur',
            details: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
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
            { id: user._id, email: user.email, pseudo: user.pseudo, role: user.role },
            JWT_SECRET,
            { expiresIn: '30d' }
        );

        res.json({
            message: 'Connexion réussie',
            token,
            user: {
                id: user._id,
                pseudo: user.pseudo,
                name: user.name,
                email: user.email,
                phone: user.phone,
                role: user.role
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Forgot Password - Envoie un code par email
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'Aucun compte avec cet email' });
        }

        // Générer un code de 6 chiffres
        const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
        
        // Hasher le code et définir l'expiration (5 minutes)
        user.resetPasswordToken = crypto.createHash('sha256').update(resetCode).digest('hex');
        user.resetPasswordExpires = Date.now() + 5 * 60 * 1000; // 5 minutes
        await user.save();

        // Envoyer l'email
        const mailOptions = {
            from: 'LGRE² <guystephanenguenemakondo@gmail.com>',
            to: user.email,
            subject: 'Code de réinitialisation - LGRE²',
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; background: #f4f4f4;">
                    <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px;">
                        <h2 style="color: #0066CC;">LGRE² - Réinitialisation de mot de passe</h2>
                        <p>Bonjour <strong>${user.name}</strong>,</p>
                        <p>Voici votre code de réinitialisation :</p>
                        <div style="background: #0066CC; color: white; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; border-radius: 5px; margin: 20px 0;">
                            ${resetCode}
                        </div>
                        <p style="color: #e74c3c;"><strong>Ce code expire dans 5 minutes.</strong></p>
                        <p>Si vous n'avez pas demandé cette réinitialisation, ignorez cet email.</p>
                        <hr style="margin: 30px 0; border: none; border-top: 1px solid #ddd;">
                        <p style="color: #666; font-size: 12px;">
                            LGRE² Marketplace<br>
                            Power by Guy Stephane NGUENE Makondo<br>
                            Contact: +237 687870254 | guystephanenguenemakondo@gmail.com
                        </p>
                    </div>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);

        res.json({ 
            message: 'Code de réinitialisation envoyé par email',
            email: user.email 
        });
    } catch (error) {
        console.error('Erreur envoi email:', error);
        res.status(500).json({ error: 'Erreur lors de l\'envoi de l\'email' });
    }
});

// Verify Reset Code
app.post('/api/auth/verify-reset-code', async (req, res) => {
    try {
        const { email, code } = req.body;

        const hashedCode = crypto.createHash('sha256').update(code).digest('hex');

        const user = await User.findOne({
            email,
            resetPasswordToken: hashedCode,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ error: 'Code invalide ou expiré' });
        }

        res.json({ message: 'Code valide', email: user.email });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Reset Password
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { email, code, newPassword } = req.body;

        // Validation du nouveau mot de passe
        if (!validatePassword(newPassword)) {
            return res.status(400).json({ 
                error: 'Le mot de passe doit contenir au moins 10 caractères, incluant des lettres, des chiffres et des caractères spéciaux' 
            });
        }

        const hashedCode = crypto.createHash('sha256').update(code).digest('hex');

        const user = await User.findOne({
            email,
            resetPasswordToken: hashedCode,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ error: 'Code invalide ou expiré' });
        }

        // Mettre à jour le mot de passe
        user.password = await bcrypt.hash(newPassword, 12);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.json({ message: 'Mot de passe réinitialisé avec succès' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get Current User
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update Profile
app.put('/api/auth/profile', authenticateToken, upload.single('profileImage'), async (req, res) => {
    try {
        const { name, phone, location, bio } = req.body;
        const updateData = { name, phone, location, bio };

        if (req.file) {
            updateData.profileImage = '/uploads/profiles/' + req.file.filename;
        }

        const user = await User.findByIdAndUpdate(
            req.user.id,
            updateData,
            { new: true }
        ).select('-password');

        res.json({ message: 'Profil mis à jour', user });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== LISTING ROUTES (Produits et Services) =====

// Create Listing
app.post('/api/listings', authenticateToken, upload.array('images', 5), async (req, res) => {
    try {
        const { type, title, description, price, category, condition, location, contactPhone } = req.body;

        const images = req.files ? req.files.map(file => '/uploads/listings/' + file.filename) : [];

        const listing = new Listing({
            type,
            title,
            description,
            price: Number(price),
            category,
            condition: condition || 'new',
            seller: req.user.id,
            images,
            location,
            contactPhone: contactPhone || null
        });

        await listing.save();

        res.status(201).json({
            message: 'Annonce créée avec succès',
            listing
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get All Listings (avec filtres et recherche)
app.get('/api/listings', async (req, res) => {
    try {
        const { 
            type, 
            category, 
            search, 
            minPrice, 
            maxPrice, 
            location, 
            condition,
            sort = '-createdAt'
        } = req.query;

        let query = { available: true };

        if (type && type !== 'all') query.type = type;
        if (category && category !== 'all') query.category = category;
        if (condition && condition !== 'all') query.condition = condition;
        if (location) query.location = { $regex: location, $options: 'i' };

        if (search) {
            query.$or = [
                { title: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } }
            ];
        }

        if (minPrice || maxPrice) {
            query.price = {};
            if (minPrice) query.price.$gte = Number(minPrice);
            if (maxPrice) query.price.$lte = Number(maxPrice);
        }

        const listings = await Listing.find(query)
            .populate('seller', 'pseudo name profileImage location')
            .sort(sort)
            .limit(100);

        res.json(listings);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get Single Listing
app.get('/api/listings/:id', async (req, res) => {
    try {
        const listing = await Listing.findById(req.params.id)
            .populate('seller', 'pseudo name profileImage location phone email createdAt');

        if (!listing) {
            return res.status(404).json({ error: 'Annonce non trouvée' });
        }

        // Increment views
        listing.views += 1;
        await listing.save();

        res.json(listing);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get User's Listings
app.get('/api/listings/user/:userId', async (req, res) => {
    try {
        const listings = await Listing.find({ seller: req.params.userId })
            .sort({ createdAt: -1 });

        res.json(listings);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update Listing
app.put('/api/listings/:id', authenticateToken, upload.array('images', 5), async (req, res) => {
    try {
        const listing = await Listing.findById(req.params.id);

        if (!listing) {
            return res.status(404).json({ error: 'Annonce non trouvée' });
        }

        if (listing.seller.toString() !== req.user.id) {
            return res.status(403).json({ error: 'Non autorisé' });
        }

        const { title, description, price, category, condition, location, contactPhone, available } = req.body;

        listing.title = title || listing.title;
        listing.description = description || listing.description;
        listing.price = price ? Number(price) : listing.price;
        listing.category = category || listing.category;
        listing.condition = condition || listing.condition;
        listing.location = location || listing.location;
        listing.contactPhone = contactPhone !== undefined ? contactPhone : listing.contactPhone;
        listing.available = available !== undefined ? available : listing.available;

        if (req.files && req.files.length > 0) {
            const newImages = req.files.map(file => '/uploads/listings/' + file.filename);
            listing.images = [...listing.images, ...newImages];
        }

        await listing.save();

        res.json({ message: 'Annonce mise à jour', listing });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete Listing
app.delete('/api/listings/:id', authenticateToken, async (req, res) => {
    try {
        const listing = await Listing.findById(req.params.id);

        if (!listing) {
            return res.status(404).json({ error: 'Annonce non trouvée' });
        }

        if (listing.seller.toString() !== req.user.id && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Non autorisé' });
        }

        await listing.deleteOne();

        res.json({ message: 'Annonce supprimée' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== MESSAGING ROUTES =====

// Send Message
app.post('/api/messages', authenticateToken, async (req, res) => {
    try {
        const { receiverId, content, listingId } = req.body;

        if (!content || !receiverId) {
            return res.status(400).json({ error: 'Contenu et destinataire requis' });
        }

        // Créer l'ID de conversation (userId triés alphabétiquement)
        const conversationId = [req.user.id, receiverId].sort().join('_');

        const message = new Message({
            conversation: conversationId,
            sender: req.user.id,
            receiver: receiverId,
            listingRef: listingId || null,
            content
        });

        await message.save();

        const populatedMessage = await Message.findById(message._id)
            .populate('sender', 'pseudo profileImage')
            .populate('receiver', 'pseudo profileImage')
            .populate('listingRef', 'title images');

        res.status(201).json({
            message: 'Message envoyé',
            data: populatedMessage
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get Conversation
app.get('/api/messages/conversation/:userId', authenticateToken, async (req, res) => {
    try {
        const conversationId = [req.user.id, req.params.userId].sort().join('_');

        const messages = await Message.find({ conversation: conversationId })
            .populate('sender', 'pseudo profileImage')
            .populate('receiver', 'pseudo profileImage')
            .populate('listingRef', 'title images price')
            .sort({ createdAt: 1 });

        // Marquer les messages comme lus
        await Message.updateMany(
            { 
                conversation: conversationId,
                receiver: req.user.id,
                read: false
            },
            { read: true }
        );

        res.json(messages);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get All Conversations
app.get('/api/messages/conversations', authenticateToken, async (req, res) => {
    try {
        // Trouver tous les messages de l'utilisateur
        const messages = await Message.find({
            $or: [
                { sender: req.user.id },
                { receiver: req.user.id }
            ]
        })
        .populate('sender', 'pseudo profileImage')
        .populate('receiver', 'pseudo profileImage')
        .populate('listingRef', 'title images')
        .sort({ createdAt: -1 });

        // Grouper par conversation et récupérer le dernier message
        const conversationsMap = new Map();

        messages.forEach(msg => {
            const conversationId = msg.conversation;
            
            if (!conversationsMap.has(conversationId)) {
                const otherUser = msg.sender._id.toString() === req.user.id 
                    ? msg.receiver 
                    : msg.sender;

                conversationsMap.set(conversationId, {
                    conversationId,
                    otherUser,
                    lastMessage: msg,
                    unreadCount: 0
                });
            }

            // Compter les messages non lus
            if (msg.receiver._id.toString() === req.user.id && !msg.read) {
                conversationsMap.get(conversationId).unreadCount++;
            }
        });

        const conversations = Array.from(conversationsMap.values());

        res.json(conversations);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get Unread Count
app.get('/api/messages/unread-count', authenticateToken, async (req, res) => {
    try {
        const count = await Message.countDocuments({
            receiver: req.user.id,
            read: false
        });

        res.json({ count });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== USER ROUTES =====

// Get User Profile (public)
app.get('/api/users/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password -resetPasswordToken -resetPasswordExpires');
        
        if (!user) {
            return res.status(404).json({ error: 'Utilisateur non trouvé' });
        }

        // Compter les annonces de l'utilisateur
        const listingsCount = await Listing.countDocuments({ seller: req.params.id, available: true });

        res.json({
            ...user.toObject(),
            listingsCount
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Search Users
app.get('/api/users/search/:query', async (req, res) => {
    try {
        const users = await User.find({
            $or: [
                { pseudo: { $regex: req.params.query, $options: 'i' } },
                { name: { $regex: req.params.query, $options: 'i' } }
            ]
        })
        .select('pseudo name profileImage location')
        .limit(20);

        res.json(users);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ===== ADMIN ROUTES =====

// Get Dashboard Stats
app.get('/api/admin/stats', authenticateToken, isAdmin, async (req, res) => {
    try {
        const totalUsers = await User.countDocuments();
        const totalListings = await Listing.countDocuments();
        const totalProducts = await Listing.countDocuments({ type: 'product' });
        const totalServices = await Listing.countDocuments({ type: 'service' });
        const totalMessages = await Message.countDocuments();

        res.json({
            users: totalUsers,
            listings: totalListings,
            products: totalProducts,
            services: totalServices,
            messages: totalMessages
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== SERVER START ====================

// Serve static files
app.use(express.static('public'));

// Root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Route non trouvée' });
});

// Start server
app.listen(PORT, () => {
    console.log(`
    ╔═══════════════════════════════════════════════╗
    ║          🔷 LGRE² Server v2.0 🔷             ║
    ╠═══════════════════════════════════════════════╣
    ║  Port: ${PORT}                                  ║
    ║  Environment: ${process.env.NODE_ENV || 'development'}            ║
    ║  API: http://localhost:${PORT}/api              ║
    ║  Power by: Guy Stephane NGUENE Makondo       ║
    ╚═══════════════════════════════════════════════╝
    `);
});

module.exports = app;
