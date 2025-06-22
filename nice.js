// server.js - Main server file
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(helmet());
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Contact form rate limiting (more restrictive)
const contactLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // limit each IP to 5 contact form submissions per hour
    message: 'Too many contact form submissions, please try again later.'
});

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/peace-org', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

// Database Models
const ContactSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, lowercase: true, trim: true },
    interest: { type: String, enum: ['volunteer', 'donate', 'organize', 'educate', 'other'] },
    message: { type: String, required: true },
    status: { type: String, enum: ['new', 'contacted', 'resolved'], default: 'new' },
    createdAt: { type: Date, default: Date.now },
    ipAddress: String,
    userAgent: String
});

const VolunteerSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    phone: { type: String, trim: true },
    age: { type: Number, min: 16, max: 100 },
    skills: [String],
    availability: {
        days: [{ type: String, enum: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'] }],
        timeSlots: [{ type: String, enum: ['morning', 'afternoon', 'evening'] }]
    },
    experience: String,
    motivation: String,
    status: { type: String, enum: ['pending', 'approved', 'active', 'inactive'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const EventSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    date: { type: Date, required: true },
    time: { type: String, required: true },
    location: {
        address: String,
        city: String,
        state: String,
        zipCode: String,
        coordinates: {
            lat: Number,
            lng: Number
        }
    },
    category: { type: String, enum: ['workshop', 'seminar', 'community-dialogue', 'fundraiser', 'training'], required: true },
    maxAttendees: { type: Number, default: 50 },
    registeredAttendees: [{ type: mongoose.Schema.Types.ObjectId, ref: 'EventRegistration' }],
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const EventRegistrationSchema = new mongoose.Schema({
    eventId: { type: mongoose.Schema.Types.ObjectId, ref: 'Event', required: true },
    name: { type: String, required: true },
    email: { type: String, required: true },
    phone: String,
    specialRequests: String,
    registeredAt: { type: Date, default: Date.now }
});

const NewsletterSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, lowercase: true },
    name: String,
    subscriptionDate: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true },
    preferences: {
        events: { type: Boolean, default: true },
        programs: { type: Boolean, default: true },
        news: { type: Boolean, default: true }
    }
});

const AdminUserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'moderator'], default: 'moderator' },
    createdAt: { type: Date, default: Date.now },
    lastLogin: Date
});

// Create models
const Contact = mongoose.model('Contact', ContactSchema);
const Volunteer = mongoose.model('Volunteer', VolunteerSchema);
const Event = mongoose.model('Event', EventSchema);
const EventRegistration = mongoose.model('EventRegistration', EventRegistrationSchema);
const Newsletter = mongoose.model('Newsletter', NewsletterSchema);
const AdminUser = mongoose.model('AdminUser', AdminUserSchema);

// Email configuration
const transporter = nodemailer.createTransporter({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// File upload configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: function (req, file, cb) {
        const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only images and documents are allowed.'));
        }
    }
});

// Middleware for JWT authentication
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// API Routes

// Contact form submission
app.post('/api/contact', contactLimiter, async (req, res) => {
    try {
        const { name, email, interest, message } = req.body;
        
        // Validation
        if (!name || !email || !message) {
            return res.status(400).json({ error: 'Name, email, and message are required' });
        }
        
        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        // Create contact entry
        const contact = new Contact({
            name,
            email,
            interest: interest || 'other',
            message,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
        });
        
        await contact.save();
        
        // Send confirmation email to user
        const userMailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Thank you for contacting Unity Peace Foundation',
            html: `
                <h3>Thank you for reaching out, ${name}!</h3>
                <p>We have received your message and will get back to you within 24-48 hours.</p>
                <p><strong>Your message:</strong></p>
                <p>${message}</p>
                <p>Together for peace,<br>Unity Peace Foundation Team</p>
            `
        };
        
        // Send notification email to admin
        const adminMailOptions = {
            from: process.env.EMAIL_USER,
            to: process.env.ADMIN_EMAIL,
            subject: 'New Contact Form Submission',
            html: `
                <h3>New Contact Form Submission</h3>
                <p><strong>Name:</strong> ${name}</p>
                <p><strong>Email:</strong> ${email}</p>
                <p><strong>Interest:</strong> ${interest || 'Not specified'}</p>
                <p><strong>Message:</strong></p>
                <p>${message}</p>
                <p><strong>Submitted at:</strong> ${new Date().toISOString()}</p>
            `
        };
        
        await Promise.all([
            transporter.sendMail(userMailOptions),
            transporter.sendMail(adminMailOptions)
        ]);
        
        res.status(201).json({ 
            message: 'Thank you for your message! We will get back to you soon.',
            contactId: contact._id
        });
        
    } catch (error) {
        console.error('Contact form error:', error);
        res.status(500).json({ error: 'Failed to submit contact form' });
    }
});

// Volunteer registration
app.post('/api/volunteer', async (req, res) => {
    try {
        const { name, email, phone, age, skills, availability, experience, motivation } = req.body;
        
        // Validation
        if (!name || !email || !motivation) {
            return res.status(400).json({ error: 'Name, email, and motivation are required' });
        }
        
        // Check if volunteer already exists
        const existingVolunteer = await Volunteer.findOne({ email });
        if (existingVolunteer) {
            return res.status(409).json({ error: 'A volunteer with this email already exists' });
        }
        
        const volunteer = new Volunteer({
            name,
            email,
            phone,
            age,
            skills: skills || [],
            availability: availability || { days: [], timeSlots: [] },
            experience,
            motivation
        });
        
        await volunteer.save();
        
        // Send confirmation email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Welcome to Unity Peace Foundation Volunteer Program',
            html: `
                <h3>Welcome to our volunteer community, ${name}!</h3>
                <p>Thank you for your interest in volunteering with Unity Peace Foundation.</p>
                <p>We will review your application and contact you within 3-5 business days with next steps.</p>
                <p>Together for peace,<br>Unity Peace Foundation Team</p>
            `
        };
        
        await transporter.sendMail(mailOptions);
        
        res.status(201).json({ 
            message: 'Volunteer registration successful! We will contact you soon.',
            volunteerId: volunteer._id
        });
        
    } catch (error) {
        console.error('Volunteer registration error:', error);
        res.status(500).json({ error: 'Failed to register volunteer' });
    }
});

// Newsletter subscription
app.post('/api/newsletter', async (req, res) => {
    try {
        const { email, name, preferences } = req.body;
        
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }
        
        const newsletter = new Newsletter({
            email,
            name,
            preferences: preferences || { events: true, programs: true, news: true }
        });
        
        await newsletter.save();
        
        res.status(201).json({ message: 'Successfully subscribed to newsletter!' });
        
    } catch (error) {
        if (error.code === 11000) {
            res.status(409).json({ error: 'Email already subscribed to newsletter' });
        } else {
            console.error('Newsletter subscription error:', error);
            res.status(500).json({ error: 'Failed to subscribe to newsletter' });
        }
    }
});

// Get upcoming events
app.get('/api/events', async (req, res) => {
    try {
        const { category, limit = 10, page = 1 } = req.query;
        
        const query = { 
            isActive: true,
            date: { $gte: new Date() }
        };
        
        if (category) {
            query.category = category;
        }
        
        const events = await Event.find(query)
            .populate('registeredAttendees', 'name email')
            .sort({ date: 1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);
        
        const total = await Event.countDocuments(query);
        
        res.json({
            events,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
        
    } catch (error) {
        console.error('Get events error:', error);
        res.status(500).json({ error: 'Failed to fetch events' });
    }
});

// Event registration
app.post('/api/events/:eventId/register', async (req, res) => {
    try {
        const { eventId } = req.params;
        const { name, email, phone, specialRequests } = req.body;
        
        if (!name || !email) {
            return res.status(400).json({ error: 'Name and email are required' });
        }
        
        const event = await Event.findById(eventId);
        if (!event) {
            return res.status(404).json({ error: 'Event not found' });
        }
        
        if (event.registeredAttendees.length >= event.maxAttendees) {
            return res.status(400).json({ error: 'Event is full' });
        }
        
        // Check if user already registered
        const existingRegistration = await EventRegistration.findOne({ eventId, email });
        if (existingRegistration) {
            return res.status(409).json({ error: 'You are already registered for this event' });
        }
        
        const registration = new EventRegistration({
            eventId,
            name,
            email,
            phone,
            specialRequests
        });
        
        await registration.save();
        
        // Add registration to event
        event.registeredAttendees.push(registration._id);
        await event.save();
        
        // Send confirmation email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: `Event Registration Confirmation - ${event.title}`,
            html: `
                <h3>Registration Confirmed!</h3>
                <p>Dear ${name},</p>
                <p>You have successfully registered for: <strong>${event.title}</strong></p>
                <p><strong>Date:</strong> ${event.date.toDateString()}</p>
                <p><strong>Time:</strong> ${event.time}</p>
                <p><strong>Location:</strong> ${event.location.address}, ${event.location.city}</p>
                <p>We look forward to seeing you there!</p>
                <p>Unity Peace Foundation Team</p>
            `
        };
        
        await transporter.sendMail(mailOptions);
        
        res.status(201).json({ 
            message: 'Successfully registered for event!',
            registrationId: registration._id
        });
        
    } catch (error) {
        console.error('Event registration error:', error);
        res.status(500).json({ error: 'Failed to register for event' });
    }
});

// Admin login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const admin = await AdminUser.findOne({ username });
        if (!admin) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const isValidPassword = await bcrypt.compare(password, admin.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        admin.lastLogin = new Date();
        await admin.save();
        
        const token = jwt.sign(
            { id: admin._id, username: admin.username, role: admin.role },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            token,
            user: {
                id: admin._id,
                username: admin.username,
                role: admin.role
            }
        });
        
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Admin dashboard - get statistics
app.get('/api/admin/dashboard', authenticateToken, async (req, res) => {
    try {
        const [
            totalContacts,
            newContacts,
            totalVolunteers,
            pendingVolunteers,
            totalEvents,
            upcomingEvents,
            newsletterSubscribers
        ] = await Promise.all([
            Contact.countDocuments(),
            Contact.countDocuments({ status: 'new' }),
            Volunteer.countDocuments(),
            Volunteer.countDocuments({ status: 'pending' }),
            Event.countDocuments(),
            Event.countDocuments({ date: { $gte: new Date() }, isActive: true }),
            Newsletter.countDocuments({ isActive: true })
        ]);
        
        res.json({
            contacts: { total: totalContacts, new: newContacts },
            volunteers: { total: totalVolunteers, pending: pendingVolunteers },
            events: { total: totalEvents, upcoming: upcomingEvents },
            newsletter: { subscribers: newsletterSubscribers }
        });
        
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard data' });
    }
});

// Admin - manage contacts
app.get('/api/admin/contacts', authenticateToken, async (req, res) => {
    try {
        const { status, page = 1, limit = 20 } = req.query;
        
        const query = status ? { status } : {};
        
        const contacts = await Contact.find(query)
            .sort({ createdAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);
        
        const total = await Contact.countDocuments(query);
        
        res.json({
            contacts,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / limit)
            }
        });
        
    } catch (error) {
        console.error('Get contacts error:', error);
        res.status(500).json({ error: 'Failed to fetch contacts' });
    }
});

// Admin - update contact status
app.patch('/api/admin/contacts/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;
        
        if (!['new', 'contacted', 'resolved'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        const contact = await Contact.findByIdAndUpdate(
            id,
            { status },
            { new: true }
        );
        
        if (!contact) {
            return res.status(404).json({ error: 'Contact not found' });
        }
        
        res.json({ message: 'Contact status updated', contact });
        
    } catch (error) {
        console.error('Update contact error:', error);
        res.status(500).json({ error: 'Failed to update contact' });
    }
});

// Admin - create event
app.post('/api/admin/events', authenticateToken, async (req, res) => {
    try {
        const eventData = req.body;
        
        // Validation
        if (!eventData.title || !eventData.description || !eventData.date || !eventData.category) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        
        const event = new Event(eventData);
        await event.save();
        
        res.status(201).json({ message: 'Event created successfully', event });
        
    } catch (error) {
        console.error('Create event error:', error);
        res.status(500).json({ error: 'Failed to create event' });
    }
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`🕊️  Peace Organization API server running on port ${PORT}`);
    console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;