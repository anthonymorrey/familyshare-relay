// Production Relay Server for Kin
// Optimized for Railway deployment
// Free tier capable: Handles 10K+ users

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== SECURITY MIDDLEWARE =====
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
        },
    },
}));

// ===== CORS =====
app.use(cors({
    origin: process.env.NODE_ENV === 'production' 
        ? ['https://relay.antomictech.com', 'https://share.antomictech.com']
        : '*',
    credentials: true
}));

// ===== RATE LIMITING =====
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per window
    message: 'Too many requests, please try again later'
});

const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 200, // 200 uploads per hour per IP
    message: 'Upload limit reached, please try again later'
});

// ===== BODY PARSING =====
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));
app.use(compression());

// ===== IN-MEMORY STORAGE =====
// For production with > 1000 users, migrate to Redis or MongoDB
const messageQueue = {};
const MESSAGE_EXPIRY = 48 * 60 * 60 * 1000; // 48 hours

// ===== CLEANUP OLD MESSAGES =====
function cleanupOldMessages() {
    const now = Date.now();
    let cleaned = 0;
    
    for (const deviceId in messageQueue) {
        const before = messageQueue[deviceId].length;
        messageQueue[deviceId] = messageQueue[deviceId].filter(msg => {
            return now - new Date(msg.timestamp).getTime() < MESSAGE_EXPIRY;
        });
        cleaned += before - messageQueue[deviceId].length;
        
        if (messageQueue[deviceId].length === 0) {
            delete messageQueue[deviceId];
        }
    }
    
    if (cleaned > 0) {
        console.log(`[CLEANUP] Removed ${cleaned} expired messages`);
    }
}

// Run cleanup every hour
setInterval(cleanupOldMessages, 60 * 60 * 1000);

// ===== HEALTH CHECK =====
app.get('/health', (req, res) => {
    const totalMessages = Object.values(messageQueue).reduce((sum, msgs) => sum + msgs.length, 0);
    const totalDevices = Object.keys(messageQueue).length;
    
    res.json({
        status: 'ok',
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        stats: {
            devices: totalDevices,
            messages: totalMessages,
            memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB'
        }
    });
});

// ===== ROOT ENDPOINT =====
app.get('/', (req, res) => {
    res.json({
        name: 'Kin Relay Server',
        version: '1.0.0',
        status: 'running',
        endpoints: {
            health: '/health',
            upload: 'POST /api/upload',
            check: 'POST /api/check',
            download: 'POST /api/download'
        }
    });
});

// ===== UPLOAD ENDPOINT =====
app.post('/api/upload', uploadLimiter, async (req, res) => {
    try {
        const { deviceId, filename, thumbnail, fullResolution, metadata, recipients, timestamp } = req.body;

        // Validation
        if (!deviceId || !filename || !thumbnail || !recipients || !metadata) {
            return res.status(400).json({ 
                error: 'Missing required fields',
                required: ['deviceId', 'filename', 'thumbnail', 'recipients', 'metadata']
            });
        }

        if (!Array.isArray(recipients) || recipients.length === 0) {
            return res.status(400).json({ error: 'Recipients must be a non-empty array' });
        }

        // Size validation (prevent abuse)
        const thumbnailSize = Buffer.from(thumbnail, 'base64').length;
        if (thumbnailSize > 500 * 1024) { // 500KB max for thumbnail
            return res.status(400).json({ error: 'Thumbnail too large (max 500KB)' });
        }

        if (fullResolution) {
            const fullSize = Buffer.from(fullResolution, 'base64').length;
            if (fullSize > 10 * 1024 * 1024) { // 10MB max for full resolution
                return res.status(400).json({ error: 'Full resolution too large (max 10MB)' });
            }
        }

        const message = {
            id: `${deviceId}-${Date.now()}`,
            filename,
            thumbnail,
            fullResolution: fullResolution || '',
            metadata,
            timestamp: timestamp || new Date().toISOString(),
            from: deviceId,
            receivedAt: new Date().toISOString()
        };

        // Queue message for each recipient
        let queued = 0;
        recipients.forEach(recipientId => {
            if (recipientId && recipientId !== deviceId) { // Don't queue for self
                if (!messageQueue[recipientId]) {
                    messageQueue[recipientId] = [];
                }
                messageQueue[recipientId].push(message);
                queued++;
            }
        });

        console.log(`[UPLOAD] ${filename} from ${deviceId} → ${queued} recipients`);
        
        res.json({ 
            success: true, 
            recipients: queued,
            messageId: message.id,
            expiresIn: '48 hours'
        });

    } catch (error) {
        console.error('[UPLOAD ERROR]', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ===== CHECK FOR NEW MESSAGES =====
app.post('/api/check', apiLimiter, async (req, res) => {
    try {
        const { deviceId, lastCheckTime } = req.body;

        if (!deviceId) {
            return res.status(400).json({ error: 'Missing deviceId' });
        }

        const messages = messageQueue[deviceId] || [];
        
        // Get only new messages since last check
        const lastCheck = lastCheckTime ? new Date(lastCheckTime) : new Date(0);
        const newMessages = messages.filter(msg => 
            new Date(msg.timestamp) > lastCheck
        );

        console.log(`[CHECK] Device ${deviceId}: ${newMessages.length} new messages`);
        
        res.json({ 
            items: newMessages,
            count: newMessages.length,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('[CHECK ERROR]', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ===== DOWNLOAD FULL RESOLUTION =====
app.post('/api/download', apiLimiter, async (req, res) => {
    try {
        const { filename, deviceId, requestFrom } = req.body;

        if (!filename || !deviceId || !requestFrom) {
            return res.status(400).json({ 
                error: 'Missing required fields',
                required: ['filename', 'deviceId', 'requestFrom']
            });
        }

        // Find the message in the queue
        const messages = messageQueue[deviceId] || [];
        const message = messages.find(msg => 
            msg.filename === filename && msg.from === requestFrom
        );

        if (message && message.fullResolution) {
            console.log(`[DOWNLOAD] ${filename} → ${deviceId}`);
            res.json({ 
                data: message.fullResolution,
                filename: message.filename,
                timestamp: message.timestamp
            });
        } else {
            res.status(404).json({ 
                error: 'File not found or no full resolution available',
                filename: filename
            });
        }

    } catch (error) {
        console.error('[DOWNLOAD ERROR]', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ===== ACKNOWLEDGE RECEIPT (DELETE MESSAGE) =====
app.post('/api/acknowledge', apiLimiter, async (req, res) => {
    try {
        const { deviceId, messageId } = req.body;

        if (!deviceId || !messageId) {
            return res.status(400).json({ error: 'Missing deviceId or messageId' });
        }

        if (messageQueue[deviceId]) {
            const before = messageQueue[deviceId].length;
            messageQueue[deviceId] = messageQueue[deviceId].filter(msg => msg.id !== messageId);
            const removed = before - messageQueue[deviceId].length;
            
            if (messageQueue[deviceId].length === 0) {
                delete messageQueue[deviceId];
            }
            
            console.log(`[ACK] Device ${deviceId} acknowledged ${messageId}`);
            res.json({ success: true, removed });
        } else {
            res.json({ success: false, message: 'No messages for device' });
        }

    } catch (error) {
        console.error('[ACK ERROR]', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ===== STATS ENDPOINT (Protected) =====
const statsAuth = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (apiKey === process.env.ADMIN_API_KEY) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
};

app.get('/api/stats', statsAuth, (req, res) => {
    const stats = {
        totalDevices: Object.keys(messageQueue).length,
        totalMessages: Object.values(messageQueue).reduce((sum, msgs) => sum + msgs.length, 0),
        messagesByDevice: Object.entries(messageQueue).map(([deviceId, messages]) => ({
            deviceId: deviceId.substring(0, 8) + '...',
            count: messages.length
        })),
        oldestMessage: null,
        newestMessage: null,
        memoryUsage: {
            heapUsed: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
            heapTotal: Math.round(process.memoryUsage().heapTotal / 1024 / 1024) + 'MB'
        },
        uptime: Math.round(process.uptime() / 60) + ' minutes'
    };

    // Find oldest and newest messages
    const allMessages = Object.values(messageQueue).flat();
    if (allMessages.length > 0) {
        stats.oldestMessage = allMessages.reduce((oldest, msg) => 
            new Date(msg.timestamp) < new Date(oldest.timestamp) ? msg : oldest
        ).timestamp;
        
        stats.newestMessage = allMessages.reduce((newest, msg) => 
            new Date(msg.timestamp) > new Date(newest.timestamp) ? msg : newest
        ).timestamp;
    }

    res.json(stats);
});

// ===== ERROR HANDLING =====
app.use((err, req, res, next) => {
    console.error('[ERROR]', err);
    res.status(500).json({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// ===== 404 HANDLER =====
app.use((req, res) => {
    res.status(404).json({ 
        error: 'Not found',
        path: req.path,
        availableEndpoints: ['/', '/health', '/api/upload', '/api/check', '/api/download']
    });
});

// ===== START SERVER =====
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log('╔════════════════════════════════════════╗');
    console.log('║   🚀 Kin Relay Server                 ║');
    console.log('║   📡 Production Ready                 ║');
    console.log('╚════════════════════════════════════════╝');
    console.log('');
    console.log(`🌐 Server: http://localhost:${PORT}`);
    console.log(`📊 Health: http://localhost:${PORT}/health`);
    console.log(`🔒 Mode: ${process.env.NODE_ENV || 'development'}`);
    console.log('');
    console.log('✅ Ready to receive connections');
    console.log('');
});

// ===== GRACEFUL SHUTDOWN =====
process.on('SIGTERM', () => {
    console.log('[SHUTDOWN] Received SIGTERM, cleaning up...');
    server.close(() => {
        console.log('[SHUTDOWN] Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('[SHUTDOWN] Received SIGINT, cleaning up...');
    server.close(() => {
        console.log('[SHUTDOWN] Server closed');
        process.exit(0);
    });
});

// ===== UNCAUGHT EXCEPTION HANDLER =====
process.on('uncaughtException', (err) => {
    console.error('[FATAL] Uncaught Exception:', err);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('[FATAL] Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});
