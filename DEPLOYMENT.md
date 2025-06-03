
# Millennium Cybersecurity Platform - Deployment Guide

## Overview
This guide covers deployment of the Millennium Cybersecurity Platform on Replit and provides manual deployment instructions for advanced users.

## Replit Deployment (Recommended)

### Prerequisites
- Replit account with Core membership (for deployment features)
- Environment variables configured in Secrets

### Required Environment Variables
Set these in Replit Secrets:
```
DATABASE_URL=postgresql://username:password@host:port/database
SESSION_SECRET=your-secure-session-secret-key
GROQ_API_KEY=your-groq-api-key-for-ai-features
MASTER_BOT_TOKEN=your-telegram-master-bot-token
```

### Deployment Steps
1. **Fork/Import Repository**
   - Import this repository to your Replit workspace
   - Ensure all dependencies are installed via `npm install`

2. **Configure Database**
   - Use Replit's PostgreSQL addon or external database
   - Run database migrations: `npm run db:push`

3. **Set Environment Variables**
   - Go to Secrets tab in Replit
   - Add all required environment variables listed above

4. **Deploy**
   - Click the "Deploy" button in Replit
   - Select "Autoscale Deployment" for web applications
   - Configure deployment settings:
     - Build command: `npm run build`
     - Run command: `npm start`
     - Machine type: Basic (upgradeable based on traffic)

5. **Custom Domain (Optional)**
   - Configure custom domain in deployment settings
   - Update DNS records as instructed

## Manual Deployment Instructions

### System Requirements
- Node.js 18+ 
- Python 3.8+
- PostgreSQL 12+
- SSL certificate (for production)

### Installation Steps

1. **Clone Repository**
```bash
git clone <repository-url>
cd millennium-platform
```

2. **Install Dependencies**
```bash
# Node.js dependencies
npm install

# Python dependencies (for toolkit features)
pip install -r python_requirements.txt
```

3. **Database Setup**
```bash
# Create PostgreSQL database
createdb millennium_platform

# Set DATABASE_URL environment variable
export DATABASE_URL="postgresql://username:password@localhost:5432/millennium_platform"

# Run migrations
npm run db:push
```

4. **Environment Configuration**
Create `.env` file:
```env
NODE_ENV=production
PORT=5000
DATABASE_URL=postgresql://username:password@localhost:5432/millennium_platform
SESSION_SECRET=your-super-secure-session-secret-minimum-32-chars
GROQ_API_KEY=your-groq-api-key
MASTER_BOT_TOKEN=your-telegram-bot-token
```

5. **Build Application**
```bash
npm run build
```

6. **Start Production Server**
```bash
npm start
```

## Production Considerations

### Security
- Use HTTPS in production
- Configure proper firewall rules
- Regularly update dependencies
- Implement rate limiting
- Monitor for suspicious activity

### Performance
- Use a reverse proxy (nginx/Apache)
- Configure caching headers
- Optimize database queries
- Monitor resource usage

### Monitoring
- Set up log aggregation
- Configure health checks
- Monitor database performance
- Track user analytics

## File Structure for Deployment

### Required Files
```
├── dist/                 # Built application (generated)
├── client/              # React frontend
├── server/              # Express backend
├── python_tools/        # Cybersecurity toolkit
├── shared/              # Shared schemas
├── package.json         # Node.js dependencies
├── .replit             # Replit configuration
└── vite.config.ts      # Build configuration
```

### Generated During Build
```
├── dist/public/        # Frontend build output
├── dist/index.js       # Backend build output
└── builds/            # Python tool builds
```

## Database Schema

The application uses PostgreSQL with the following tables:
- `admin_users` - User management
- `visitors` - Visitor tracking
- `packet_logs` - Network monitoring
- `analytics` - System analytics
- `sessions` - Session management

## API Endpoints

### Authentication
- `POST /api/admin/login` - Admin login
- `POST /api/admin/logout` - Admin logout
- `GET /api/admin/me` - Get current user

### Admin Panel
- `GET /api/admin/stats` - Dashboard statistics
- `GET /api/admin/visitors` - Visitor data
- `GET /api/admin/packets` - Packet logs

### Tools
- `POST /api/admin/execute-tool` - Execute cybersecurity tools
- `POST /api/admin/build-executable` - Build Python executables
- `POST /api/advanced-crypter` - Advanced file encryption

## Troubleshooting

### Common Issues

1. **Port Already in Use**
   - Change PORT environment variable
   - Kill existing processes: `pkill -f node`

2. **Database Connection Failed**
   - Verify DATABASE_URL format
   - Check PostgreSQL service status
   - Ensure database exists

3. **Python Tools Not Working**
   - Install Python dependencies: `pip install -r python_requirements.txt`
   - Check Python version compatibility
   - Verify file permissions

4. **Build Failures**
   - Clear node_modules: `rm -rf node_modules && npm install`
   - Check TypeScript errors: `npm run check`
   - Verify all imports are correct

### Performance Optimization

1. **Frontend**
   - Enable gzip compression
   - Configure CDN for static assets
   - Optimize bundle size

2. **Backend**
   - Use database connection pooling
   - Implement Redis for session storage
   - Configure proper caching headers

3. **Python Tools**
   - Pre-compile frequently used tools
   - Use virtual environments
   - Optimize memory usage

## Support

For deployment issues:
1. Check logs for error messages
2. Verify all environment variables
3. Ensure proper file permissions
4. Test database connectivity

## Security Notice

This platform is designed for educational cybersecurity training and authorized penetration testing only. Ensure proper authorization before deployment and use in accordance with applicable laws and regulations.
