
#!/bin/bash

# Millennium Cybersecurity Platform Startup Script
# Educational cybersecurity training platform

echo "🚀 Starting Millennium Cybersecurity Platform..."

# Check Node.js version
echo "📋 Checking Node.js version..."
node --version

# Check Python version
echo "📋 Checking Python version..."
python3 --version

# Install Python dependencies if they don't exist
if [ ! -d "python_env" ]; then
    echo "📦 Installing Python dependencies..."
    pip3 install -r python_requirements.txt
fi

# Create necessary directories
echo "📁 Creating required directories..."
mkdir -p builds
mkdir -p temp
mkdir -p python_tools/output

# Check database connection
echo "🗄️ Checking database connection..."
if [ -z "$DATABASE_URL" ]; then
    echo "❌ DATABASE_URL not set!"
    exit 1
fi

# Run database migrations
echo "🔄 Running database migrations..."
npm run db:push

# Build application if in production
if [ "$NODE_ENV" = "production" ]; then
    echo "🏗️ Building application for production..."
    npm run build
fi

# Start the application
echo "🎯 Starting application..."
if [ "$NODE_ENV" = "production" ]; then
    npm start
else
    npm run dev
fi
