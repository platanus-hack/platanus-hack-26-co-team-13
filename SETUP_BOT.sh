#!/bin/bash

# Script to set up Telegram Supervisor Bot with your credentials

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR/backend"

echo "════════════════════════════════════════════════════════════════════════════════"
echo "🤖 TELEGRAM SUPERVISOR BOT - SETUP"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "❌ Error: .env file not found in backend/"
    echo "   Please create it first with your TELEGRAM_BOT_TOKEN and TELEGRAM_ADMIN_CHAT_ID"
    exit 1
fi

# Extract values from .env
BOT_TOKEN=$(grep "TELEGRAM_BOT_TOKEN=" .env | cut -d'=' -f2)
CHAT_ID=$(grep "TELEGRAM_ADMIN_CHAT_ID=" .env | cut -d'=' -f2)

# Verify they're set
if [ -z "$BOT_TOKEN" ] || [ "$BOT_TOKEN" = "your_bot_token_here" ]; then
    echo "❌ Error: TELEGRAM_BOT_TOKEN not set in .env"
    exit 1
fi

if [ -z "$CHAT_ID" ] || [ "$CHAT_ID" = "your_chat_id_here" ]; then
    echo "❌ Error: TELEGRAM_ADMIN_CHAT_ID not set in .env"
    exit 1
fi

echo "✅ Configuration found:"
echo "   Bot Token: ${BOT_TOKEN:0:10}...${BOT_TOKEN: -10}"
echo "   Chat ID: $CHAT_ID"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: python3 not found"
    exit 1
fi

echo "✅ Python3 found: $(python3 --version)"
echo ""

# Check dependencies
echo "📦 Checking dependencies..."
python3 -c "import telegram" 2>/dev/null || {
    echo "⚠️  Installing python-telegram-bot..."
    pip install python-telegram-bot aiohttp -q
}

python3 -c "import fastapi" 2>/dev/null || {
    echo "⚠️  Installing FastAPI dependencies..."
    pip install -r requirements.txt -q
}

echo "✅ All dependencies ready"
echo ""

# Test bot token
echo "🔍 Testing bot token..."
python3 << 'PYTHON_SCRIPT'
import sys
import os
from telegram import Bot
import asyncio

async def test_bot():
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        token = open('.env').read()
        token = [line.split('=')[1].strip() for line in token.split('\n') if 'TELEGRAM_BOT_TOKEN=' in line][0]
    
    try:
        bot = Bot(token=token)
        me = await bot.get_me()
        print(f"✅ Bot connected: @{me.username}")
        return True
    except Exception as e:
        print(f"❌ Bot connection failed: {e}")
        return False

try:
    success = asyncio.run(test_bot())
    sys.exit(0 if success else 1)
except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)
PYTHON_SCRIPT

if [ $? -ne 0 ]; then
    echo "❌ Bot token verification failed"
    exit 1
fi

echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo "🎉 SETUP COMPLETE!"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""
echo "To start the bot, run:"
echo ""
echo "    python -m api.main"
echo ""
echo "Then in Telegram:"
echo "  1. Find your bot"
echo "  2. Type: /start"
echo "  3. You should see available commands"
echo ""
echo "To test alerts:"
echo ""
echo "    curl -X POST http://127.0.0.1:8000/api/v1/telegram/send-alert \\"
echo "      -H 'Content-Type: application/json' \\"
echo "      -d '{\"severity\":\"HIGH\",\"content_preview\":\"Test alert\",\"threats\":[\"test\"],\"threat_score\":0.8}'"
echo ""
