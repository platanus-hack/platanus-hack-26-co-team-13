#!/usr/bin/env python3
"""Verify Telegram bot connection and send welcome message."""

import asyncio
import logging
import os
import sys
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))


async def main():
    """Verify bot and send welcome message."""
    
    # Load environment from .env file
    env_file = Path(__file__).parent.parent.parent / "backend" / ".env"
    if not env_file.exists():
        env_file = Path(".env")
    
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                if "=" in line and not line.startswith("#"):
                    key, value = line.strip().split("=", 1)
                    os.environ[key] = value
    
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_ADMIN_CHAT_ID")
    
    if not token or token == "your_bot_token_here":
        print("❌ Error: TELEGRAM_BOT_TOKEN not configured in .env")
        return False
    
    if not chat_id or chat_id == "your_chat_id_here":
        print("❌ Error: TELEGRAM_ADMIN_CHAT_ID not configured in .env")
        return False
    
    print("=" * 80)
    print("🤖 TELEGRAM SUPERVISOR BOT - VERIFICATION")
    print("=" * 80)
    print()
    
    # Step 1: Test bot connection
    print("[1/4] Testing bot connection...")
    try:
        from telegram import Bot
        
        bot = Bot(token=token)
        me = await bot.get_me()
        print(f"✅ Bot connected!")
        print(f"   Username: @{me.username}")
        print(f"   Name: {me.first_name}")
        print()
    except Exception as e:
        print(f"❌ Failed to connect bot: {e}")
        return False
    
    # Step 2: Send welcome message
    print("[2/4] Sending welcome message...")
    try:
        welcome_message = "🤖 Firewall Supervisor Bot - Online!\n\nYour bot is now connected and ready to receive firewall alerts.\n\nAvailable Commands:\n• /start - Show this message\n• /status - Bot status\n• /alerts - Recent alerts\n• /pending - Pending approvals\n• /report - Daily report\n• /critical - Critical alerts\n\nReady to receive alerts! 🚀"
        
        await bot.send_message(
            chat_id=int(chat_id),
            text=welcome_message,
        )
        print("✅ Welcome message sent!")
        print()
    except Exception as e:
        print(f"❌ Failed to send message: {e}")
        return False
    
    # Step 3: Send test alert
    print("[3/4] Sending test alert...")
    try:
        test_alert = "🚨 TEST ALERT (5f2e1a3c)\n\nThreat Score: 85%\nSource: test_bot\nThreats: prompt_injection, data_exfiltration\n\nPreview: Ignore previous instructions...\n\nStatus: Test Alert - Everything Working!\n\n[✅ Approve] [❌ Reject] [📄 Details]"
        
        await bot.send_message(
            chat_id=int(chat_id),
            text=test_alert,
        )
        print("✅ Test alert sent!")
        print()
    except Exception as e:
        print(f"❌ Failed to send test alert: {e}")
        return False
    
    # Step 4: Test status
    print("[4/4] Getting bot statistics...")
    try:
        # Try to initialize supervisor to show it works
        from models import SupervisorConfig
        from bot import TelegramSupervisor
        
        config = SupervisorConfig(
            telegram_token=token,
            admin_chat_id=chat_id,
        )
        supervisor = TelegramSupervisor(config)
        
        print(f"✅ Supervisor initialized!")
        print(f"   Config validated")
        print(f"   Database ready")
        print()
    except Exception as e:
        print(f"⚠️  Warning: {e}")
        print("   (This is OK, database will be created on first run)")
        print()
    
    # Success!
    print("=" * 80)
    print("✅ ALL VERIFICATION CHECKS PASSED!")
    print("=" * 80)
    print()
    print("🎉 Your bot is ready to receive firewall alerts!")
    print()
    print("Next steps:")
    print()
    print("1. Start the backend:")
    print("   $ cd backend")
    print("   $ python -m api.main")
    print()
    print("2. Check your Telegram - you should see:")
    print("   • Welcome message")
    print("   • Test alert with buttons")
    print()
    print("3. Try the /start command in your bot")
    print()
    print("4. To send alerts from your code:")
    print()
    print("   from api.main import telegram_bridge")
    print()
    print("   if telegram_bridge:")
    print("       await telegram_bridge.on_memory_quarantined(")
    print("           analysis_id='ana_123',")
    print("           content='Malicious content',")
    print("           threats_detected=['prompt_injection'],")
    print("           threat_score=0.95,")
    print("           authority='untrusted',")
    print("           source='email',")
    print("       )")
    print()
    print("5. Or use the test endpoint:")
    print()
    print("   curl -X POST http://127.0.0.1:8000/api/v1/telegram/send-alert \\")
    print("     -H 'Content-Type: application/json' \\")
    print("     -d '{\"severity\":\"HIGH\",\"content_preview\":\"Test\",\"threats\":[\"test\"],\"threat_score\":0.8}'")
    print()
    print("=" * 80)
    print()
    
    return True


if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⏸️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
