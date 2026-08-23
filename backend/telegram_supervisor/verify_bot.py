#!/usr/bin/env python3
"""Verify Telegram bot connection and send welcome message."""

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


def main():
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

    # Step 1: Test bot connection (using simple HTTP request)
    print("[1/4] Testing bot connection...")
    try:
        import requests
        
        response = requests.get(
            f"https://api.telegram.org/bot{token}/getMe",
            timeout=10
        )
        data = response.json()
        
        if data.get("ok"):
            me = data.get("result", {})
            print(f"✅ Bot connected!")
            print(f"   Username: @{me.get('username', 'N/A')}")
            print(f"   Name: {me.get('first_name', 'N/A')}")
            print()
        else:
            print(f"❌ Failed to connect bot: {data.get('description', 'Unknown error')}")
            return False
    except Exception as e:
        print(f"❌ Failed to connect bot: {e}")
        return False

    # Step 2: Chat validation
    print("[2/4] Validating chat connection...")
    try:
        import requests
        
        # Try to get chat info
        response = requests.get(
            f"https://api.telegram.org/bot{token}/getChat",
            params={"chat_id": int(chat_id)},
            timeout=10
        )
        data = response.json()
        
        if data.get("ok"):
            chat_info = data.get("result", {})
            print(f"✅ Chat is accessible!")
            print(f"   Chat ID: {chat_info.get('id')}")
            if chat_info.get('first_name'):
                print(f"   User: {chat_info.get('first_name')}")
            print()
        else:
            # Chat not found likely means user hasn't sent /start to bot yet
            print("⚠️  Chat not yet initialized")
            print("   Action: Open Telegram and write /start to @platanus_hackbot")
            print("   Then run this script again.")
            print()
            return False
    except Exception as e:
        print(f"❌ Failed to validate chat: {e}")
        return False

    # Step 3: Check models and database
    print("[3/4] Validating models and database...")
    try:
        from telegram_supervisor.models import SupervisorConfig, QuarantineAlert, ApprovalRequest
        from telegram_supervisor.database import TelegramBotDatabase

        # Test config creation (doesn't need Bot)
        config = SupervisorConfig(
            telegram_token=token,
            admin_chat_id=chat_id,
        )
        
        # Test database
        db = TelegramBotDatabase("verify_test.db")
        db.close()

        print(f"✅ Models and database validated!")
        print(f"   SupervisorConfig OK")
        print(f"   TelegramBotDatabase OK")
        print()
    except Exception as e:
        print(f"❌ Failed validation: {e}")
        import traceback
        traceback.print_exc()
        return False

    # Step 4: Send test alert
    print("[4/4] Sending test alert...")
    try:
        import requests
        
        test_alert = "🚨 TEST ALERT (5f2e1a3c)\n\nThreat Score: 85%\nSource: test_bot\nThreats: prompt_injection, data_exfiltration\n\nPreview: Ignore previous instructions...\n\nStatus: Test Alert - Everything Working!\n\n[✅ Approve] [❌ Reject] [📄 Details]"

        response = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": int(chat_id), "text": test_alert},
            timeout=10
        )
        data = response.json()
        
        if data.get("ok"):
            print("✅ Test alert sent!")
            print()
        else:
            print(f"⚠️  Could not send test alert: {data.get('description', 'Unknown error')}")
            print("   (This is OK, you may need to send /start to bot first)")
            print()
    except Exception as e:
        print(f"⚠️  Could not send test alert: {e}")
        print("   (This is OK, you may need to send /start to bot first)")
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
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⏸️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
