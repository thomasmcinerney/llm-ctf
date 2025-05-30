#!/usr/bin/env python3
"""
Simple startup script for the LLM Security Research Platform
"""

import sys
import os
from pathlib import Path


def check_dependencies():
    """Check if required dependencies are installed"""
    required_packages = [
        'fastapi', 'uvicorn', 'pydantic', 'python-dotenv', 'openai'
    ]

    missing = []
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing.append(package)

    if missing:
        print(f"❌ Missing required packages: {', '.join(missing)}")
        print("Install them with: pip install -r requirements.txt")
        return False

    return True


def check_env_file():
    """Check if .env file exists and has required keys"""
    env_path = Path(".env")
    if not env_path.exists():
        print("⚠️  No .env file found. Creating template...")
        env_template = """# LLM Security Research Platform Configuration

# Required: OpenAI API Key
OPENAI_API_KEY=your_openai_key_here

# Optional: Anthropic API Key (for Claude support)
ANTHROPIC_API_KEY=your_anthropic_key_here

# Optional: Enable verbose logging
VERBOSE=false

# Optional: Server port
PORT=9000
"""
        env_path.write_text(env_template)
        print("📝 Created .env template file. Please add your API keys!")
        return False

    # Check if OpenAI key is set
    from dotenv import load_dotenv
    load_dotenv()

    if not os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY") == "your_openai_key_here":
        print("❌ OPENAI_API_KEY not set in .env file")
        return False

    return True


def main():
    """Main startup function"""
    print("🔬 LLM Security Research Platform Startup")
    print("=" * 50)

    # Check dependencies
    print("🔍 Checking dependencies...")
    if not check_dependencies():
        sys.exit(1)
    print("✅ Dependencies OK")

    # Check environment
    print("🔍 Checking environment...")
    if not check_env_file():
        sys.exit(1)
    print("✅ Environment OK")

    # Create required directories
    print("📁 Creating directories...")
    Path("logs").mkdir(exist_ok=True)
    Path("research_sessions").mkdir(exist_ok=True)
    print("✅ Directories OK")

    # Import and run the main application
    print("🚀 Starting server...")
    try:
        from main import app
        import uvicorn

        port = int(os.getenv("PORT", "9000"))
        print(f"🌐 Server will start on http://localhost:{port}")
        print("📊 Available endpoints:")
        print("  - GET  /api/challenges")
        print("  - POST /api/start_research")
        print("  - POST /api/interact")
        print("  - GET  /api/sessions")
        print("  - GET  /api/health")
        print("\n🛡️  Security challenges loaded:")

        from config import SECURITY_CHALLENGES
        for challenge_id, challenge in SECURITY_CHALLENGES.items():
            print(f"  - {challenge_id}: {challenge['name']}")

        print("\n" + "=" * 50)
        print("🎯 Ready for security research!")
        print("Press Ctrl+C to stop the server")
        print("=" * 50)

        uvicorn.run(app, host="0.0.0.0", port=port)

    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
    except Exception as e:
        print(f"❌ Failed to start server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()