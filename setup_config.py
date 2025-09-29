#!/usr/bin/env python3
"""
Configuration setup script for Censys Data Summarization Agent.
Helps users securely configure API keys and settings.
"""

import os
import sys
from pathlib import Path
from config import get_global_config, setup_secure_config, validate_api_keys


def main():
    """Interactive configuration setup."""
    print("🔧 Censys Data Summarization Agent - Configuration Setup")
    print("=" * 60)
    
    # Initialize configuration
    config = get_global_config()
    setup_secure_config()
    
    print("\n📋 Current Configuration:")
    api_status = validate_api_keys()
    for provider, status in api_status.items():
        status_icon = "✅" if status else "❌"
        print(f"  {status_icon} {provider.upper()}: {'Configured' if status else 'Not configured'}")
    
    print("\n🔑 API Key Configuration:")
    print("Choose how to configure your API keys:")
    print("1. Set environment variables (recommended for production)")
    print("2. Use config file (convenient for development)")
    print("3. Skip configuration (use heuristic analysis only)")
    
    choice = input("\nEnter your choice (1-3): ").strip()
    
    if choice == "1":
        setup_environment_variables()
    elif choice == "2":
        setup_config_file()
    elif choice == "3":
        print("✅ Skipping API key configuration. App will use heuristic analysis.")
    else:
        print("❌ Invalid choice. Exiting.")
        sys.exit(1)
    
    print("\n🎉 Configuration complete!")
    print("\nTo run the application:")
    print("  streamlit run app.py")


def setup_environment_variables():
    """Guide user through environment variable setup."""
    print("\n🌍 Environment Variable Setup:")
    print("Add these to your shell profile (~/.bashrc, ~/.zshrc, etc.):")
    print()
    
    # OpenAI setup
    openai_key = input("Enter your OpenAI API key (or press Enter to skip): ").strip()
    if openai_key:
        print(f"\nexport OPENAI_API_KEY='{openai_key}'")
    
    # Gemini setup
    gemini_key = input("Enter your Google API key (or press Enter to skip): ").strip()
    if gemini_key:
        print(f"\nexport GOOGLE_API_KEY='{gemini_key}'")
    
    print("\n📝 Instructions:")
    print("1. Copy the export commands above")
    print("2. Add them to your shell profile file")
    print("3. Restart your terminal or run: source ~/.bashrc")
    print("4. The application will automatically detect these keys")


def setup_config_file():
    """Guide user through config file setup."""
    print("\n📁 Config File Setup:")
    
    # OpenAI setup
    openai_key = input("Enter your OpenAI API key (or press Enter to skip): ").strip()
    if openai_key:
        config = get_global_config()
        config.set_api_key("openai", openai_key, save=True)
        print("✅ OpenAI API key saved to config file")
    
    # Gemini setup
    gemini_key = input("Enter your Google API key (or press Enter to skip): ").strip()
    if gemini_key:
        config = get_global_config()
        config.set_api_key("gemini", gemini_key, save=True)
        print("✅ Google API key saved to config file")
    
    print("\n🔒 Security Note:")
    print("The config file has been created with restricted permissions (600)")
    print("Only you can read/write the file. Keep your API keys secure!")


def show_api_key_instructions():
    """Show instructions for obtaining API keys."""
    print("\n📖 How to Get API Keys:")
    print()
    print("🔑 OpenAI API Key:")
    print("1. Visit: https://platform.openai.com/api-keys")
    print("2. Sign in or create an account")
    print("3. Click 'Create new secret key'")
    print("4. Copy the key (starts with 'sk-')")
    print()
    print("🔑 Google API Key (for Gemini):")
    print("1. Visit: https://makersuite.google.com/app/apikey")
    print("2. Sign in with your Google account")
    print("3. Click 'Create API Key'")
    print("4. Copy the key")
    print()
    print("💡 Note: Both services offer free tiers for testing!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Setup cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        sys.exit(1)
