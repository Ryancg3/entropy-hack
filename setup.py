"""Run once:  python3 setup.py   (asks for your name + API key, then tests the connection)"""
import getpass, subprocess, sys
from pathlib import Path

API_URL = "https://2-31-186-181.sslip.io"

print("\n=== Break the Model: setup ===\n")
try:
    import requests, dotenv  # noqa: F401
except ImportError:
    print("Installing requirements...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-q", "requests", "python-dotenv"], check=False)
    import requests

name = input("Your name: ").strip() or "anonymous"
key = getpass.getpass("Your API key, Groq or Nebius (paste it; it stays hidden): ").strip()
if not key:
    sys.exit("No key entered. Get a free one at console.groq.com -> API Keys, then run this again.")

provider = "groq" if key.startswith("gsk_") else "nebius"
test_model = "groq/llama-3.1-8b-instant" if provider == "groq" else "Qwen/Qwen3-30B-A3B-Instruct-2507"
Path(".env").write_text(f"YOUR_NAME={name}\nAPI_KEY={key}\nAPI_URL={API_URL}\n")
print(f"\nSaved ({'Groq' if provider == 'groq' else 'Nebius'} key). Testing the connection...")

import requests  # noqa: E402
try:
    r = requests.post(f"{API_URL}/chat", headers={"X-API-Key": key}, timeout=120, json={
        "participant": name, "model": test_model,
        "conversation_id": "setup-test", "message": "Hi! What are your visiting hours?"})
    data = r.json()
except Exception as e:  # noqa: BLE001
    sys.exit(f"\n❌ Could not reach the server ({e}). Check your internet, then run: python3 setup.py")

if r.status_code == 200:
    print(f"\n✅ It works! Riley says: {data['reply'][:200]}\n")
    print("Now start attacking:  python3 chat.py\n")
elif r.status_code == 429:
    print("\n✅ Your key works, but its rate limit is busy. Wait a minute, then run: python3 chat.py\n")
elif "401" in str(data) or "key" in str(data).lower():
    sys.exit("\n❌ Your key was rejected. Copy it again and run: python3 setup.py")
else:
    sys.exit(f"\n❌ Error {r.status_code}: {data}\nAsk an organizer for help.")
