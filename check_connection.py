"""Check that your Nebius key works with the Break the Model server.

    python3 check_connection.py          # test the smallest model
    python3 check_connection.py --all    # test every model

Uses only the Python standard library, so nothing needs installing.
Reads NEBIUS_API_KEY from .env (or the environment). If there is none, it asks
for the key and offers to save it to .env. The key is never printed.
"""
import getpass
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_API_URL = "https://2-31-186-181.sslip.io"
ENV_FILE = Path(__file__).parent / ".env"
TEST_MESSAGE = "Hi! What are your visiting hours?"


def read_env():
    values = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                values[k.strip()] = v.strip()
    for k in ("YOUR_NAME", "NEBIUS_API_KEY", "API_URL"):
        if os.environ.get(k):
            values[k] = os.environ[k]
    return values


def request(url, body=None, key=None, timeout=120):
    headers = {"Content-Type": "application/json"}
    if key:
        headers["X-Nebius-Key"] = key
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")[:300]


def main():
    env = read_env()
    api = env.get("API_URL", DEFAULT_API_URL).rstrip("/")
    name = env.get("YOUR_NAME", "")
    key = env.get("NEBIUS_API_KEY", "")

    if not key or key == "paste-your-nebius-key-here":
        name = input("Your name: ").strip() or "anonymous"
        key = getpass.getpass("Your Nebius API key (stays hidden): ").strip()
        if not key:
            sys.exit("No key entered. Get one at Nebius Token Factory -> API keys -> Create.")
        if input("Save it to .env for next time? [Y/n]: ").strip().lower() in ("", "y", "yes"):
            ENV_FILE.write_text(f"YOUR_NAME={name}\nNEBIUS_API_KEY={key}\nAPI_URL={api}\n")
            print(f"Saved to {ENV_FILE.name} (git-ignored).")
    else:
        source = "the NEBIUS_API_KEY variable" if os.environ.get("NEBIUS_API_KEY") else ENV_FILE.name
        print(f"Using the key from {source}.")

    print(f"\n1. Reaching the server at {api} ...")
    try:
        status, data = request(f"{api}/models", timeout=30)
    except Exception as e:  # noqa: BLE001
        sys.exit(f"   ❌ Could not reach the server ({e}). Check your internet connection.")
    if status != 200:
        sys.exit(f"   ❌ Server answered {status}: {data}")
    models = [(m["id"], m.get("tier", "")) for m in data["models"]]
    print(f"   ✅ Server is up. {len(models)} models available.")

    if "--all" not in sys.argv:
        # Smallest model only: cheapest way to prove the key works.
        models = [m for m in models if m[1] == "small"] or models[-1:]

    print("\n2. Sending a test message with your key ...")
    failures = 0
    for model, tier in models:
        body = {"participant": name, "model": model,
                "conversation_id": "connection-check", "message": TEST_MESSAGE}
        try:
            status, data = request(f"{api}/chat", body=body, key=key)
        except Exception as e:  # noqa: BLE001
            status, data = None, str(e)
        label = f"{model} ({tier})" if tier else model
        if status == 200:
            print(f"   ✅ {label}\n      Riley: {data.get('reply', '')[:120]!r}\n"
                  f"      turn_id: {data.get('turn_id')}")
        else:
            failures += 1
            text = str(data)
            if status == 401 or "401" in text or "authenticat" in text.lower():
                print(f"   ❌ {label}: Nebius rejected your key. Copy it again from Nebius Token Factory\n"
                      f"      and put it in .env (or delete .env and run this script again).")
            else:
                print(f"   ❌ {label}: {status} {text[:300]}")

    print("\nAll good. Start attacking with: python3 chat.py" if not failures
          else f"\n{failures} model(s) failed. Ask an organizer if it keeps happening.")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
