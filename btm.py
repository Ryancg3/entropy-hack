"""Break the Model — tiny client. Every call is also saved to logs/my_attempts.jsonl."""
import json, os, time, uuid
from pathlib import Path
import requests
from dotenv import load_dotenv

load_dotenv()
API = os.environ["API_URL"].rstrip("/")
NAME = os.environ.get("YOUR_NAME", "")
KEY = os.environ.get("API_KEY") or os.environ["NEBIUS_API_KEY"]
PROVIDER = "groq" if KEY.startswith("gsk_") else "nebius"
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
# Deck targets; the server will serve them later (through Entropy's org ID).
CLAUDE_MODELS = [("claude-haiku-5-5", "Claude Haiku 5.5"), ("claude-sonnet-5-5", "Claude Sonnet 5.5")]
LOG = Path(__file__).parent / "logs" / "my_attempts.jsonl"
LOG.parent.mkdir(exist_ok=True)
LAST_TURN_ID = None

ORDER = {"small": 0, "medium": 1, "large": 2, "very large": 3}


def list_models():
    """Models that work with YOUR key, weakest first: [(model_id, size), ...]"""
    ms = requests.get(f"{API}/models", timeout=30).json()["models"]
    mine = [m for m in ms if m.get("provider") == PROVIDER]
    mine.sort(key=lambda m: ORDER.get(m.get("tier"), 9))
    out = [(m["id"], m.get("tier", "")) for m in mine]
    served = [m for m in ms if "claude" in m["id"].lower()]
    if served:  # use the server's own ids once it serves Claude
        out += [(m["id"], m.get("tier", "Claude")) for m in served]
    else:
        out += [(mid, f"{label}, not served yet") for mid, label in CLAUDE_MODELS]
    return out


def is_claude(model):
    return "claude" in model.lower()


def set_anthropic_key(key, save=True):
    """Use this Anthropic key for Claude models; optionally append it to .env."""
    global ANTHROPIC_KEY
    ANTHROPIC_KEY = key
    if save:
        with (Path(__file__).parent / ".env").open("a") as f:
            f.write(f"\nANTHROPIC_API_KEY={key}\n")


def key_for(model):
    """Anthropic key for Claude models, otherwise the Groq/Nebius key."""
    return ANTHROPIC_KEY if ANTHROPIC_KEY and is_claude(model) else KEY


def new_conversation():
    return "conv_" + uuid.uuid4().hex[:12]


def chat_raw(message, model, conversation_id=None):
    """Send one message and return (http_status, full_response_dict) without raising.

    Every call is logged to logs/my_attempts.jsonl, like chat(). Used by recon.py,
    which needs every response field (tool_calls with args, turn_id, ...), not just the reply.
    """
    body = {"participant": NAME, "model": model,
            "conversation_id": conversation_id or new_conversation(), "message": message}
    r = requests.post(f"{API}/chat", json=body, headers={"X-API-Key": key_for(model)}, timeout=300)
    try:
        data = r.json()
    except ValueError:
        data = {"error": "non-JSON response", "text": r.text[:500]}
    with LOG.open("a") as f:
        f.write(json.dumps({"ts": time.strftime("%H:%M:%S"), "request": body, "response": data}) + "\n")
    return r.status_code, data


def chat(message, model, conversation_id=None):
    """Send one message. Reuse the same conversation_id to keep talking in one conversation."""
    global LAST_TURN_ID
    status, data = chat_raw(message, model, conversation_id)
    if status != 200:
        err = data.get("error")
        raise RuntimeError(err.get("message") if isinstance(err, dict) else err)
    for tc in data.get("tool_calls") or []:
        print(f"  [Riley used tool: {tc['name']}]")
    LAST_TURN_ID = data["turn_id"]
    return data["reply"]
