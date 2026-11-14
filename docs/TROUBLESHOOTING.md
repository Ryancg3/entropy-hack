# Troubleshooting

Setup and tooling problems we've hit, and how we fixed them. Check here first; add a new entry when you solve something that isn't listed.

## Template

```markdown
### <the symptom, as you saw it>

- **Cause:** <why it happens>
- **Fix:** <what to run or change>
- **Seen by:** <name>, YYYY-MM-DD
```

## Entries

### "Nebius rejected your key", or a 502 with `HTTP 401 from upstream` / `unauthenticated`

- **Cause:** the key is wrong, revoked or out of credit. The server wraps Nebius's 401 in a 502, so the raw error looks like a server fault.
- **Fix:** copy the key again from Nebius Token Factory → API keys, delete `.env` and run `python3 check_connection.py`.
- **Seen by:** Oscar, 2026-11-14

### `ModuleNotFoundError: No module named 'requests'` (or `dotenv`)

- **Cause:** the chat client needs `requests` and `python-dotenv`, and your Python doesn't have them.
- **Fix:** `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`, then run scripts with `.venv/bin/python`. `check_connection.py` needs no packages, so it still works.
- **Seen by:** Oscar, 2026-11-14

### `KeyError: 'API_URL'` / "Run setup first" in a git worktree or fresh clone

- **Cause:** `.env` is git-ignored, so new clones and worktrees don't have it.
- **Fix:** run `python3 check_connection.py` to create it, or link an existing one: `ln -s /path/to/main/checkout/.env .env`.
- **Seen by:** Oscar, 2026-11-14

### The models in `chat.py` don't match the event deck

- **Cause:** the deck lists Gemma 3 27B and DeepSeek V4 Pro (Claude models later). The server currently offers Qwen3-30B, gpt-oss-120b, Qwen3-235B and DeepSeek-V4-Pro.
- **Fix:** trust the server. `python3 check_connection.py` prints the live list, and `btm.list_models()` returns it.
- **Seen by:** Oscar, 2026-11-14
