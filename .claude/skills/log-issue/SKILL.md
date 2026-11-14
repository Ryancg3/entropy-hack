---
name: log-issue
description: Record a setup, tooling or server problem and its fix in docs/TROUBLESHOOTING.md. Use when someone says "log this issue" or "document this problem", or right after solving an error that isn't already listed there (install errors, key or .env problems, server errors, script bugs).
---

# Log an issue

Add an entry to `docs/TROUBLESHOOTING.md` using the template at the top of that file.

## Steps

1. Search `docs/TROUBLESHOOTING.md` for the symptom first. If it's there, add to that entry (a new cause, a better fix, another "Seen by") instead of duplicating it.
2. Write the heading as the symptom the person actually saw: the error text or what went wrong. That's what the next person will search for.
3. Fill in:
   - **Cause:** why it happens, if known. Write "unknown" rather than guessing.
   - **Fix:** the exact commands or changes that solved it. If it isn't solved yet, write "open" and what has been tried.
   - **Seen by:** name (from `git config user.name` if not given) and today's date.
4. If the fix needs a code change (for example in `check_connection.py` or `btm.py`), say so in the entry and offer to make the change.

## Never

Paste API keys, `.env` contents, Entropy's org ID or event passwords into the file, even inside an error message. Replace them with `<redacted>`.

## After

Show the person the entry. Offer to commit it (`docs: troubleshoot <symptom>`), but only commit if they say yes.
