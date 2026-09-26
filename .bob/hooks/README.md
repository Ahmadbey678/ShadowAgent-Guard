# ShadowAgent Guard — pre-trust hook

`pretrust.py` is a Bob lifecycle hook that scans any workspace for hostile
agent configuration **before** Bob works in it.

---

## How it works

| Event | Behaviour |
|---|---|
| `SessionStart` | Runs the `guard config` check against the workspace. Prints a short PASS/BLOCK summary to stdout (added to model context). Never blocks (exit 0 always). |
| `UserPromptSubmit` | If the last scan returned BLOCK and the session has not been acknowledged, writes a reason to stderr and exits 2 (Bob blocks the prompt). If the prompt contains the acknowledgement text, creates a marker and exits 0. |

### Caching

Scan results are cached for 10 minutes, keyed by workspace path + HEAD SHA,
under `%TEMP%\shadowagent-pretrust\cache\`.

### Acknowledgement markers

Markers live at `%TEMP%\shadowagent-pretrust\ack_<session_id>.marker`.
They are **never** written inside the scanned workspace.

### Security invariants

- The subprocess `cwd` is always the ShadowAgent Guard root, never the workspace.
- Evidence text, decoded payloads, and secret values are **never** printed.
- Only `rule_id`, file path, severity, grade, and counts appear in output.

---

## Workspace registration (dogfooding — already active)

`ShadowAgent-Guard/.bob/settings.json` registers the hook for this repo.
Workspace hooks only run in **trusted** folders, so this is safe for
dogfooding: a hostile repository cannot reach this hook via workspace config.

---

## ⚠️  GLOBAL registration — required for protection on hostile repos

> **Workspace hooks only run in trusted folders.**
> A hostile repository could ship its own `.bob/settings.json` with a
> completely different hook (or no hook at all), bypassing this protection
> entirely. Global hooks always run, regardless of workspace trust, so
> global registration is the **only** way to gate untrusted repos.

Paste this block into `%USERPROFILE%\.bob\settings.json`
(create the file if it does not exist):

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python C:\\Users\\ahmad\\Documents\\Projects\\ShadowAgent-Guard\\.bob\\hooks\\pretrust.py",
            "timeout": 90
          }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python C:\\Users\\ahmad\\Documents\\Projects\\ShadowAgent-Guard\\.bob\\hooks\\pretrust.py",
            "timeout": 90
          }
        ]
      }
    ]
  }
}
```

If `%USERPROFILE%\.bob\settings.json` already has a `hooks` section, merge
the two `SessionStart` and `UserPromptSubmit` arrays into the existing ones
rather than replacing the whole file.

---

## Stdin payload reference

Bob sends one JSON object per event on stdin:

**SessionStart**
```json
{
  "session_id": "task-abc123",
  "cwd": "C:\\path\\to\\workspace",
  "hook_event_name": "SessionStart",
  "source": "startup"
}
```

**UserPromptSubmit**
```json
{
  "session_id": "task-abc123",
  "cwd": "C:\\path\\to\\workspace",
  "hook_event_name": "UserPromptSubmit",
  "prompt": "the user's prompt text"
}
```

---

## Exit-code rules

| Event | Exit 0 | Exit 2 |
|---|---|---|
| `SessionStart` | Always. Output goes to model context. | Not meaningful (ignored by Bob). |
| `UserPromptSubmit` | Prompt proceeds normally. | Bob blocks the prompt; stderr is shown as the reason. |

---

## Manual test

```powershell
# SessionStart — BLOCK expected on ai-pr branch
$json = '{"session_id":"test-1","cwd":"C:\\Users\\ahmad\\Documents\\Projects\\shadowagent-demo-target","hook_event_name":"SessionStart","source":"startup"}'
$json | python C:\Users\ahmad\Documents\Projects\ShadowAgent-Guard\.bob\hooks\pretrust.py

# UserPromptSubmit — blocked (exit 2)
$json = '{"session_id":"test-1","cwd":"C:\\Users\\ahmad\\Documents\\Projects\\shadowagent-demo-target","hook_event_name":"UserPromptSubmit","prompt":"do something"}'
$json | python C:\Users\ahmad\Documents\Projects\ShadowAgent-Guard\.bob\hooks\pretrust.py; echo "exit: $LASTEXITCODE"

# UserPromptSubmit — acknowledged (exit 0)
$json = '{"session_id":"test-1","cwd":"C:\\Users\\ahmad\\Documents\\Projects\\shadowagent-demo-target","hook_event_name":"UserPromptSubmit","prompt":"I acknowledge ShadowAgent Guard findings"}'
$json | python C:\Users\ahmad\Documents\Projects\ShadowAgent-Guard\.bob\hooks\pretrust.py; echo "exit: $LASTEXITCODE"
```
