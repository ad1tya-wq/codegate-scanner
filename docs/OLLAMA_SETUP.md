# CodeGate — Corpus Generation Setup (Host Machine)

**You are generating a dataset of AI-written Python code for a security
research project.** Four open-source LLMs each receive the same set of
coding prompts, and we collect what they write. Later analysis — on a
different machine — checks which snippets contain security bugs.

Everything runs **locally on your machine**. No network setup, no firewall
rules, no shared Wi-Fi, no account, no API key. When it's done you send
back **one file**.

**Your time: ~20 minutes of setup, then it runs unattended for 2–5 hours.**

> **Safety note:** this generates code but **never runs it**. The
> `--generate-only` flag guarantees that. The part of the pipeline that
> executes generated code stays on the research machine, deliberately.

---

## Contents

- [Part A — Install](#part-a--install) (4 things to install)
- [Part B — Setup](#part-b--setup) (configure and test)
- [Part C — Run](#part-c--run)
- [Part D — Send the results back](#part-d--send-the-results-back)
- [Troubleshooting](#troubleshooting)

## What you need

| | |
|---|---|
| Disk | ~20 GB free (16 GB models + working space) |
| RAM | 8 GB minimum for 7B models — see A2 if you have less |
| OS | Windows, macOS, or Linux |

---

# PART A — INSTALL

Four things: Ollama, the models, Python, and the project. Verify each
before moving on.

## A1 · Install Ollama

Download and install from **https://ollama.com/download**

Open a terminal — **PowerShell** on Windows, **Terminal** on macOS/Linux —
and verify:

```bash
ollama --version
```

✅ **Expected:** a version number, e.g. `ollama version 0.5.x`

❌ *"command not found"* → close and reopen the terminal so the installer's
PATH change takes effect. Still failing? Reinstall and reboot.

## A2 · Download the four models

Each is ~4 GB. This is the slowest step — start it and go do something else.

```bash
ollama pull qwen2.5-coder:7b
ollama pull deepseek-coder:6.7b
ollama pull codellama:7b
ollama pull starcoder2:7b
```

> ### 💡 Under 8 GB RAM, or want this to finish much faster?
>
> Use the small variants instead:
>
> ```bash
> ollama pull qwen2.5-coder:1.5b
> ollama pull deepseek-coder:1.3b
> ollama pull starcoder2:3b
> ollama pull codellama:7b
> ```
>
> This is completely fine — arguably **better** for this project. Smaller
> models write more varied and more insecure code, which is exactly the
> signal we're measuring. **Just tell us which you pulled** so we can match
> the config in step B1.

Verify:

```bash
ollama list
```

✅ **Expected:** all four models listed, with their exact `:tag` suffixes.
**Keep this output** — you'll need the exact names in B1.

## A3 · Install Python

First check whether you already have it:

```bash
python --version
```

✅ **3.11 or newer** → skip to A4.

Otherwise install from **https://www.python.org/downloads/**

> ⚠️ **Windows:** on the first installer screen, tick
> **"Add python.exe to PATH"** before clicking Install. Missing this causes
> most Windows setup problems.

Verify (reopen your terminal first):

```bash
python --version
pip --version
```

✅ **Expected:** both report versions, Python ≥ 3.11.

*macOS/Linux note:* if `python` isn't found but `python3` is, use `python3`
and `pip3` throughout this guide.

## A4 · Get the project

**First, repo access.** The repository is private, so you need to be added
as a collaborator. Send your GitHub username to the project owner — you'll
get an email invite that you must accept before cloning.

**Install git** if you don't have it (`git --version` to check) from
**https://git-scm.com/downloads**.

Then clone and install:

```bash
git clone https://github.com/ad1tya-wq/codegate-scanner.git
cd codegate-scanner
pip install -e .
```

✅ **Expected:** clone succeeds, then `pip` ends with
`Successfully installed codegate-0.2.0`

❌ *"repository not found"* → the collaborator invite isn't accepted yet.
Check your email (and GitHub notifications), accept, retry.

❌ *`pip` not found* → use `python -m pip install -e .` instead.

**Verify the whole install:**

```bash
python -c "import codegate; print('CodeGate', codegate.__version__)"
```

✅ **Expected:** `CodeGate 0.2.0`

> ### No git? (alternative)
> Download the ZIP from the repo's green **Code** button → *Download ZIP*,
> extract it, then `cd` into the extracted folder and run `pip install -e .`.
> You'll use the file-transfer method in Part D rather than git push.

---

# PART B — SETUP

## B1 · Match the config to your models

**Skip this entirely if you pulled the four models exactly as listed in A2.**

If you used the small variants, open **`config.yaml`** in the project
folder with any text editor (Notepad, TextEdit, VS Code) and find:

```yaml
generators:
  - qwen2.5-coder:7b
  - deepseek-coder:6.7b
  - codellama:7b
  - starcoder2:7b
```

Replace those four lines with exactly what `ollama list` showed you:

```yaml
generators:
  - qwen2.5-coder:1.5b
  - deepseek-coder:1.3b
  - codellama:7b
  - starcoder2:3b
```

> Names must match `ollama list` **character for character**, including the
> `:tag`. Keep the two-space indentation and the `- ` prefix. Change nothing
> else in the file.

## B2 · Smoke test (2 minutes)

Never start a multi-hour run without testing the small case:

```bash
python scripts/run_real.py --generate-only --limit 5 --out-dir data/runs/smoke
```

✅ **Expected output:**

```
[preflight] Ollama reachable at http://localhost:11434; all 4 models present
Loaded 5 prompts across 3 CWEs
Generators: ['qwen2.5-coder:7b', 'deepseek-coder:6.7b', ...]
Planned samples: 20  (resumable -- safe to interrupt and rerun)

=== GENERATION COMPLETE ===
Samples generated : 20
```

If you see `GENERATION COMPLETE`, everything works. Otherwise jump to
[Troubleshooting](#troubleshooting) — the error messages name the exact
problem and step.

## B3 · Stop the machine sleeping

The full run takes hours; sleeping pauses it.

- **Windows:** Settings → System → Power & battery → Screen and sleep →
  *"When plugged in, put my device to sleep after"* → **Never**
- **macOS:** System Settings → Displays → Advanced → enable *"Prevent
  automatic sleeping on power adapter when the display is off"*
- **Linux:** Settings → Power → Automatic Suspend → **Off** (plugged in)

Keep it on power.

---

# PART C — RUN

```bash
python scripts/run_real.py --generate-only --out-dir data/runs/real_540
```

Generates **540 samples** (135 prompts × 4 models). Expect **2–5 hours** on
CPU, much faster on GPU. Leave the terminal open.

> ### ✅ Interruptions are safe
> Close the lid, lose power, hit Ctrl+C, Wi-Fi drops — doesn't matter. Run
> the **exact same command** again and it resumes from where it stopped.
> Finished work is never redone. You'll see
> `[resume] N sample(s) already complete` on restart.

### Optional — run in the background

**macOS / Linux**
```bash
mkdir -p logs
nohup python scripts/run_real.py --generate-only --out-dir data/runs/real_540 > logs/gen.log 2>&1 &
tail -f logs/gen.log        # watch; Ctrl+C stops watching, not the run
```

**Windows PowerShell**
```powershell
mkdir logs -Force
Start-Process python -ArgumentList "scripts/run_real.py","--generate-only","--out-dir","data/runs/real_540" -RedirectStandardOutput logs/gen.log -NoNewWindow
Get-Content logs/gen.log -Wait
```

### When it finishes

```
=== GENERATION COMPLETE ===
Samples generated : 540
Generators        : ['codellama:7b', 'deepseek-coder:6.7b', ...]
Unique snippets   : 500+
Send this ONE file back:
  C:\...\codegate-scanner\data\runs\real_540\generations.parquet
```

That path is the only thing we need. On to Part D.

---

# PART D — SEND THE RESULTS BACK

**The file:** `data/runs/real_540/generations.parquet` (a few MB).

Pick **one** method.

## Method 1 — Push to a git branch (preferred)

Keeps everything versioned and needs no third-party service.

```bash
git checkout -b corpus/real-540

git add -f data/runs/real_540/generations.parquet

git -c user.name="YOUR NAME" -c user.email="your@email.com" \
    commit -m "data: 540-sample real corpus from local Ollama run"

git push -u origin corpus/real-540
```

> ⚠️ The `-f` in `git add -f` is **required**. `.parquet` files are
> normally gitignored; this one is a deliberate exception. Without `-f` git
> silently ignores the file and you'd push an empty commit.

✅ **Expected:** `branch 'corpus/real-540' set up to track...`
Then message us — we'll pull the branch. **Done.**

❌ *`Permission denied` / `403`* → your collaborator access is read-only.
Ask for write access, or use Method 2.

❌ *asks for a password* → GitHub needs a Personal Access Token, not your
password. Easiest fix is Method 2 instead.

## Method 2 — File transfer

Equally fine. Send the file via **Google Drive, WeTransfer, Dropbox,
Discord, or email** (it's only a few MB).

**Finding the file:**
- **Windows:** in the project folder, open `data\runs\real_540\` —
  or paste `explorer data\runs\real_540` into PowerShell
- **macOS:** `open data/runs/real_540`
- **Linux:** `xdg-open data/runs/real_540`

Attach **`generations.parquet`**. Nothing else.

## Method 3 — Zip everything (if something went wrong)

If the run was messy or partly failed, send the whole run folder including
the checkpoint, so we can recover partial work:

```bash
# macOS / Linux
zip -r codegate-corpus.zip data/runs/real_540/

# Windows PowerShell
Compress-Archive -Path data/runs/real_540 -DestinationPath codegate-corpus.zip
```

Send `codegate-corpus.zip`.

## After sending

Nothing further is needed from you. To reclaim ~16 GB of disk:

```bash
ollama rm qwen2.5-coder:7b
ollama rm deepseek-coder:6.7b
ollama rm codellama:7b
ollama rm starcoder2:7b
```

You can also revert the sleep setting from B3, and delete the project
folder. Thank you — this is the part of the project that can't be
automated away.

---

# Troubleshooting

**`could not connect to Ollama at http://localhost:11434`**

Ollama isn't running. Windows/macOS: launch it from the Start menu /
Applications (it runs as a background app). Linux:
`sudo systemctl start ollama`. Confirm with `ollama list`.

**`Ollama at ... is missing model(s): [...]`**

`config.yaml` doesn't match your models. Run `ollama list` and redo B1 so
the names match exactly, tags included.

**`ERROR: every generation failed -- nothing was produced.`**

Ollama stopped partway. Restart it, rerun the same command — completed
samples are preserved and it resumes.

**`pip install -e .` fails**

Check `python --version` is 3.11+. Try `python -m pip install -e .`. On
Windows, if Python isn't recognised at all, reinstall it with *"Add
python.exe to PATH"* ticked (A3).

**`repository not found` when cloning**

The collaborator invite hasn't been accepted. Check email/GitHub
notifications, accept, retry.

**Far slower than expected**

Normal on CPU: ~10–30 seconds per sample. If the total is impractical:
- switch to the small models in A2's note (several times faster), or
- run in chunks: `--limit 40` now, full command later — it resumes, so
  nothing is wasted.

**Anything else**

Send us the last ~30 lines of terminal output. The run is resumable, so
nothing is lost while we sort it out.

---

## What this is actually doing, if you're curious

Each model gets the same 135 coding tasks — things like *"write a function
that looks up a user in a database."* Some are phrased to invite an
insecure implementation, some ask for a safe one, and some are deliberate
near-misses that *look* risky but aren't.

Giving identical prompts to different models lets us measure how their
security failure patterns differ — and whether a safety guarantee
calibrated on one model still holds when a team switches to another. Your
machine does the writing; the analysis happens elsewhere.
