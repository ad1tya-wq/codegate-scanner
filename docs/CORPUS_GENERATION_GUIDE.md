# CodeGate — Corpus Generation Guide (v2)

**You are generating a dataset of AI-written Python code for a security
research project.** Four open-source LLMs each receive the same set of
coding prompts, and we collect what they write. Later analysis — on a
different machine — checks which snippets contain security bugs.

Everything runs **locally on your machine**. No network setup, no firewall
rules, no shared Wi-Fi, no account, no API key. When it's done you send
back **one file**.

> **Safety note:** this generates code but **never runs it**. The
> `--generate-only` flag guarantees that. The part of the pipeline that
> executes generated code stays on the research machine, deliberately.

---

## What changed since last time (worth 60 seconds)

The first run worked. It produced 516 real samples and it found three real
bugs in our labelling code that we could never have found any other way.

What it *couldn't* do was produce the certified threshold the whole project
depends on. We assumed that was because the dataset was too small. It
wasn't. When we went back and measured, our labelling code was calling the
generated functions with the **wrong number of arguments** — it always
passed exactly two for SQL prompts and exactly one for command prompts. Any
function with a different signature crashed, got recorded as "unjudgeable,"
and was thrown away. That silently discarded about 44% of everything you
generated, and it hit the vulnerable examples hardest — which are the only
ones the statistics actually need.

So: **nothing you did was wrong, and none of your work was wasted.** Our
labeller was. It's fixed. This run is bigger and the prompts are more
varied, but it's the same command and the same resume behaviour you already
know.

One thing does change on your side: **one of the four models is being
swapped** (details in A2).

---

## Contents

- [What you need](#what-you-need)
- [Part A — Install](#part-a--install)
- [Part B — Configure](#part-b--configure)
- [Part C — Pilot run (do not skip)](#part-c--pilot-run-do-not-skip)
- [Part D — The full run](#part-d--the-full-run)
- [Part E — Send the results back](#part-e--send-the-results-back)
- [Troubleshooting](#troubleshooting)
- [What this is actually doing](#what-this-is-actually-doing-if-youre-curious)

---

## What you need

| | |
|---|---|
| Disk | ~20 GB free (16 GB models + working space) |
| RAM | 8 GB minimum for 7B models — see A2 if you have less |
| OS | Windows, macOS, or Linux |
| Time | ~20 min setup · ~1 h pilot · then 6–18 h unattended, resumable |

**You can start Part A right now.** The model downloads take a while and
nothing else depends on them.

---

# PART A — INSTALL

Four things: Ollama, the models, Python, and the project. Verify each before
moving on.

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
ollama pull codegemma:7b-instruct
```

> ### ⚠️ The fourth model changed — `starcoder2:7b` is out
>
> `starcoder2` is a **base completion** model, not an instruction-tuned
> one. In the last run it produced **zero** vulnerable samples across 163
> attempts — it doesn't follow "write this the insecure way" the way the
> other three do, so it contributed volume but no usable signal.
>
> We still need four **distinct model families** (the headline experiment
> tests whether a guarantee calibrated on three models still holds on a
> fourth it has never seen), so this is a swap, not a removal.
>
> If `codegemma:7b-instruct` isn't available on your Ollama version, try
> these in order and **tell us which one worked** — it goes in the config
> and gets named in the final report:
>
> ```bash
> ollama pull granite-code:8b        # 2nd choice
> ollama pull mistral:7b-instruct    # 3rd choice
> ```

> ### 💡 Under 8 GB RAM, or want this to finish much faster?
>
> Use the small variants instead:
>
> ```bash
> ollama pull qwen2.5-coder:1.5b
> ollama pull deepseek-coder:1.3b
> ollama pull codellama:7b
> ollama pull codegemma:2b
> ```
>
> This is completely fine — arguably **better** for this project. Smaller
> models write more varied and more insecure code, which is exactly the
> signal we're measuring. **Just tell us which you pulled** so we can match
> the config in B2.

Verify:

```bash
ollama list
```

✅ **Expected:** all four models listed, with their exact `:tag` suffixes.
**Keep this output** — you'll need the exact names in B2.

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

Then clone, switch to the working branch, and install:

```bash
git clone https://github.com/ad1tya-wq/codegate-scanner.git
cd codegate-scanner
git checkout feat/certificate-restoration
pip install -e .
```

> **Note the `git checkout`.** All of the current work lives on the
> `feat/certificate-restoration` branch, not `main`. If you skip this
> you'll generate against the old prompt set.

✅ **Expected:** clone succeeds, branch switches, then `pip` ends with
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
> Download the ZIP from the repo's green **Code** button — **switch the
> branch dropdown to `feat/certificate-restoration` first** — then extract
> it, `cd` into the extracted folder, and run `pip install -e .`. You'll
> use the file-transfer method in Part E rather than git push.

---

# PART B — CONFIGURE

## B1 · Get the latest changes

Do this immediately before the pilot, and again before the full run. We are
actively pushing prompt updates to this branch.

```bash
git pull
pip install -e .
```

## B2 · Match the config to your models

**Skip this entirely if you pulled the four models exactly as listed in A2.**

If you used different variants, open **`config.yaml`** in the project folder
with any text editor (Notepad, TextEdit, VS Code) and find:

```yaml
generators:
  - qwen2.5-coder:7b
  - deepseek-coder:6.7b
  - codellama:7b
  - codegemma:7b-instruct
```

Replace those four lines with exactly what `ollama list` showed you:

```yaml
generators:
  - qwen2.5-coder:1.5b
  - deepseek-coder:1.3b
  - codellama:7b
  - codegemma:2b
```

> Names must match `ollama list` **character for character**, including the
> `:tag`. Keep the two-space indentation and the `- ` prefix. Change nothing
> else in the file.

## B3 · Stop the machine sleeping

The full run takes hours; sleeping pauses it.

- **Windows:** Settings → System → Power & battery → Screen and sleep →
  *"When plugged in, put my device to sleep after"* → **Never**
- **macOS:** System Settings → Displays → Advanced → enable *"Prevent
  automatic sleeping on power adapter when the display is off"*
- **Linux:** Settings → Power → Automatic Suspend → **Off** (plugged in)

Keep it on power.

---

# PART C — PILOT RUN (DO NOT SKIP)

**This step did not exist last time, and skipping it is what cost us the
last run.** One hour now protects two nights.

The pilot generates a small, representative slice — a few task groups from
each of the three vulnerability types — so we can label it on our side and
check that the fixed oracles actually produce usable results **before** you
commit your machine to an overnight run.

```bash
python scripts/run_real.py --generate-only --pilot-per-cwe 3 --out-dir data/runs/pilot
```

✅ **Expected output:**

```
[preflight] Ollama reachable at http://localhost:11434; all 4 models present
[pilot] 3 task group(s) per CWE
Loaded 27 prompts across 3 CWEs
Generators: ['qwen2.5-coder:7b', 'deepseek-coder:6.7b', ...]
Planned samples: 108  (resumable -- safe to interrupt and rerun)

=== GENERATION COMPLETE ===
Samples generated : 108
```

**Roughly 30–60 minutes.**

### ⛔ Then stop and wait

Send us `data/runs/pilot/generations.parquet` (see [Part E](#part-e--send-the-results-back)
for how) and **wait for our go-ahead** before starting Part D.

We label it in about two minutes and check the yield. If something's off,
we fix the prompts, push, and you re-pilot — an hour lost instead of two
nights. If it looks good we'll tell you to go, and you move straight to
Part D on the same machine with everything already set up.

---

# PART D — THE FULL RUN

**Only start this after we've confirmed the pilot looks good.**

```bash
git pull
python scripts/run_real.py --generate-only --out-dir data/runs/real_2160
```

Check the `Planned samples:` line before you walk away:

✅ **Expected:** `Planned samples: 2160`

❌ If it says **540**, you're on the old prompt set — run `git pull` again
and confirm you're on the `feat/certificate-restoration` branch
(`git branch --show-current`).

**Expect 6–18 hours** depending on your hardware, so plan on **two overnight
sessions**. Leave the terminal open.

> ### ✅ Interruptions are safe
> Close the lid, lose power, hit Ctrl+C, Wi-Fi drops — doesn't matter. Run
> the **exact same command** again and it resumes from where it stopped.
> Finished work is never redone. You'll see
> `[resume] N sample(s) already complete` on restart.

> ### 📤 Send the file after *each* session, not just at the end
> This is new, and it matters. `generations.parquet` is valid and readable
> at any point, so send us whatever you have at the end of each night. That
> way a dead laptop or a corrupted disk can never strand the whole run on
> one machine. We can merge partial files on our side.

### Optional — run in the background

**macOS / Linux**
```bash
mkdir -p logs
nohup python scripts/run_real.py --generate-only --out-dir data/runs/real_2160 > logs/gen.log 2>&1 &
tail -f logs/gen.log        # watch; Ctrl+C stops watching, not the run
```

**Windows PowerShell**
```powershell
mkdir logs -Force
Start-Process python -ArgumentList "scripts/run_real.py","--generate-only","--out-dir","data/runs/real_2160" -RedirectStandardOutput logs/gen.log -NoNewWindow
Get-Content logs/gen.log -Wait
```

### When it finishes

```
=== GENERATION COMPLETE ===
Samples generated : 2160
Generators        : ['codegemma:7b-instruct', 'codellama:7b', ...]
Unique snippets   : 2000+
Send this ONE file back:
  C:\...\codegate-scanner\data\runs\real_2160\generations.parquet
```

That path is the only thing we need.

---

# PART E — SEND THE RESULTS BACK

**The file:** `generations.parquet` from whichever run directory
(`data/runs/pilot/` for the pilot, `data/runs/real_2160/` for the full run).
It's a few MB.

Pick **one** method.

## Method 1 — Push to a git branch (preferred)

Keeps everything versioned and needs no third-party service.

```bash
git checkout -b corpus/real-2160

git add -f data/runs/real_2160/generations.parquet

git -c user.name="YOUR NAME" -c user.email="your@email.com" \
    commit -m "data: real corpus from local Ollama run"

git push -u origin corpus/real-2160
```

For the pilot, use `corpus/pilot` and the pilot path instead.

> ⚠️ The `-f` in `git add -f` is **required**. `.parquet` files are normally
> gitignored; this one is a deliberate exception. Without `-f` git silently
> ignores the file and you'd push an empty commit.

✅ **Expected:** `branch 'corpus/real-2160' set up to track...`
Then message us — we'll pull the branch. **Done.**

❌ *`Permission denied` / `403`* → your collaborator access is read-only.
Ask for write access, or use Method 2.

❌ *asks for a password* → GitHub needs a Personal Access Token, not your
password. Easiest fix is Method 2 instead.

## Method 2 — File transfer

Equally fine. Send the file via **Google Drive, WeTransfer, Dropbox,
Discord, or email** (it's only a few MB).

**Finding the file:**
- **Windows:** in the project folder, open `data\runs\real_2160\` —
  or paste `explorer data\runs\real_2160` into PowerShell
- **macOS:** `open data/runs/real_2160`
- **Linux:** `xdg-open data/runs/real_2160`

Attach **`generations.parquet`**. Nothing else.

## Method 3 — Zip everything (if something went wrong)

If the run was messy or partly failed, send the whole run folder including
the checkpoint, so we can recover partial work:

```bash
# macOS / Linux
zip -r codegate-corpus.zip data/runs/real_2160/

# Windows PowerShell
Compress-Archive -Path data/runs/real_2160 -DestinationPath codegate-corpus.zip
```

Send `codegate-corpus.zip`.

## After sending

Nothing further is needed from you. To reclaim ~16 GB of disk:

```bash
ollama rm qwen2.5-coder:7b
ollama rm deepseek-coder:6.7b
ollama rm codellama:7b
ollama rm codegemma:7b-instruct
```

You can also revert the sleep setting from B3, and delete the project
folder. Thank you — this is the part of the project that can't be automated
away.

---

# PART F — OPTIONAL TOP-UP (82 samples)

**Only if you have an hour free. The project goes ahead without this.**

The full run was written into `data/runs/real_540/`, which still held the
September run's progress file. That made it reuse 404 old answers, 78 of
them to prompts that have since been reworded. That's our code's fault, not
yours, and it's fixed now: progress files record the exact prompt wording
and won't reuse a stale answer again. A repaired progress file is on the
`corpus/real-2160` branch. Resuming from it generates only the 82 samples
still missing (about 30–60 minutes).

```bash
git fetch
git checkout corpus/real-2160
git pull
python scripts/run_real.py --generate-only --out-dir data/runs/real_2160
```

You should see `[resume] 2078 sample(s) already complete` and
`Planned samples: 2160`. When it finishes, send the file back as in Part E,
committing on this same branch:

```bash
git add -f data/runs/real_2160/generations.parquet
git commit -m "data: top up real_2160 to 2,160 samples"
git push
```

**Always use the exact `--out-dir` shown.** Resume reads whatever progress
file is in that folder.

---

# Troubleshooting

**`could not connect to Ollama at http://localhost:11434`**

Ollama isn't running. Windows/macOS: launch it from the Start menu /
Applications (it runs as a background app). Linux:
`sudo systemctl start ollama`. Confirm with `ollama list`.

**`Ollama at ... is missing model(s): [...]`**

`config.yaml` doesn't match your models. Run `ollama list` and redo B2 so
the names match exactly, tags included.

**`ollama pull codegemma:7b-instruct` → manifest not found**

Your Ollama version doesn't carry that tag. Work down the fallback ladder in
A2 (`granite-code:8b`, then `mistral:7b-instruct`), and **tell us which one
you ended up with** so we can set it in the config and name it in the report.

**`Planned samples: 540` instead of 2160**

You're on the old prompt set. Run `git branch --show-current` — it must say
`feat/certificate-restoration`. If not, `git checkout feat/certificate-restoration`,
then `git pull`.

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

**Far slower than 18 hours**

Normal on CPU is ~10–30 seconds per sample. If the total is impractical:
- switch to the small models in A2's note (several times faster, and
  arguably better signal for this project), or
- run in chunks — the command resumes, so stopping and restarting across
  several days costs nothing. Just send us the file at each stopping point.

**Anything else**

Send us the last ~30 lines of terminal output. The run is resumable, so
nothing is lost while we sort it out.

---

## What this is actually doing, if you're curious

Each model gets the same set of coding tasks — things like *"write a
function that looks up a user in a database."* Some are phrased to invite an
insecure implementation, some ask for a safe one, and some are deliberate
near-misses that *look* risky but aren't. That third category is the
interesting one: it's what stops a detector from just learning "anything
touching a database is scary."

Giving identical prompts to different models lets us measure how their
security failure patterns differ — and whether a safety guarantee calibrated
on one set of models still holds when a team switches to another. That's the
actual research question. Your machine does the writing; the analysis, and
all the code execution, happens elsewhere.
