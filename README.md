# Safeguard

A personal security monitor for your Mac. It watches for the things attackers actually do once they get in, and tells you what to do about each one. It's a single Python file with no installs and no cloud. It only reads: it never changes settings or kills anything. The one exception is `canary --install`, which writes three empty tripwire files so Safeguard can catch ransomware encrypting your Documents.

## The app

`SafeguardApp/` is a native macOS app (SwiftUI, macOS 14+) with a custom dark interface. It has ten screens:
- **Overview:** security score, threat level, activity chart, protections, findings and watch zones.
- **Threats:** filter and search findings; for each one, mark it reviewed, trust the program, accept the change, or ask the Advisor to explain it and propose a fix. Tick several findings (shift-click selects a range) and mark them reviewed in one action.
- **Protection:** one card per safeguard, with Open Settings and, for a failing check, Ask Safeguard.
- **Network:** live connections with app icons and signatures, open ports, DNS servers and mounted network drives.
- **Startup Items:** launch agents and daemons, the login items macOS keeps hidden, ransomware tripwires, and the sensitive files Safeguard watches.
- **Link Shield:** check a link before you click it.
- **Advisor:** the optional AI, on its own screen: brief the scan, pick a finding, ask, approve a fix.
- **Activity:** scan history, the event log, and every applied fix with its undo.
- **Settings:** appearance, auto-scan interval, notifications, the Advisor and its API key, background protection, baseline and trusted programs.

It runs in the menu bar too: a shield icon with a status panel, and closing the window keeps it scanning in the background. Safeguard registers itself as a login item on first launch so monitoring survives a reboot; turn that off in Settings › Background protection.

Seven looks, switched in Settings › Appearance (the whole window redraws at once):
- **A · Graphite:** calm dark dashboard, lime accent, ring gauge. Geist.
- **B · Field Ops:** terminal instrument panel in amber on warm black, F-key navigation (F1 to F7, F9). JetBrains Mono.
- **C · Dot Matrix:** black, dotted numerals, a single red alert, pill navigation. Doto, Space Grotesk and Space Mono.
- **D · Bento:** soft charcoal tiles, big friendly numbers, a coral accent. Bricolage Grotesque and Inter.
- **E · Swiss:** pure type and thick rules, no boxes. Inter Tight.
- **F · Hardware:** embossed panels, keycap buttons, an LCD score. IBM Plex Sans and Mono.
- **G · Neo-Brutal:** light paper, black outlines, hard shadows, bright fills. Space Grotesk and Space Mono.

All fonts are bundled with their open licences under `SafeguardApp/Resources/Fonts/`.

```bash
cd SafeguardApp
./build.sh      # builds, signs and installs to /Applications, no local copy
./release.sh    # builds dist/Safeguard-<version>.dmg for sharing
```

Building needs Xcode or the Command Line Tools (Swift 5.9+, macOS 14 SDK). The DMG is signed with your Apple Development identity when one is present and is **not notarized**, so first launch on another Mac needs right-click → Open. See `SafeguardApp/Resources/INSTALL.txt`.

The app bundles `safeguard.py` as its detection engine and runs it with macOS's built-in `/usr/bin/python3`, so the app and the command line share one baseline in `~/.safeguard/`.

## Quick start (command line)

```bash
python3 safeguard.py audit                 # how locked-down is this Mac? (with fixes)
python3 safeguard.py baseline              # "this is what normal looks like"
python3 safeguard.py scan                  # what changed since then? what's online right now?
python3 safeguard.py check-url <link>      # check a link before you click it
python3 safeguard.py canary --install      # plant tripwire files that catch ransomware
python3 safeguard.py agent explain <id>    # ask the advisor about one finding (optional)
python3 safeguard.py fix list              # reversible remedies and their risk
python3 safeguard.py loginitems            # hidden login items (asks admin once)
python3 safeguard.py browser --days 7      # sites visited, from local history
python3 safeguard.py browser --sync        # import now
python3 safeguard.py browser --clear       # delete Safeguard's copy
python3 safeguard.py browser --requests    # live requests captured by the extension
python3 safeguard.py browser --install-extension
python3 safeguard.py bridge                # loopback ingest for the extension
python3 safeguard.py schedule --install    # scan every 15 min in the background, with notifications
```

Data, the HTML report and the alert log live in `~/.safeguard/` (override with `SAFEGUARD_HOME`).
When a scan flags something you did yourself, like installing an app or editing `.zshrc`, run `baseline` again to accept it.
To silence a trusted dev tool in connection alerts, add its name or path to `~/.safeguard/allowlist.json`.

## The Advisor (optional AI)

A finding can be explained, and fixed, by an optional AI mediator. It is off until you turn it on.

- **It cannot run anything.** The model receives one finding and a short list of candidate fixes that Safeguard has already derived locally. It may only pick one of those, by id, with parameters that Safeguard validates. Anything else is rejected.
- **Nothing changes without you.** The proposal shows the exact command, the risk and whether admin is needed. You press *Fix it*; Safeguard applies it, verifies the result, and offers Undo. If verification fails, the change is rolled back.
- **Only the finding leaves your Mac.** No files, screenshots or history. Turn off "Send finding details" to send just the title and severity. The send happens when you press *Ask*, never on a schedule.
- **OpenAI-compatible, Anthropic, or local.** DeepSeek, OpenAI, Groq, Anthropic, or Ollama/LM Studio on `http://127.0.0.1:11434/v1` with no key and nothing leaving the Mac.
- **Live model list.** The model field is a dropdown filled from the provider's own `/models` endpoint (Anthropic's `/v1/models`, Ollama's tag list), with a refresh item. No typing model names.
- **Reasoning effort.** Off / Low / Medium / High. Sent as `reasoning_effort` to OpenAI-compatible APIs and as an extended-thinking budget to Anthropic; providers that do not support it fall back automatically.
- **When a model answers in prose.** Safeguard asks again for JSON once; if it still refuses, it shows the plain answer instead of an error, and writes the raw reply to `~/.safeguard/agent-last.json` for diagnosis. Truncated answers are retried with a larger token budget.
- **An agent, not a chat box.** For a finding it runs read-only checks before answering: npm registry vs installed copy, file facts and code signature, small configs/plists, folder listings, which process owns a port, and for a browser request the domain's DNS, TLS certificate, local history and current rules. It reports what it verified instead of telling you to go look.
- **Verify a browser request.** Select any captured request → *Verify this request*; the agent checks DNS, certificate validity, visit history and rules, then can add the domain to the block or warn list (undoable).
- **Security sweep.** Browser → *Security sweep* sends a compact summary of recent sites to the advisor. It returns only sites worth a second look, with Block/Warn buttons; safe sites are omitted and nothing is applied without a click.
- **Actions stay bounded.** The agent can investigate freely, but any change still comes from Safeguard's fixed fix catalogue and waits for your approval.
- **Brief me.** From Threats, one scan-wide summary: what matters, what can wait, at most three priorities.
- **Follow-ups.** Ask another question about the same finding; the answer stays text-only.
- **Protection checks too.** A failing protection card has *Ask Safeguard* as well as *Open Settings*, so checks like "backup missing" get the same treatment.
- **Auto-brief.** Optional, off by default: once a day after a scan, summarise findings without asking. It sends the same data automatically, so enable it deliberately. It runs while the app is open; launch-agent scans do not call the model.
- **Key storage.** The key lives in your login Keychain (service `local.safeguard.agent`), never in a file. macOS may ask once per app build to unlock it: choose **Always Allow**. The app reads it once per session and keeps it in memory, so the dialog does not repeat on every request. For the terminal:

```bash
security add-generic-password -s local.safeguard.agent -a openai -w "sk-..." -U
python3 safeguard.py agent test
```

Settings › Advisor: provider, endpoint, model, key, explain-only mode, detail sharing, auto-brief, and a daily request cap (default 40). Settings › Browser history: retention (7/30/90 days or a year) and clearing Safeguard's copy.

**Browser extension (requests + blocking).** Browser › Requests → *Install extension*, then in Chrome/Arc/Brave/Edge open `chrome://extensions`, enable Developer mode, and choose **Load unpacked**. The folder sits on your **Desktop** as `Safeguard Browser Extension`, and Safeguard copies that path to the clipboard, so you can press Command-Shift-G, Command-V, Return in the picker. Chrome 156 has removed command-line loading, so this three-click install is the only supported path. The extension talks only to `127.0.0.1` with a token from `~/.safeguard/bridge-token`.

What it captures: URL, method, resource type, tab, frame, initiator, status, and whether the request was hidden. It does **not** capture headers, cookies, bodies or page content. Blocking uses Chrome's declarative rules; warnings use a local page with *Continue once*. The bridge binds loopback only and is stopped when Safeguard quits.

Requests are only as live as the browser: the extension posts a heartbeat every minute, and the Requests screen says **"last seen 2 days ago"** instead of showing an empty list when the browser is closed or the extension is not loaded. Events captured while Safeguard was closed are kept in the extension's local storage (last 800) and sent when the bridge returns. After updating Safeguard, press **Reload** for the extension on `chrome://extensions`.

History and requests are pruned on every import, and the database is compacted in place (`auto_vacuum=INCREMENTAL`), so `browser.db` stays near its real size instead of growing forever.

**Full Disk Access** is required for browser history: System Settings › Privacy & Security › Full Disk Access → add `/Applications/Safeguard.app` → relaunch. Without it the Browser screen shows which browsers are blocked.

Every applied fix appears on Activity with its verification result and an Undo button.

### The fix catalogue

Eleven reversible actions, all previewed before they run:

| Action | Risk | Admin | Undo |
|---|---|---|---|
| `ssh.disable` | low | yes | yes |
| `firewall.enable`, `firewall.stealth` | low | yes | yes |
| `dns.clear`, `proxy.clear` | medium | yes | previous values |
| `persist.quarantine` | medium | when system-wide | restore file |
| `cron.remove` | medium | no | crontab backup |
| `package.uninstall` | medium | no | reinstall |
| `app.quarantine` | medium | when in /Applications | move back |
| `profile.remove` | medium | yes | reinstall the profile |
| `tcc.revoke` | medium | no | re-grant manually |

```bash
python3 safeguard.py fix list
python3 safeguard.py fix apply persist.quarantine --params '{"path":"~/Library/LaunchAgents/x.plist"}'   # dry run
python3 safeguard.py fix apply persist.quarantine --params '...' --yes                                   # apply
```

Every change is copied to `~/.safeguard/quarantine/<time>/` first, verified, and recorded in `~/.safeguard/fixes.json` and `activity.jsonl`. Fixes that fail verification roll themselves back; Activity lists them all with Undo.

## What it detects

| Attack step | How Safeguard notices |
|---|---|
| A site you visited | Browser history is imported read-only from Safari, Chrome and other local profiles; Apple and Chromium protect these files, so grant **Full Disk Access** to Safeguard. Query values are hidden in the UI. |
| Malware making itself start on boot | New or changed LaunchAgents/LaunchDaemons, cron jobs, system extensions and login hooks, with the code signature of what they run; hidden login items on demand (Startup Items › Check login items, or `safeguard.py loginitems`), because macOS gates that list behind an admin prompt |
| Malware switching off protections | Any protection that passed at baseline (firewall, FileVault, SIP, Authenticated Root, Gatekeeper, XProtect and others) now failing |
| Backdoor SSH access | Changes to `~/.ssh/authorized_keys` and `sshd_config`; bursts of failed SSH logins |
| Password guessing | Repeated wrong `sudo` passwords |
| A new way in | New administrator accounts, hidden users (UID below 500), passwordless `sudo` rules, and edits to `/etc/sudoers`, `/etc/pam.d` or `/etc/periodic` |
| Redirecting your bank or email to a fake site | Changes to `/etc/hosts`, DNS servers, per-domain resolvers, proxy or PAC settings, and any new root certificate (a rogue CA reads everything) |
| Employer-grade remote control | MDM enrollment or a configuration profile appearing, and Remote Management (ARD), File Sharing, Printer Sharing or Internet Sharing switching on |
| Poisoned dev setup (malicious npm/pip packages, AI-generated "fix" scripts) | Changes to shell profiles, `.gitconfig`, `.npmrc` and `pip.conf`; new global npm/Homebrew packages; new browser extensions |
| Password and key theft | New or changed `.netrc`, AWS, git, GitHub, Docker, Kubernetes and GPG credential files, plus SSH keys without passphrases |
| Malware calling home | Programs online that run from temp/Downloads folders, are unsigned, self-signed, or talk to backdoor/IRC/Tor ports, or connect to a bare IP with no domain |
| Malware watching you | New Screen Recording, Accessibility, Input Monitoring or Full Disk Access grants (needs Full Disk Access to read; otherwise reported as unknown) |
| Paste-a-command scams ("ClickFix") | shell history containing `curl \| sh`, `base64 \| sh`, `osascript do shell script` or quarantine stripping; and any browser or document app that launches a shell |
| Ransomware | A changed tripwire file in Documents, and a backup that is missing or more than two weeks old |
| Phishing links (now often AI-written and flawless) | Look-alike domains (`paypa1`, Cyrillic letters), brand names in the wrong place, `@` tricks, raw IPs, shorteners |

## What needs admin rights or Full Disk Access

Safeguard never prompts for a password. Checks that macOS withholds are reported as `unknown`, with what to do about it:

| Check | Needs | Without it |
|---|---|---|
| Screen Recording / Accessibility grants | Full Disk Access | reported as unknown |
| Firmware password (Intel Macs) | admin | reported as unknown |
| Passwordless `sudo` rules | admin (only visible if one exists) | reported as unknown |
| Hidden login items (`sfltool dumpbtm`) | nothing on most Macs, admin on some | reported as unknown or empty |
| Tripwire files in Documents | Files and Folders permission (Safeguard prompts once) | falls back to `~/Safeguard Tripwires` |

## What it can't do

- It isn't antivirus: it doesn't scan files for known malware. It does watch XProtect's presence and version, so a missing or stale definition set shows up as a protection failure.
- It can't read the TCC database without Full Disk Access, so permission abuse stays `unknown` until you grant it.
- Without `sudo` it only sees network activity from your own user's programs, not root daemons.
- It can't stop deepfake calls or AI-voice scams. Only habits do that (see below).
- A clever, targeted attacker can evade any single tool. Safeguard raises the bar and shortens the time until you notice.
- The Advisor can be wrong. It only ever chooses from the fixed catalogue above, its parameters are validated locally, and its explanation is text, not truth. Treat it as a second opinion.

## What this Mac needs right now (from the current audit)

1. **No Time Machine destination.** There is no backup, so ransomware or a bad update costs every file. Add a disk in System Settings > General > Time Machine and turn on encryption.
2. **Remote Login (SSH)** and **Firewall stealth mode** were the previous findings; both now pass. Re-run `safeguard.py audit` after changing anything.

## Habits that beat AI-powered attacks

- **Passkeys or an authenticator app on email, bank, GitHub and mobile money.** AI phishing is good at stealing passwords; it can't steal a passkey.
- **A family code word.** AI can clone a voice from a few seconds of audio. If "your brother" calls asking for money urgently, ask for the word, or hang up and call back on the number you already have.
- **Never paste a command a web page tells you to run** to "verify you're human" or "fix an error" (the "ClickFix" scam). That's how infostealers install themselves.
- **A password manager.** It won't autofill on a fake domain, which makes it a phishing detector too.
- **Treat urgency as a red flag.** "Act within 1 hour" is the attack.
