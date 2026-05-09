# thiel

> *"Every great business is built on a secret. Keep yours out of git."*

**thiel** scans your source code for accidentally committed secrets — API keys, tokens, passwords, and private keys — before they reach your git history.

Named after Peter Thiel's framework: every great company is built on a secret. Keep yours out of main.

## What it detects

- AWS Access Keys & Secret Access Keys
- OpenAI & Anthropic API Keys
- GitHub Tokens (Personal Access, OAuth, App, Fine-Grained)
- Google API Keys & OAuth Tokens
- Stripe, Slack, Twilio, SendGrid, Mailgun keys
- HuggingFace & Databricks Tokens
- Private Keys (RSA, EC, DSA, OpenSSH)
- Generic API Key / Secret assignments
- Hardcoded passwords

## Installation

```sh
pip install thiel
```

Or run directly:

```sh
python thiel.py
```

## Usage

```
thiel scan [path]       Scan git-tracked files for secrets (default: current directory)
thiel scan --all        Scan every file, not just git-tracked ones
thiel install           Install thiel as a git pre-push hook in this repo
thiel install --force   Overwrite an existing pre-push hook
thiel uninstall         Remove the thiel pre-push hook from this repo
thiel hook              Run directly as a git pre-push hook (reads refs from stdin)
thiel help              Show help
```

## Git hook (recommended)

Run `thiel install` once per repo and every future `git push` is scanned automatically. If secrets are found, the push is blocked before anything reaches the remote.

```sh
cd your-repo
thiel install
```

To remove the hook:

```sh
thiel uninstall
```

## How it works

On `thiel scan`, thiel reads all git-tracked files (or all files with `--all`) and matches each line against a library of regex patterns for known secret formats. Placeholder values (`your_api_key`, `example`, `changeme`, etc.) are ignored to reduce false positives. Binary files, lock files, and build artifacts are skipped automatically.

When installed as a pre-push hook, thiel runs automatically on `git push` and only scans the files changed in the commits being pushed.

## Requirements

- Python 3.11+
- Git
