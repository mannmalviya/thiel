"""
Pattern data for thiel: secret regexes, skip lists, and Thielian wisdom.

Edit this file to add new detections or tweak which paths the scanner skips.
The scanner logic itself lives in __main__.py.
"""

# ── Thielian wisdom ──────────────────────────────────────────────────────────

CAUGHT_QUOTES = [
    "Don't tell them, they wouldn't believe you even if you did.",
    "What important truth do very few people agree with you on?\n  That you shouldn't push API keys to main.",
    "Every great business is built on a secret. Keep it that way — don't commit it.",
    "Competition is for losers. So is pushing secrets to GitHub.",
    "A startup messed up at its foundation cannot be fixed. Neither can an exposed API key.",
    "The most contrarian thing of all is not to oppose the crowd but to think for yourself —\n  and keep your secrets out of git.",
    "Monopolize your secrets. Don't let the world see them.",
    "You are not a lottery ticket. Your API keys shouldn't be public either.",
    "Brilliant thinking is rare, but courage is in even shorter supply.\n  Have the courage to keep your .env out of version control.",
    "The next Bill Gates will not build an operating system.\n  The next Larry Page will not make a search engine.\n  The next developer to push secrets to main will be you, apparently.",
    "Going from zero to one is hard. Rotating leaked API keys is harder.",
    "Secrets are the engine of every monopoly. Yours just got pushed to origin/main.",
]

CLEAN_QUOTES = [
    "Zero secrets found. Zero to one. Good work.",
    "No secrets detected. Thiel approves. You may proceed.",
    "Clean. Like a well-kept competitive moat.",
    "Nothing found. Your secrets are safe. Unlike Palantir's reputation.",
]

# ── Secret patterns ───────────────────────────────────────────────────────────

PATTERNS = [
    # AWS
    (r'AKIA[0-9A-Z]{16}',                                       'AWS Access Key ID'),
    (r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']', 'AWS Secret Access Key'),
    # OpenAI
    (r'sk-[a-zA-Z0-9]{48}',                                     'OpenAI API Key'),
    (r'sk-proj-[a-zA-Z0-9\-_]{80,}',                            'OpenAI Project Key'),
    # Anthropic
    (r'sk-ant-[a-zA-Z0-9\-_]{90,}',                             'Anthropic API Key'),
    # GitHub
    (r'ghp_[a-zA-Z0-9]{36}',                                    'GitHub Personal Access Token'),
    (r'gho_[a-zA-Z0-9]{36}',                                    'GitHub OAuth Token'),
    (r'ghs_[a-zA-Z0-9]{36}',                                    'GitHub App Token'),
    (r'github_pat_[a-zA-Z0-9_]{82}',                            'GitHub Fine-Grained PAT'),
    # Google
    (r'AIza[0-9A-Za-z\-_]{35}',                                 'Google API Key'),
    (r'ya29\.[0-9A-Za-z\-_]+',                                  'Google OAuth Token'),
    # Stripe
    (r'sk_live_[0-9a-zA-Z]{24,}',                               'Stripe Live Secret Key'),
    (r'rk_live_[0-9a-zA-Z]{24,}',                               'Stripe Restricted Key'),
    # Slack
    (r'xoxb-[0-9A-Za-z\-]{50,}',                                'Slack Bot Token'),
    (r'xoxp-[0-9A-Za-z\-]{100,}',                               'Slack User Token'),
    (r'xoxa-[0-9A-Za-z\-]{50,}',                                'Slack App Token'),
    (r'xoxs-[0-9A-Za-z\-]{50,}',                                'Slack Legacy Token'),
    # Twilio
    (r'AC[0-9a-fA-F]{32}',                                      'Twilio Account SID'),
    (r'SK[0-9a-fA-F]{32}',                                      'Twilio API Key'),
    # SendGrid
    (r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',            'SendGrid API Key'),
    # Mailgun
    (r'key-[0-9a-zA-Z]{32}',                                    'Mailgun API Key'),
    # HuggingFace
    (r'hf_[a-zA-Z0-9]{34,}',                                    'HuggingFace Token'),
    # Databricks
    (r'dapi[a-zA-Z0-9]{32}',                                    'Databricks API Token'),
    # Private keys
    (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',   'Private Key'),
    # Generic high-confidence patterns
    (r'(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*["\']([A-Za-z0-9+/\-_]{32,})["\']',
                                                                 'Generic API Key/Secret'),
    # Hardcoded passwords in assignment
    (r'(?i)password\s*=\s*["\'][^"\']{8,}["\']',               'Hardcoded Password'),
]

# Files and directories to always skip
SKIP_DIRS  = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'env',
              'dist', 'build', '.next', '.nuxt', 'vendor', 'target'}
SKIP_EXTS  = {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2',
              '.ttf', '.eot', '.pdf', '.zip', '.tar', '.gz', '.lock',
              '.min.js', '.min.css', '.map', '.pyc', '.exe', '.bin', '.so', '.dylib'}
SKIP_FILES = {'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'Pipfile.lock',
              'poetry.lock', 'composer.lock', 'Cargo.lock', 'go.sum'}
