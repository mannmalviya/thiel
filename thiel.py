#!/usr/bin/env python3
"""
thiel - Secrets belong in the shadows, not in your git history.

Named after Peter Thiel's framework: every great company is built on a secret.
Keep yours out of main.
"""

import sys
import re
import os
import subprocess
import argparse
import random
from pathlib import Path

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

# ── Scanning logic ────────────────────────────────────────────────────────────

def compile_patterns():
    """
    Pre-compile every regex in PATTERNS so the scanner doesn't recompile per line.

    Returns:
        list[tuple[re.Pattern, str]]: (compiled pattern, human-readable name) pairs.
    """
    return [(re.compile(p), name) for p, name in PATTERNS]

COMPILED = compile_patterns()


def should_skip(path: Path) -> bool:
    """
    Decide whether a path is in a skip-listed directory, has a skip-listed
    extension, or is a known lockfile / minified asset.

    Args:
        path (Path): Filesystem path to check.

    Returns:
        bool: True if the scanner should ignore this path.
    """
    for part in path.parts:
        if part in SKIP_DIRS:
            return True
    if path.name in SKIP_FILES:
        return True
    suffix = path.suffix.lower()
    name_lower = path.name.lower()
    if suffix in SKIP_EXTS:
        return True
    if name_lower.endswith('.min.js') or name_lower.endswith('.min.css'):
        return True
    return False


def scan_content(content: str, filepath: str) -> list[dict]:
    """
    Walk every line of file content and record matches for any known secret
    pattern, skipping lines that look like placeholders.

    Args:
        content (str): Raw text of the file being scanned.
        filepath (str): Path string used to label findings.

    Returns:
        list[dict]: One dict per match with keys file, line, type, content.
    """
    findings = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, 1):
        # Skip obvious false positives: placeholder values
        stripped = line.strip()
        if any(ph in stripped.lower() for ph in
               ['your_api_key', 'your-api-key', 'xxx', 'placeholder',
                'changeme', 'example', '<secret>', 'insert_key']):
            continue
        for pattern, name in COMPILED:
            if pattern.search(line):
                findings.append({
                    'file': filepath,
                    'line': lineno,
                    'type': name,
                    'content': line.rstrip()[:120],
                })
    return findings


def scan_file(path: Path) -> list[dict]:
    """
    Read a single file from disk and scan it for secrets. Silently returns an
    empty list for skip-listed or unreadable files.

    Args:
        path (Path): File to scan.

    Returns:
        list[dict]: Findings produced by scan_content, or [] if skipped/unreadable.
    """
    if should_skip(path):
        return []
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except (OSError, PermissionError):
        return []
    return scan_content(text, str(path))


def get_pushed_files() -> list[Path] | None:
    """
    Parse pre-push hook refs from stdin and diff each ref range to collect
    the files that are about to be pushed.

    Returns:
        list[Path] | None: Files changed in the pushed commits, or None if
        the set couldn't be determined (caller should fall back to a full scan).
    """
    files = set()
    for line in sys.stdin:
        parts = line.strip().split()
        if len(parts) < 4:
            continue
        local_ref, local_sha, remote_ref, remote_sha = parts[:4]
        zero = '0' * 40
        if local_sha == zero:
            continue  # deletion, nothing to scan
        base = remote_sha if remote_sha != zero else '--root'
        try:
            if base == '--root':
                result = subprocess.run(
                    ['git', 'diff', '--name-only', local_sha],
                    capture_output=True, text=True
                )
            else:
                result = subprocess.run(
                    ['git', 'diff', '--name-only', f'{remote_sha}..{local_sha}'],
                    capture_output=True, text=True
                )
            for f in result.stdout.strip().splitlines():
                p = Path(f)
                if p.exists():
                    files.add(p)
        except Exception:
            return None
    return list(files) if files else None


def scan_git_tracked() -> list[Path]:
    """
    List every git-tracked file in the current repo, falling back to a
    recursive directory walk if git is unavailable.

    Returns:
        list[Path]: Tracked files from `git ls-files`, or all files under cwd.
    """
    try:
        result = subprocess.run(
            ['git', 'ls-files'],
            capture_output=True, text=True
        )
        return [Path(f) for f in result.stdout.strip().splitlines() if f]
    except Exception:
        return list(Path('.').rglob('*'))


def scan_directory(root: Path) -> list[Path]:
    """
    Recursively collect every regular file under root, ignoring directories.

    Args:
        root (Path): Directory to walk.

    Returns:
        list[Path]: All files found beneath root.
    """
    return [p for p in root.rglob('*') if p.is_file()]

# ── Output ────────────────────────────────────────────────────────────────────

RED    = '\033[91m'
YELLOW = '\033[93m'
GREEN  = '\033[92m'
CYAN   = '\033[96m'
BOLD   = '\033[1m'
DIM    = '\033[2m'
RESET  = '\033[0m'

def no_color() -> bool:
    """
    Check whether ANSI color output should be suppressed (non-TTY stdout or
    NO_COLOR env var set).

    Returns:
        bool: True if output should be plain text.
    """
    return not sys.stdout.isatty() or os.environ.get('NO_COLOR')


def c(code: str, text: str) -> str:
    """
    Wrap text in an ANSI color/style code, or return it unchanged when color
    is disabled.

    Args:
        code (str): ANSI escape sequence (e.g. RED, BOLD).
        text (str): Text to colorize.

    Returns:
        str: Colorized text, or the raw text if no_color() is true.
    """
    if no_color():
        return text
    return f'{code}{text}{RESET}'


def print_banner():
    """
    Print the thiel ASCII-art banner and tagline to stdout.

    Returns:
        None
    """
    print(c(BOLD, """
  ████████╗██╗  ██╗██╗███████╗██╗
  ╚══██╔══╝██║  ██║██║██╔════╝██║
     ██║   ███████║██║█████╗  ██║
     ██║   ██╔══██║██║██╔══╝  ██║
     ██║   ██║  ██║██║███████╗███████╗
     ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝
"""))
    print(c(DIM, '  Secrets belong in the shadows, not in your git history.\n'))


def print_findings(findings: list[dict]):
    """
    Group findings by file path and print each file's hits with line numbers,
    secret type, and a snippet of the offending line.

    Args:
        findings (list[dict]): Findings produced by the scanner.

    Returns:
        None
    """
    by_file: dict[str, list] = {}
    for f in findings:
        by_file.setdefault(f['file'], []).append(f)

    for filepath, hits in by_file.items():
        print(c(BOLD + YELLOW, f'\n  {filepath}'))
        for hit in hits:
            lineno_str = f'line {hit["line"]:>4}'
            print(f"    {c(DIM, lineno_str)}  {c(RED, hit['type'])}")
            print(f"             {c(DIM, hit['content'])}")


def print_verdict(findings: list[dict], hook_mode: bool):
    """
    Render the final scan result: either a clean-bill message or a failure
    block with findings, a Thiel quote, and remediation guidance.

    Args:
        findings (list[dict]): All collected scanner findings.
        hook_mode (bool): If True, append a "Push blocked." notice on failure.

    Returns:
        None
    """
    if findings:
        quote = random.choice(CAUGHT_QUOTES)
        print(c(RED + BOLD, f'\n  ✗  {len(findings)} secret(s) found across '
                            f'{len({f["file"] for f in findings})} file(s).\n'))
        print_findings(findings)
        print(c(YELLOW + BOLD, f'\n  "{quote}"\n'))
        print(c(DIM, '  Fix: remove the secrets, rotate any exposed keys, '
                     'and consider adding them to .gitignore or .env.\n'))
        if hook_mode:
            print(c(RED, '  Push blocked.\n'))
    else:
        quote = random.choice(CLEAN_QUOTES)
        print(c(GREEN + BOLD, f'\n  ✓  {quote}\n'))

# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_scan(args):
    """
    Handle the `thiel scan` subcommand: pick the file set (git-tracked or
    every file via --all), scan each one, and print a verdict.

    Args:
        args (argparse.Namespace): Parsed CLI args with .path and .all.

    Returns:
        int: 1 if any findings were reported, 0 otherwise (exit code).
    """
    print_banner()
    root = Path(args.path)
    print(c(CYAN, f'  Scanning {root.resolve()} ...\n'))

    if args.all:
        files = scan_directory(root)
    else:
        files = scan_git_tracked()
        if not files:
            files = scan_directory(root)

    findings = []
    for f in files:
        findings.extend(scan_file(f))

    print_verdict(findings, hook_mode=False)
    return 1 if findings else 0


def cmd_hook(args):
    """
    Handle the `thiel hook` subcommand invoked by the pre-push git hook.
    Reads pushed refs from stdin, scans the affected files, and exits 1
    if any secrets are found.

    Args:
        args (argparse.Namespace): Parsed CLI args (unused, kept for parity).

    Returns:
        None: Always exits via sys.exit() rather than returning.
    """
    files = get_pushed_files()
    if files is None:
        # Fallback: scan all tracked files
        files = scan_git_tracked()

    if not files:
        sys.exit(0)

    findings = []
    for f in files:
        findings.extend(scan_file(f))

    if findings:
        print_banner()
        print_verdict(findings, hook_mode=True)
        sys.exit(1)

    sys.exit(0)


def cmd_install(args):
    """
    Handle the `thiel install` subcommand: write a pre-push hook in the
    current git repo that runs `thiel hook` on every push.

    Args:
        args (argparse.Namespace): Parsed CLI args with .force flag.

    Returns:
        None: Exits non-zero if not a git repo or if a hook already exists
        without --force.
    """
    try:
        result = subprocess.run(
            ['git', 'rev-parse', '--git-dir'],
            capture_output=True, text=True, check=True
        )
        git_dir = result.stdout.strip()
    except subprocess.CalledProcessError:
        print(c(RED, '  Not a git repository.'))
        sys.exit(1)

    hooks_dir = Path(git_dir) / 'hooks'
    hooks_dir.mkdir(exist_ok=True)
    hook_path = hooks_dir / 'pre-push'

    script_path = Path(__file__).resolve()
    hook_content = f"""#!/bin/sh
# thiel pre-push hook — installed by `thiel install`
python3 "{script_path}" hook
"""

    if hook_path.exists() and not args.force:
        print(c(YELLOW, f'  Hook already exists at {hook_path}.'))
        print(c(DIM,    '  Use --force to overwrite.'))
        sys.exit(1)

    hook_path.write_text(hook_content)
    hook_path.chmod(0o755)
    print(c(GREEN + BOLD, f'\n  ✓  thiel installed as pre-push hook at {hook_path}\n'))
    print(c(DIM, '  Every future `git push` will be scanned for secrets.\n'))
    print(c(CYAN, '  "Secrets are the engine of every monopoly. Guard yours."\n'))


def cmd_help(args):
    """
    Handle the `thiel help` subcommand: print the banner, usage summary,
    detected secret categories, and a closing tip.

    Args:
        args (argparse.Namespace): Parsed CLI args (unused).

    Returns:
        None
    """
    print_banner()
    print(c(BOLD, '  What is thiel?\n'))
    print('  thiel scans your source code for accidentally committed secrets —')
    print('  API keys, tokens, passwords, and private keys — before they reach')
    print('  your git history (and the internet).\n')
    print(c(BOLD, '  Commands:\n'))
    cmds = [
        ('thiel scan [path]',      'Scan git-tracked files for secrets (default: current directory)'),
        ('thiel scan --all',       'Scan every file, not just git-tracked ones'),
        ('thiel install',          'Install thiel as a git pre-push hook in this repo'),
        ('thiel install --force',  'Overwrite an existing pre-push hook'),
        ('thiel uninstall',        'Remove the thiel pre-push hook from this repo'),
        ('thiel hook',             'Run directly as a git pre-push hook (reads refs from stdin)'),
        ('thiel help',             'Show this message'),
    ]
    for cmd, desc in cmds:
        print(f'  {c(CYAN, cmd):<40}  {c(DIM, desc)}')
    print()
    print(c(BOLD, '  What it detects:\n'))
    categories = [
        'AWS Access/Secret Keys',
        'OpenAI & Anthropic API Keys',
        'GitHub Tokens (PAT, OAuth, App)',
        'Google API Keys & OAuth Tokens',
        'Stripe, Slack, Twilio, SendGrid, Mailgun',
        'HuggingFace & Databricks Tokens',
        'Private Keys (RSA, EC, DSA, OpenSSH)',
        'Generic API Key / Secret assignments',
        'Hardcoded passwords',
    ]
    for cat in categories:
        print(f'  {c(DIM, "·")} {cat}')
    print()
    print(c(DIM, '  Tip: run `thiel install` once per repo and every future push is'))
    print(c(DIM, '  scanned automatically. No secrets reach origin/main.\n'))
    print(c(YELLOW, '  "Every great business is built on a secret. Keep yours out of git."\n'))


def cmd_uninstall(args):
    """
    Handle the `thiel uninstall` subcommand: delete the pre-push hook from
    the current repo, but only if it was originally installed by thiel.

    Args:
        args (argparse.Namespace): Parsed CLI args (unused).

    Returns:
        None: Exits early if no hook exists or the hook wasn't ours.
    """
    try:
        result = subprocess.run(
            ['git', 'rev-parse', '--git-dir'],
            capture_output=True, text=True, check=True
        )
        git_dir = result.stdout.strip()
    except subprocess.CalledProcessError:
        print(c(RED, '  Not a git repository.'))
        sys.exit(1)

    hook_path = Path(git_dir) / 'hooks' / 'pre-push'
    if not hook_path.exists():
        print(c(YELLOW, '  No pre-push hook found.'))
        sys.exit(0)

    content = hook_path.read_text()
    if 'thiel' not in content:
        print(c(YELLOW, '  The pre-push hook was not installed by thiel. Leaving it alone.'))
        sys.exit(0)

    hook_path.unlink()
    print(c(GREEN, '\n  ✓  thiel pre-push hook removed.\n'))


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog='thiel',
        description='Scan source code for secrets before they reach main.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='"Every great business is built on a secret. Keep yours out of git."'
    )
    sub = parser.add_subparsers(dest='command')

    p_scan = sub.add_parser('scan', help='Scan for secrets in the current repo')
    p_scan.add_argument('path', nargs='?', default='.', help='Directory to scan (default: .)')
    p_scan.add_argument('--all', action='store_true',
                        help='Scan all files, not just git-tracked ones')

    sub.add_parser('hook', help='Run as a git pre-push hook (reads refs from stdin)')

    p_install = sub.add_parser('install', help='Install as a git pre-push hook')
    p_install.add_argument('--force', action='store_true',
                           help='Overwrite existing hook')

    sub.add_parser('uninstall', help='Remove the git pre-push hook')

    sub.add_parser('help', help='Show what thiel does and how to use it')

    args = parser.parse_args()

    if args.command == 'scan':
        sys.exit(cmd_scan(args))
    elif args.command == 'hook':
        cmd_hook(args)
    elif args.command == 'install':
        cmd_install(args)
    elif args.command == 'uninstall':
        cmd_uninstall(args)
    elif args.command == 'help':
        cmd_help(args)
    else:
        cmd_help(args)


if __name__ == '__main__':
    main()
