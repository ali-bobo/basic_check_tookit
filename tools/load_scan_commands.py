#!/usr/bin/env python3
"""
Simple loader and dry-run runner for `reports/scan_commands.json`.
- Default: lists commands and prints them (dry-run).
- Optional: actually executes a non-admin command if `--execute` given.

Usage:
  python tools/load_scan_commands.py --list --platform linux
  python tools/load_scan_commands.py --execute --id linux_free
"""
import argparse
import hashlib
import json
import shlex
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_JSON = ROOT / 'reports' / 'scan_commands.json'

# Security: 只允許這份清單內的可執行檔被執行，防止指令注入 (CWE-78)
ALLOWED_EXECUTABLES = {
    'free', 'ps', 'ss', 'df', 'uptime', 'who', 'last', 'uname', 'cat', 'find',
    'grep', 'awk', 'sed', 'sort', 'head', 'tail', 'ls', 'stat', 'id', 'hostname',
    'ip', 'ping', 'netstat', 'lsof', 'top', 'pgrep', 'date', 'lscpu', 'mount',
    'du', 'file', 'lsmod', 'dmesg', 'journalctl', 'systemctl', 'hostnamectl',
    'timedatectl', 'getconf', 'sw_vers', 'vm_stat', 'diskutil', 'launchctl',
    'dscl', 'csrutil', 'spctl', 'fdesetup', 'traceroute', 'dig', 'nslookup',
    'host', 'curl',
}


def verify_checksum(json_path: Path) -> bool:
    """驗證 JSON 檔案的 SHA-256 是否與 .sha256 側車檔相符。"""
    sha_path = json_path.parent / (json_path.name + '.sha256')
    if not sha_path.is_file():
        print(f'[!] checksum 檔案不存在: {sha_path}')
        return False
    sha_line = sha_path.read_text(encoding='utf-8').strip().split()[0]
    actual = hashlib.sha256(json_path.read_bytes()).hexdigest()
    if sha_line == actual:
        print(f'[+] checksum 驗證通過: {actual[:16]}...')
        return True
    print(f'[!] checksum 不符！')
    print(f'    期望: {sha_line}')
    print(f'    實際: {actual}')
    return False


def load_commands(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    p = Path(path) if path else DEFAULT_JSON
    with p.open('r', encoding='utf-8') as f:
        return json.load(f)


def get_commands_by_platform(commands: List[Dict[str, Any]], platform: Optional[str]) -> List[Dict[str, Any]]:
    if not platform:
        return commands
    return [c for c in commands if c.get('platform') == platform]


def find_command_by_id(commands: List[Dict[str, Any]], id_: str) -> Optional[Dict[str, Any]]:
    for c in commands:
        if c.get('id') == id_:
            return c
    return None


def print_command(cmd: Dict[str, Any]) -> None:
    print(f"- id: {cmd.get('id')}")
    print(f"  platform: {cmd.get('platform')}")
    print(f"  requires_admin: {cmd.get('requires_admin')}")
    print(f"  command: {cmd.get('command')}")
    print(f"  description: {cmd.get('description')}\n")


def run_command(cmd: str, execute: bool = False, timeout: int = 30) -> Dict[str, Any]:
    """If execute==False do a dry-run and return the command string only.
    If execute==True, actually run the command via shlex.split (no shell=True).
    """
    result = {
        'command': cmd,
        'execute': execute,
        'exit_code': None,
        'stdout': None,
        'stderr': None,
    }
    if not execute:
        return result

    # Security: 解析指令並驗證可執行檔是否在 allowlist 內 (CWE-78)
    try:
        parts = shlex.split(cmd)
    except ValueError as e:
        result['exit_code'] = -1
        result['stderr'] = f'Invalid command syntax: {e}'
        return result

    if not parts:
        result['exit_code'] = -1
        result['stderr'] = 'Empty command'
        return result

    import os
    executable_name = os.path.basename(parts[0])
    if executable_name not in ALLOWED_EXECUTABLES:
        result['exit_code'] = -1
        result['stderr'] = (
            f"Security: executable '{executable_name}' is not in the allowed list. "
            "Execution blocked."
        )
        return result

    try:
        proc = subprocess.run(
            parts,
            shell=False,          # shell=False 防止指令注入
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        result['exit_code'] = proc.returncode
        result['stdout'] = (proc.stdout or '')[:8192]
        result['stderr'] = (proc.stderr or '')[:8192]
    except Exception as e:
        result['exit_code'] = -1
        result['stderr'] = str(e)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--list', action='store_true', help='List available commands')
    ap.add_argument('--platform', choices=['linux', 'windows', 'macos'], help='Filter by platform')
    ap.add_argument('--id', help='Command id to show or execute')
    ap.add_argument('--execute', action='store_true', help='Actually execute the command (default: dry-run)')
    ap.add_argument('--path', help='Custom path to scan_commands.json')
    ap.add_argument('--verify-checksum', action='store_true', help='Verify SHA-256 of scan_commands.json before loading')
    args = ap.parse_args()

    json_path = Path(args.path) if args.path else DEFAULT_JSON
    if args.verify_checksum:
        if not verify_checksum(json_path):
            raise SystemExit(1)

    commands = load_commands(json_path)
    if args.list:
        cmds = get_commands_by_platform(commands, args.platform)
        for c in cmds:
            print_command(c)
        return

    if args.id:
        cmd = find_command_by_id(commands, args.id)
        if not cmd:
            print(f'Command id {args.id} not found')
            return
        print('Command (dry-run):')
        print(cmd.get('command'))
        if cmd.get('requires_admin'):
            print('\nNOTE: This command requires admin privileges. Execution is not recommended in non-admin mode.')
            return
        if args.execute:
            print('\nExecuting...')
            res = run_command(cmd.get('command'), execute=True)
            print('Exit code:', res['exit_code'])
            print('stdout:\n', res['stdout'] or '')
            print('stderr:\n', res['stderr'] or '')
        else:
            print('\nDry-run (no execution). Use --execute to run the command explicitly.')
        return

    # default: list summary
    print('Available commands (summary):\n')
    cmds = get_commands_by_platform(commands, args.platform)
    for c in cmds:
        print(f"{c.get('id'):20} | {c.get('platform'):7} | requires_admin={c.get('requires_admin')}")


if __name__ == '__main__':
    main()
