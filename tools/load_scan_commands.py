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
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_JSON = ROOT / 'reports' / 'scan_commands.json'


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
    If execute==True, actually run the command (caller is responsible to ensure safety).
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

    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
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
    ap.add_argument('--platform', choices=['linux','windows'], help='Filter by platform')
    ap.add_argument('--id', help='Command id to show or execute')
    ap.add_argument('--execute', action='store_true', help='Actually execute the command (default: dry-run)')
    ap.add_argument('--path', help='Custom path to scan_commands.json')
    args = ap.parse_args()

    commands = load_commands(Path(args.path) if args.path else None)
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
