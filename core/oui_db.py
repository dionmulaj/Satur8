"""
IEEE OUI Database
Parses the OUI registration file and provides O(1) vendor lookups.

Supports two file formats automatically:

  Format A (plain  — the format shipped with this project):
      E043DB  Shenzhen ViewAt Technology Co.,Ltd.
      CC46D6  Cisco Systems, Inc

  Format B (classic IEEE download from https://standards-oui.ieee.org/oui/oui.txt):
      00-00-0C   (hex)\t\tCisco Systems, Inc
      00000C     (base 16)\t\tCisco Systems, Inc

Place the file at the project root as  oui.txt  (or call load() with an explicit path).
"""

import os
import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

_oui_map: dict[str, str] = {}
_loaded   = False
_source   = 'not loaded'

_DEFAULT_PATHS = [
    os.path.join(os.path.dirname(__file__), '..', 'oui.txt'),
    os.path.join(os.path.dirname(__file__), '..', 'oui', 'oui.txt'),
    'oui.txt',
]

_RE_PLAIN = re.compile(r'^([0-9A-Fa-f]{6})\s+(.+)$')
_RE_IEEE  = re.compile(r'^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$')


def _parse_line(line: str):
    line = line.rstrip()
    m = _RE_PLAIN.match(line)
    if m and '(hex)' not in line and '(base 16)' not in line:
        return m.group(1).upper(), m.group(2).strip()
    m = _RE_IEEE.match(line)
    if m:
        return m.group(1).replace('-', '').upper(), m.group(2).strip()
    return None


def load(path: Optional[str] = None) -> int:
    global _oui_map, _loaded, _source

    candidates = [path] if path else _DEFAULT_PATHS
    chosen = None
    for c in candidates:
        if c and os.path.isfile(c):
            chosen = os.path.abspath(c)
            break

    if not chosen:
        logger.warning(
            'IEEE OUI file not found. Vendor lookups will return "Unknown". '
            'Place oui.txt in the project root.'
        )
        return 0

    count = 0
    new_map: dict[str, str] = {}
    try:
        with open(chosen, 'r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                result = _parse_line(line)
                if result:
                    oui_key, vendor = result
                    new_map[oui_key] = vendor
                    count += 1
    except Exception as exc:
        logger.error(f'Failed to load OUI file {chosen}: {exc}')
        return 0

    _oui_map = new_map
    _loaded  = True
    _source  = chosen
    logger.info(f'Loaded {count:,} OUI entries from {chosen}')
    return count


def lookup(mac: str) -> str:
    global _loaded
    if not _loaded:
        load() 

    try:
        flat = re.sub(r'[^0-9A-Fa-f]', '', mac).upper()
        if len(flat) < 6:
            return 'Unknown'
        return _oui_map.get(flat[:6], 'Unknown')
    except Exception:
        return 'Unknown'


def is_loaded() -> bool:
    return _loaded


def entry_count() -> int:
    return len(_oui_map)


def source_path() -> str:
    return _source
