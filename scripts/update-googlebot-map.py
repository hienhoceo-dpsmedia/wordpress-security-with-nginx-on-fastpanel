#!/usr/bin/env python3

"""
Fetch the official Google crawler IP ranges and render them as an nginx map include.

This script powers the Googlebot spoofing protection that ships with the
WordPress Security with Nginx on FastPanel project.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import pathlib
import shutil
import sys
import tempfile
import textwrap
import urllib.error
import urllib.request
from typing import Iterable, List

DEFAULT_DATA_URLS = (
    "https://developers.google.com/search/apis/ipranges/googlebot.json",
    "https://developers.google.com/static/search/apis/ipranges/special-crawlers.json",
    "https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json",
    "https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json",
)
DEFAULT_MAP_PATH = "/etc/nginx/fastpanel2-includes/googlebot-verified.map"
DEFAULT_HTTP_INCLUDE_PATH = "/etc/nginx/fastpanel2-includes/googlebot-verify-http.mapinc"


class GooglebotMapError(Exception):
    """Raised when the Googlebot map cannot be generated."""


def fetch_json(url: str) -> dict:
    """Download and decode JSON from the supplied URL."""
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            if resp.status != 200:
                raise GooglebotMapError(f"Failed to fetch {url} (HTTP {resp.status})")
            payload = resp.read()
    except urllib.error.URLError as exc:
        raise GooglebotMapError(f"Failed to fetch {url}: {exc}") from exc

    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise GooglebotMapError(f"Invalid JSON from {url}: {exc}") from exc


def extract_prefixes(data: dict) -> List[str]:
    """Extract raw IPv4 and IPv6 prefixes from a Google crawler payload."""
    prefixes = data.get("prefixes")
    if not isinstance(prefixes, list):
        raise GooglebotMapError("JSON payload missing 'prefixes' array")

    result: List[str] = []
    for entry in prefixes:
        if not isinstance(entry, dict):
            continue
        ipv4 = entry.get("ipv4Prefix")
        ipv6 = entry.get("ipv6Prefix")
        if ipv4:
            result.append(str(ipv4))
        if ipv6:
            result.append(str(ipv6))

    return result


def dedupe_and_sort_prefixes(prefixes: Iterable[str]) -> List[str]:
    """Remove duplicates while ensuring IPv4 blocks appear before IPv6."""
    seen = set()
    ipv4: List[str] = []
    ipv6: List[str] = []

    for prefix in prefixes:
        if prefix in seen:
            continue
        seen.add(prefix)
        if ":" in prefix:
            ipv6.append(prefix)
        else:
            ipv4.append(prefix)

    ipv4_sorted = sorted(ipv4)
    ipv6_sorted = sorted(ipv6)
    combined = ipv4_sorted + ipv6_sorted
    if not combined:
        raise GooglebotMapError("No Google crawler prefixes discovered across all sources")
    return combined


def write_file_atomic(path: pathlib.Path, lines: Iterable[str]) -> None:
    """Write a file atomically (to avoid partially-written output)."""
    path.parent.mkdir(parents=True, exist_ok=True)

    content = "".join(lines)
    tmp_fd, tmp_path = tempfile.mkstemp(prefix=path.name, dir=str(path.parent))
    try:
        with open(tmp_fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        shutil.move(tmp_path, path)
        path.chmod(0o644)
    finally:
        try:
            pathlib.Path(tmp_path).unlink(missing_ok=True)  # type: ignore[attr-defined]
        except TypeError:
            # Python < 3.8 compatibility (missing_ok not available)
            if pathlib.Path(tmp_path).exists():
                pathlib.Path(tmp_path).unlink()


def render_map_file(prefixes: Iterable[str], data_urls: Iterable[str]) -> List[str]:
    timestamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    header_lines = ["# Auto-generated Google crawler CIDR map"]
    header_lines.extend(f"# Source: {url}" for url in data_urls)
    header_lines.append(f"# Generated: {timestamp}")
    header_lines.append("")
    lines = ["\n".join(header_lines)]
    for prefix in prefixes:
        lines.append(f"{prefix} 1;\n")
    return lines


def render_http_include(map_path: pathlib.Path) -> List[str]:
    timestamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    content = textwrap.dedent(
        f"""\
        # Auto-generated Googlebot verification rules
        # Generated: {timestamp}

        geo $is_verified_googlebot {{
            default 0;
            include {map_path};
        }}

        map $http_user_agent $ua_is_googlebot {{
            default 0;
            "~*Googlebot" 1;
            "~*Google-InspectionTool" 1;
            "~*GoogleOther" 1;
            "~*Google-Site-Verification" 1;
            "~*AdsBot-Google" 1;
            "~*AdsBot-Google-Mobile" 1;
            "~*APIs-Google" 1;
            "~*Mediapartners-Google" 1;
            "~*Feedfetcher-Google" 1;
        }}
        """
    )
    return [content]


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate the Googlebot verification map for nginx."
    )
    parser.add_argument(
        "--data-url",
        dest="data_urls",
        action="append",
        metavar="URL",
        help=(
            "JSON endpoint for Google crawler IP ranges. "
            "Specify multiple times to override the default source list."
        ),
    )
    parser.add_argument(
        "--map-path",
        default=DEFAULT_MAP_PATH,
        help="Destination path for the nginx map include (default: %(default)s)",
    )
    parser.add_argument(
        "--http-include-path",
        default=DEFAULT_HTTP_INCLUDE_PATH,
        help="Destination path for the nginx http-level include (default: %(default)s)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress informational output (errors still displayed)",
    )
    return parser.parse_args(list(argv))


def main(argv: Iterable[str]) -> int:
    args = parse_args(argv)
    map_path = pathlib.Path(args.map_path)
    http_include_path = pathlib.Path(args.http_include_path)

    data_urls = args.data_urls or list(DEFAULT_DATA_URLS)

    combined_prefixes: List[str] = []
    for data_url in data_urls:
        data = fetch_json(data_url)
        prefixes = extract_prefixes(data)
        if not prefixes:
            raise GooglebotMapError(f"No prefixes discovered in payload from {data_url}")
        combined_prefixes.extend(prefixes)

    prefixes = dedupe_and_sort_prefixes(combined_prefixes)

    write_file_atomic(map_path, render_map_file(prefixes, data_urls))
    write_file_atomic(http_include_path, render_http_include(map_path))

    if not args.quiet:
        print(f"[googlebot-map] Wrote {len(prefixes)} prefix entries to {map_path}")
        print(f"[googlebot-map] Updated http include at {http_include_path}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except GooglebotMapError as exc:
        print(f"[googlebot-map] ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
