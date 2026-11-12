"""Synthetic log generator.

Produces realistic access-log lines in the LogScope application format, e.g.::

    2026-11-11T14:23:01Z WARNING 203.0.113.7 POST /login 401 - Failed login for user "admin"

Every scenario is deterministic for a given ``seed`` and ``start`` so tests are
repeatable. Suspicious traffic always comes from the documentation-only IP
ranges 203.0.113.0/24 and 198.51.100.0/24 (RFC 5737), so generated data can
never be mistaken for a real third party.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

Event = tuple[datetime, str]

MIN_ENTRIES = 200
MAX_ENTRIES = 20000

SCENARIOS: dict[str, dict[str, str]] = {
    "normal": {
        "label": "Normal traffic",
        "description": "Ordinary visitors browsing pages and using the API.",
        "expect": "no suspicious patterns.",
    },
    "failed_logins": {
        "label": "Failed login attempts",
        "description": "Many users occasionally mistype their password, and one client keeps retrying.",
        "expect": "one low-severity brute-force pattern.",
    },
    "brute_force": {
        "label": "Password guessing",
        "description": "Two clients try to log in again and again within a few minutes (brute-force-like).",
        "expect": "brute-force patterns for two IP addresses.",
    },
    "scan_404": {
        "label": "Many 'page not found' errors",
        "description": "One client requests lots of pages that don't exist, such as /wp-admin or /.env.",
        "expect": "an 'excessive 404 responses' pattern.",
    },
    "server_errors": {
        "label": "Server errors",
        "description": "For a short time the server fails and answers with 500, 502 and 503 errors.",
        "expect": "a server error spike.",
    },
    "high_volume": {
        "label": "Very high request volume",
        "description": "One client sends several requests every second for minutes.",
        "expect": "an 'unusually high request volume' pattern.",
    },
    "mixed": {
        "label": "Mixed traffic (recommended)",
        "description": "Normal traffic plus every situation above. Best for a first try or a demo.",
        "expect": "four different suspicious patterns.",
    },
}

NORMAL_ENDPOINTS = [
    ("GET", "/"), ("GET", "/products"), ("GET", "/products/42"), ("GET", "/products/17"),
    ("GET", "/cart"), ("POST", "/cart/items"), ("GET", "/api/v1/orders"), ("POST", "/api/v1/orders"),
    ("GET", "/api/v1/users/me"), ("PUT", "/api/v1/users/me"), ("GET", "/static/app.js"),
    ("GET", "/static/styles.css"), ("GET", "/search?q=laptop"), ("GET", "/about"), ("POST", "/login"),
    ("POST", "/logout"), ("GET", "/healthz"), ("DELETE", "/cart/items/3"),
]
PROBE_PATHS = [
    "/wp-admin", "/wp-login.php", "/.env", "/.git/config", "/phpmyadmin", "/admin.php",
    "/backup.zip", "/db.sql", "/config.php.bak", "/server-status", "/cgi-bin/test.cgi",
    "/api/v1/debug", "/old", "/test", "/admin/login", "/xmlrpc.php", "/.aws/credentials",
]
USERNAMES = ["admin", "root", "alice", "bob", "carol", "dave", "support", "test", "guest", "operator"]
SERVER_ERRORS = [
    (500, "ERROR", "Unhandled exception while processing request"),
    (502, "ERROR", "Bad gateway: upstream connection refused"),
    (503, "CRITICAL", "Service unavailable: database connection pool exhausted"),
]


def generate_logs(
    scenario: str, count: int, seed: int | None = None, start: datetime | None = None
) -> list[str]:
    """Return about ``count`` log lines for ``scenario``, sorted by time.

    Raises:
        ValueError: for an unknown scenario or a count outside the allowed range.
    """
    if scenario not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario!r}")
    if not isinstance(count, int) or not MIN_ENTRIES <= count <= MAX_ENTRIES:
        raise ValueError(f"count must be between {MIN_ENTRIES} and {MAX_ENTRIES}")

    rng = random.Random(seed)
    # Normal traffic spreads over ~2 seconds per entry (at least 30 minutes).
    duration = max(1800, count * 2)
    if start is None:
        now = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
        start = now - timedelta(seconds=duration)

    events = _build_scenario(rng, scenario, count, start, duration)
    events.sort(key=lambda event: event[0])
    return [line for _, line in events]


def _build_scenario(rng: random.Random, scenario: str, count: int, start: datetime, duration: int) -> list[Event]:
    """Mix normal background traffic with the scenario's suspicious portion."""
    def portion(share: float) -> int:
        return max(10, int(count * share))

    def attack_start() -> datetime:
        return start + timedelta(seconds=rng.randint(duration // 5, duration // 2))

    if scenario == "normal":
        return _normal_traffic(rng, count, start, duration)
    if scenario == "failed_logins":
        n = portion(0.25)
        return (_normal_traffic(rng, count - n, start, duration)
                + _scattered_failed_logins(rng, n - 8, start, duration)
                + _brute_force(rng, 8, attack_start(), "198.51.100.23", gap=(8, 20)))
    if scenario == "brute_force":
        n = portion(0.2)
        return (_normal_traffic(rng, count - n, start, duration)
                + _brute_force(rng, n * 2 // 3, attack_start(), "203.0.113.45")
                + _brute_force(rng, n - n * 2 // 3, attack_start(), "198.51.100.77"))
    if scenario == "scan_404":
        n = portion(0.2)
        return _normal_traffic(rng, count - n, start, duration) + _path_scan(rng, n, attack_start(), "203.0.113.99")
    if scenario == "server_errors":
        n = portion(0.15)
        return _normal_traffic(rng, count - n, start, duration) + _server_error_burst(rng, n, attack_start())
    if scenario == "high_volume":
        n = max(200, int(count * 0.35))
        n = min(n, count - 10)
        return _normal_traffic(rng, count - n, start, duration) + _request_flood(rng, n, attack_start(), "198.51.100.150")

    # mixed: every pattern in smaller portions
    n = max(15, int(count * 0.06))
    flood = max(130, int(count * 0.15))
    suspicious = (
        _brute_force(rng, n, attack_start(), "203.0.113.45")
        + _path_scan(rng, n + 10, attack_start(), "203.0.113.99")
        + _server_error_burst(rng, n, attack_start())
        + _request_flood(rng, flood, attack_start(), "198.51.100.150")
        + _scattered_failed_logins(rng, n // 2, start, duration)
    )
    return _normal_traffic(rng, max(10, count - len(suspicious)), start, duration) + suspicious


def _line(moment: datetime, level: str, ip: str, method: str, endpoint: str, status: int, message: str) -> Event:
    return moment, f"{moment:%Y-%m-%dT%H:%M:%S}Z {level} {ip} {method} {endpoint} {status} - {message}"


def _client_pool(rng: random.Random, size: int) -> list[str]:
    """Private-network client addresses for normal users."""
    return [
        rng.choice([f"192.168.{rng.randint(0, 20)}.{rng.randint(2, 254)}",
                    f"10.0.{rng.randint(0, 50)}.{rng.randint(2, 254)}",
                    f"172.16.{rng.randint(0, 31)}.{rng.randint(2, 254)}"])
        for _ in range(size)
    ]


def _normal_traffic(rng: random.Random, n: int, start: datetime, duration: int) -> list[Event]:
    clients = _client_pool(rng, max(20, n // 25))
    events = []
    for _ in range(max(0, n)):
        moment = start + timedelta(seconds=rng.randint(0, duration))
        method, endpoint = rng.choice(NORMAL_ENDPOINTS)
        roll = rng.random()
        if roll < 0.90:
            status = 201 if method == "POST" and endpoint != "/login" else rng.choice([200, 200, 200, 304])
            level, message = "INFO", f"Request completed in {rng.randint(4, 380)} ms"
        elif roll < 0.95:
            endpoint, status, level, message = rng.choice(["/products/999", "/favicon.ico", "/img/banner.png"]), 404, "WARNING", "Resource not found"
            method = "GET"
        elif roll < 0.98:
            status, level, message = rng.choice([400, 403]), "WARNING", "Request rejected by validation"
        elif roll < 0.995:
            method, endpoint, status, level = "POST", "/login", 401, "WARNING"
            message = f'Failed login for user "{rng.choice(USERNAMES)}"'
        else:
            status, level, message = 500, "ERROR", "Unhandled exception while processing request"
        events.append(_line(moment, level, rng.choice(clients), method, endpoint, status, message))
    return events


def _scattered_failed_logins(rng: random.Random, n: int, start: datetime, duration: int) -> list[Event]:
    """Failed logins spread over the whole period: each IP stays below the threshold."""
    clients = _client_pool(rng, max(10, n // 2))
    return [
        _line(start + timedelta(seconds=rng.randint(0, duration)), "WARNING", rng.choice(clients),
              "POST", "/login", 401, f'Failed login for user "{rng.choice(USERNAMES)}"')
        for _ in range(max(0, n))
    ]


def _brute_force(rng: random.Random, n: int, moment: datetime, ip: str, gap: tuple[int, int] = (1, 4)) -> list[Event]:
    events = []
    for i in range(max(0, n)):
        moment += timedelta(seconds=rng.randint(*gap))
        user = rng.choice(USERNAMES[:4])
        if i == n - 1 and n > 20:  # long campaigns sometimes end with a success
            events.append(_line(moment, "INFO", ip, "POST", "/login", 200, f'Login successful for user "{user}"'))
        else:
            events.append(_line(moment, "WARNING", ip, "POST", "/login", 401, f'Failed login for user "{user}"'))
    return events


def _path_scan(rng: random.Random, n: int, moment: datetime, ip: str) -> list[Event]:
    events = []
    for _ in range(max(0, n)):
        moment += timedelta(seconds=rng.randint(0, 3))
        events.append(_line(moment, "WARNING", ip, rng.choice(["GET", "GET", "HEAD", "POST"]),
                            rng.choice(PROBE_PATHS), 404, "Resource not found"))
    return events


def _server_error_burst(rng: random.Random, n: int, moment: datetime) -> list[Event]:
    """An outage: many clients receive 5xx responses within a couple of minutes."""
    clients = _client_pool(rng, 30)
    events = []
    for _ in range(max(0, n)):
        offset = timedelta(seconds=rng.randint(0, max(60, n // 2)))
        status, level, message = rng.choice(SERVER_ERRORS)
        method, endpoint = rng.choice(NORMAL_ENDPOINTS[:10])
        events.append(_line(moment + offset, level, rng.choice(clients), method, endpoint, status, message))
    return events


def _request_flood(rng: random.Random, n: int, moment: datetime, ip: str) -> list[Event]:
    """Roughly 3-4 requests per second from a single client."""
    events = []
    for i in range(max(0, n)):
        moment += timedelta(seconds=1) if i % rng.randint(3, 4) == 0 else timedelta(0)
        method, endpoint = rng.choice(NORMAL_ENDPOINTS[:7])
        events.append(_line(moment, "INFO", ip, method, endpoint, 200, f"Request completed in {rng.randint(2, 40)} ms"))
    return events
