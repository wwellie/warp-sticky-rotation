#!/usr/bin/env python3
"""Three-exit connection-sticky WARP rotation controller.

Commands:

* ``reconcile`` repairs local state without switching the selector.
* ``tick`` selects the next ready backend for new connections.
* ``drain-refresh TAG`` drains and refreshes one backend.
* ``status`` prints selector, state, and connection counts as JSON.

A draining backend rejects new external SOCKS admissions, preserves established
connections, and refreshes only after both Clash and network-namespace
connection inventories are empty.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
from typing import Any, Callable, Iterator
import urllib.parse
import uuid

RING = ("warp3", "warp4", "warp5")
SELECTOR = "warp-active"
SINGBOX_CONTAINER = "singbox-warp"
SINGBOX_CONFIG_PATH = os.environ.get("WARP_STICKY_SINGBOX_CONFIG", "/etc/sing-box/config.json")
DOCKER_NETWORK = os.environ.get("WARP_STICKY_NETWORK", "").strip()
CLASH_PORT = 9090
CLASH_SECRET_PATH = Path(
    os.environ.get("WARP_STICKY_CLASH_SECRET_FILE", "/etc/warp-sticky-rotation/clash.secret")
)
BACKEND_SOCKS_PORT = 1081
TRACE_URL = os.environ.get("WARP_STICKY_TRACE_URL", "https://www.cloudflare.com/cdn-cgi/trace")
STATE_PATH = Path(os.environ.get("WARP_STICKY_STATE", "/var/lib/warp-sticky-rotate/state.json"))
LOCK_PATH = Path(os.environ.get("WARP_STICKY_LOCK", "/run/warp-sticky-rotate/controller.lock"))
DRAIN_LOCK_DIR = Path(os.environ.get("WARP_STICKY_DRAIN_LOCK_DIR", "/run/warp-sticky-rotate"))
DRAIN_POLL_S = float(os.environ.get("WARP_STICKY_DRAIN_POLL_S", "1"))
DRAIN_ZERO_SAMPLES = int(os.environ.get("WARP_STICKY_DRAIN_ZERO_SAMPLES", "2"))
REFRESH_ATTEMPTS = int(os.environ.get("WARP_STICKY_REFRESH_ATTEMPTS", "3"))
REFRESH_POLL_S = float(os.environ.get("WARP_STICKY_REFRESH_POLL_S", "1"))
REFRESH_READY_TIMEOUT_S = float(os.environ.get("WARP_STICKY_REFRESH_READY_TIMEOUT_S", "120"))
FAILED_RETRY_S = float(os.environ.get("WARP_STICKY_FAILED_RETRY_S", "180"))
SERVICE_TEMPLATE = "warp-sticky-drain-refresh@{tag}.service"
BARRIER_COMMENT = "warp-sticky-draining"
FIREWALL_TOOLS = ("iptables", "ip6tables")
WG_HOOK_PATTERN = r"^[[:space:]]*(PreUp|PreDown|PostUp|PostDown)[[:space:]]*="
FIXED_INBOUND_KEYS = {"type", "tag", "listen", "listen_port"}
FIXED_SELECTOR_KEYS = {"type", "tag", "outbounds", "default", "interrupt_exist_connections"}
FIXED_BACKEND_KEYS = {"type", "tag", "server", "server_port", "version"}

VALID_PHASES = {"unknown", "ready", "active", "draining", "refreshing", "failed"}
CommandRunner = Callable[..., subprocess.CompletedProcess[Any]]
_DOCKER_NETWORK_CACHE: str | None = None



class RuntimeFault(RuntimeError):
    """A live dependency could not be proven safe enough for an action."""


class LockBusy(RuntimeFault):
    """Another controller instance already owns the requested lock."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def log(message: str) -> None:
    stamp = dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    print(f"[{stamp}] {message}", flush=True)


def ordered_after(current: str, ring: tuple[str, ...] = RING) -> list[str]:
    if current not in ring:
        raise ValueError(f"selector outside configured ring: {current}")
    index = ring.index(current)
    return [ring[(index + offset) % len(ring)] for offset in range(1, len(ring))]


def choose_candidate(
    current: str,
    state: dict[str, Any],
    ring: tuple[str, ...] = RING,
    *,
    is_locally_ready: Callable[[str, dict[str, Any]], bool],
) -> str | None:
    tags = state.setdefault("tags", {})
    active_ip = str(tags.get(current, {}).get("ip") or "")
    for tag in ordered_after(current, ring):
        entry = tags.get(tag, {})
        if entry.get("phase") != "ready":
            continue
        if not is_locally_ready(tag, entry):
            continue
        candidate_ip = str(entry.get("ip") or "")
        if not candidate_ip or (active_ip and candidate_ip == active_ip):
            continue
        return tag
    return None


def connection_count_for_tag(payload: dict[str, Any], tag: str) -> int:
    connections = payload.get("connections")
    if not isinstance(connections, list):
        raise ValueError("invalid Clash connections payload")
    count = 0
    for index, connection in enumerate(connections):
        if not isinstance(connection, dict):
            raise ValueError(f"invalid Clash connection record at index {index}")
        chains = connection.get("chains")
        if (
            not isinstance(chains, list)
            or not chains
            or not all(isinstance(item, str) and item.strip() for item in chains)
        ):
            raise ValueError(f"invalid Clash chains at index {index}")
        if tag in chains:
            count += 1
    return count


def select_shared_network(networks_by_container: dict[str, set[str]], configured: str = "") -> str:
    if not networks_by_container or any(not networks for networks in networks_by_container.values()):
        raise ValueError("container network inventory is empty")
    if configured:
        missing = [name for name, networks in networks_by_container.items() if configured not in networks]
        if missing:
            raise ValueError(f"configured Docker network is not shared by: {', '.join(sorted(missing))}")
        return configured
    common = set.intersection(*(set(networks) for networks in networks_by_container.values()))
    if len(common) != 1:
        raise ValueError(f"expected exactly one shared Docker network, found: {sorted(common)}")
    return common.pop()


def default_state(ring: tuple[str, ...] = RING) -> dict[str, Any]:
    return {
        "version": 1,
        "ring": list(ring),
        "active": "",
        "last_switch_at": "",
        "last_switch_ms": None,
        "tags": {
            tag: {"phase": "unknown", "ip": "", "generation": "", "container_id": ""}
            for tag in ring
        },
    }


def normalize_state(state: Any, ring: tuple[str, ...] = RING) -> dict[str, Any]:
    if not isinstance(state, dict) or state.get("version") != 1:
        return default_state(ring)
    if state.get("ring") != list(ring):
        state["ring"] = list(ring)
    tags = state.setdefault("tags", {})
    if not isinstance(tags, dict):
        state["tags"] = tags = {}
    for tag in ring:
        entry = tags.setdefault(tag, {})
        if not isinstance(entry, dict):
            tags[tag] = entry = {}
        if entry.get("phase") not in VALID_PHASES:
            entry["phase"] = "unknown"
        entry.setdefault("ip", "")
        entry.setdefault("generation", "")
        entry.setdefault("container_id", "")
    for tag in list(tags):
        if tag not in ring:
            del tags[tag]
    return state


def begin_drain(entry: dict[str, Any], *, now: float) -> None:
    entry["phase"] = "draining"
    entry["drain_id"] = uuid.uuid4().hex
    entry["drain_generation"] = str(entry.get("generation") or "")
    entry["drain_container_id"] = str(entry.get("container_id") or "")
    entry["demoted_at_epoch"] = now
    entry["demoted_at"] = utc_now()
    entry["old_ip"] = entry.get("ip", "")
    entry["last_connection_count"] = None


def ensure_drain_identity(entry: dict[str, Any], *, now: float) -> None:
    if entry.get("phase") not in {"draining", "refreshing"}:
        return
    entry.setdefault("drain_id", uuid.uuid4().hex)
    entry.setdefault("drain_generation", str(entry.get("generation") or ""))
    entry.setdefault("drain_container_id", str(entry.get("container_id") or ""))
    entry.setdefault("demoted_at_epoch", now)
    entry.setdefault("demoted_at", utc_now())
    entry.setdefault("old_ip", entry.get("ip", ""))


def clear_drain_identity(entry: dict[str, Any]) -> None:
    for key in (
        "drain_id",
        "drain_generation",
        "drain_container_id",
        "demoted_at_epoch",
        "demoted_at",
        "admission_barrier_at",
    ):
        entry.pop(key, None)


def mark_identity_change_failed(
    entry: dict[str, Any],
    *,
    generation: str,
    container_id: str,
    reason: str,
    now: float,
) -> None:
    entry.update(
        {
            "phase": "failed",
            "ip": "",
            "generation": generation,
            "container_id": container_id,
            "last_error": reason,
            "failed_at": utc_now(),
            "retry_after": now + FAILED_RETRY_S,
        }
    )
    clear_drain_identity(entry)


def recover_failed_entry(state: dict[str, Any], tag: str, *, now: float) -> bool:
    entry = state["tags"][tag]
    if entry.get("phase") != "failed" or float(entry.get("retry_after", 0) or 0) > now:
        return False
    running, generation, container_id = container_identity(tag)
    if not running or not generation or not container_id:
        mark_identity_change_failed(
            entry,
            generation=generation,
            container_id=container_id,
            reason="container_not_running_during_failed_recovery",
            now=now,
        )
        return False
    try:
        install_admission_barrier(container_id)
        ip, probed_generation = probe_backend(tag, container_ref=container_id)
        name_running, name_generation, name_container_id = container_identity(tag)
        if (
            not name_running
            or probed_generation != generation
            or name_generation != generation
            or name_container_id != container_id
        ):
            raise RuntimeFault(f"backend {tag} identity changed during failed recovery")
        remove_admission_barrier(container_id)
    except RuntimeFault as exc:
        mark_identity_change_failed(
            entry,
            generation=generation,
            container_id=container_id,
            reason=str(exc),
            now=now,
        )
        return False
    entry.update(
        {
            "phase": "ready",
            "ip": ip,
            "generation": generation,
            "container_id": container_id,
            "last_verified_at": utc_now(),
        }
    )
    entry.pop("retry_after", None)
    entry.pop("last_error", None)
    entry.pop("failed_at", None)
    clear_drain_identity(entry)
    return True


def reconcile_selector_state(
    state: dict[str, Any],
    current: str,
    ring: tuple[str, ...] = RING,
    *,
    now: float,
) -> list[str]:
    if current not in ring:
        raise ValueError(f"selector outside configured ring: {current}")
    tags = state.setdefault("tags", {})
    pending: list[str] = []
    for tag in ring:
        entry = tags.setdefault(tag, {"phase": "unknown", "ip": "", "generation": ""})
        previous = entry.get("phase", "unknown")
        if tag == current:
            entry["phase"] = "active"
            entry.pop("retry_after", None)
            entry.pop("drain_id", None)
            entry.pop("drain_generation", None)
            entry.pop("drain_container_id", None)
            continue
        if previous == "active":
            begin_drain(entry, now=now)
        elif entry.get("phase") in {"draining", "refreshing"}:
            ensure_drain_identity(entry, now=now)
        if entry.get("phase") in {"draining", "refreshing"}:
            pending.append(tag)

    state["active"] = current
    return pending


def apply_switch(
    state: dict[str, Any],
    *,
    old: str,
    new: str,
    now: float,
    switch_ms: float,
) -> None:
    tags = state["tags"]
    old_entry = tags[old]
    new_entry = tags[new]
    begin_drain(old_entry, now=now)
    new_entry["phase"] = "active"
    new_entry.pop("retry_after", None)
    new_entry.pop("drain_id", None)
    new_entry.pop("drain_generation", None)
    new_entry.pop("drain_container_id", None)
    state["active"] = new
    state["last_switch_at"] = utc_now()
    state["last_switch_epoch"] = now
    state["last_switch_ms"] = round(switch_ms, 3)
    state["last_switch"] = {"old": old, "new": new}


@contextlib.contextmanager
def file_lock(path: Path, *, nonblocking: bool = False) -> Iterator[Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as handle:
        flags = fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0)
        try:
            fcntl.flock(handle.fileno(), flags)
        except BlockingIOError as exc:
            raise LockBusy(f"lock busy: {path}") from exc
        try:
            yield handle
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def load_state(path: Path = STATE_PATH) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default_state()
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeFault(f"state unreadable: {path}: {exc}") from exc
    return normalize_state(raw)


def save_state(state: dict[str, Any], path: Path = STATE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(normalize_state(state), ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, path)
        dir_fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temp_name)


def run_command(
    argv: list[str],
    *,
    timeout: float,
    check: bool = False,
    input_text: str | None = None,
    binary: bool = False,
    runner: CommandRunner = subprocess.run,
) -> subprocess.CompletedProcess[Any]:
    return runner(
        argv,
        capture_output=True,
        text=not binary,
        timeout=timeout,
        check=check,
        input=input_text.encode("utf-8") if binary and input_text is not None else input_text,
    )


def docker_network() -> str:
    global _DOCKER_NETWORK_CACHE
    if _DOCKER_NETWORK_CACHE:
        return _DOCKER_NETWORK_CACHE
    networks_by_container: dict[str, set[str]] = {}
    for container in (SINGBOX_CONTAINER, *RING):
        proc = run_command(
            ["docker", "inspect", "-f", "{{json .NetworkSettings.Networks}}", container],
            timeout=5,
        )
        try:
            payload = json.loads(proc.stdout) if proc.returncode == 0 else None
        except json.JSONDecodeError as exc:
            raise RuntimeFault(f"invalid Docker network inventory for {container}") from exc
        if not isinstance(payload, dict):
            raise RuntimeFault(f"Docker network inventory unavailable for {container}")
        networks_by_container[container] = set(payload)
    try:
        _DOCKER_NETWORK_CACHE = select_shared_network(networks_by_container, DOCKER_NETWORK)
    except ValueError as exc:
        raise RuntimeFault(str(exc)) from exc
    return _DOCKER_NETWORK_CACHE


def container_identity(ref: str) -> tuple[bool, str, str]:
    proc = run_command(
        ["docker", "inspect", "-f", "{{.Id}}|{{.State.Running}}|{{.State.StartedAt}}", ref],
        timeout=5,
    )
    if proc.returncode != 0:
        return False, "", ""
    container_id, first, remainder = proc.stdout.strip().partition("|")
    running, second, generation = remainder.partition("|")
    if not first or not second or len(container_id) != 64 or any(ch not in "0123456789abcdef" for ch in container_id):
        return False, "", ""
    return running == "true", generation, container_id


def container_info(ref: str) -> tuple[bool, str]:
    running, generation, _container_id = container_identity(ref)
    return running, generation


def _barrier_rule_argv(tag: str, firewall: str, operation: str) -> list[str]:
    if tag not in RING and not (
        len(tag) == 64 and all(ch in "0123456789abcdef" for ch in tag)
    ):
        raise ValueError(f"invalid backend container reference: {tag}")
    if firewall not in FIREWALL_TOOLS or operation not in {"-C", "-I", "-D"}:
        raise ValueError("invalid admission barrier command")
    argv = [
        "docker",
        "exec",
        tag,
        firewall,
        "-w",
        "2",
        operation,
        "INPUT",
    ]
    if operation == "-I":
        argv.append("1")
    argv.extend(
        [
            "!",
            "-i",
            "lo",
            "-p",
            "tcp",
            "--dport",
            str(BACKEND_SOCKS_PORT),
            "-m",
            "conntrack",
            "--ctstate",
            "NEW",
            "-m",
            "comment",
            "--comment",
            BARRIER_COMMENT,
            "-j",
            "REJECT",
            "--reject-with",
            "tcp-reset",
        ]
    )
    return argv


def install_admission_barrier(tag: str) -> None:
    for firewall in FIREWALL_TOOLS:
        check = run_command(_barrier_rule_argv(tag, firewall, "-C"), timeout=5)
        if check.returncode == 0:
            continue
        if check.returncode != 1:
            raise RuntimeFault(
                f"backend {tag} {firewall} admission barrier check failed: {check.stderr.strip()}"
            )
        insert = run_command(_barrier_rule_argv(tag, firewall, "-I"), timeout=5)
        if insert.returncode != 0:
            raise RuntimeFault(
                f"backend {tag} {firewall} admission barrier install failed: {insert.stderr.strip()}"
            )
        verify = run_command(_barrier_rule_argv(tag, firewall, "-C"), timeout=5)
        if verify.returncode != 0:
            raise RuntimeFault(f"backend {tag} {firewall} admission barrier verification failed")


def verify_admission_barrier(tag: str) -> None:
    for firewall in FIREWALL_TOOLS:
        verify = run_command(_barrier_rule_argv(tag, firewall, "-C"), timeout=5)
        if verify.returncode != 0:
            raise RuntimeFault(f"backend {tag} {firewall} admission barrier is not continuous")


def remove_admission_barrier(tag: str) -> None:
    for firewall in FIREWALL_TOOLS:
        for _ in range(4):
            check = run_command(_barrier_rule_argv(tag, firewall, "-C"), timeout=5)
            if check.returncode == 1:
                break
            if check.returncode != 0:
                raise RuntimeFault(
                    f"backend {tag} {firewall} admission barrier check failed: {check.stderr.strip()}"
                )
            delete = run_command(_barrier_rule_argv(tag, firewall, "-D"), timeout=5)
            if delete.returncode != 0:
                raise RuntimeFault(
                    f"backend {tag} {firewall} admission barrier removal failed: {delete.stderr.strip()}"
                )
        else:
            raise RuntimeFault(f"backend {tag} {firewall} admission barrier has duplicate rules")


def backend_client_connection_count(tag: str) -> int:
    proc = run_command(
        [
            "docker",
            "exec",
            tag,
            "ss",
            "-Hnt",
            "state",
            "connected",
            f"( sport = :{BACKEND_SOCKS_PORT} )",
        ],
        timeout=5,
    )
    if proc.returncode != 0:
        raise RuntimeFault(f"backend {tag} socket inventory unavailable: {proc.stderr.strip()}")
    return sum(1 for line in proc.stdout.splitlines() if line.strip())


def clash_secret() -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(CLASH_SECRET_PATH, flags)
        with os.fdopen(descriptor, encoding="utf-8") as stream:
            metadata = os.fstat(stream.fileno())
            content = stream.read(4097)
    except (OSError, UnicodeError) as exc:
        raise RuntimeFault(f"Clash secret file unavailable: {CLASH_SECRET_PATH}") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise RuntimeFault(
            f"Clash secret file must be a regular file with mode 0600: {CLASH_SECRET_PATH}"
        )
    secret = content.strip()
    if metadata.st_uid != os.geteuid() or not secret or len(content) > 4096:
        raise RuntimeFault(
            f"Clash secret file ownership or content is invalid: {CLASH_SECRET_PATH}"
        )
    if "\r" in secret or "\n" in secret:
        raise RuntimeFault("Clash API secret contains forbidden line breaks")
    return secret


def clash_request(path: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> Any:
    if not path.startswith("/") or "\r" in path or "\n" in path:
        raise ValueError("invalid Clash API path")
    if method not in {"GET", "PUT", "DELETE"}:
        raise ValueError("invalid Clash API method")
    body = "" if payload is None else json.dumps(payload, separators=(",", ":"))
    request = (
        f"{method} {path} HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        f"Authorization: Bearer {clash_secret()}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body.encode('utf-8'))}\r\n"
        "Connection: close\r\n"
        "\r\n"
        f"{body}"
    )
    proc = run_command(
        [
            "docker",
            "exec",
            "-i",
            SINGBOX_CONTAINER,
            "nc",
            "-w",
            "5",
            "127.0.0.1",
            str(CLASH_PORT),
        ],
        timeout=8,
        input_text=request,
        binary=True,
    )
    if proc.returncode != 0:
        raise RuntimeFault(f"Clash API {method} {path} transport failed")
    invalid_response = f"Clash API {method} {path} returned an invalid HTTP response"
    raw_response = proc.stdout
    if not isinstance(raw_response, bytes):
        raise RuntimeFault(invalid_response)
    head, separator, response_body = raw_response.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not separator or not lines:
        raise RuntimeFault(invalid_response)
    status_match = re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3}) ([\t\x20-\x7e]*)", lines[0])
    if status_match is None:
        raise RuntimeFault(invalid_response)
    headers: dict[bytes, bytes] = {}
    for line in lines[1:]:
        if not line or line[:1] in {b" ", b"\t"} or b":" not in line:
            raise RuntimeFault(invalid_response)
        name, value = line.split(b":", 1)
        if re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is None:
            raise RuntimeFault(invalid_response)
        key = name.lower()
        if key in headers or any(byte != 0x09 and not 0x20 <= byte <= 0x7E for byte in value):
            raise RuntimeFault(invalid_response)
        headers[key] = value.strip(b" \t")
    if b"transfer-encoding" in headers:
        raise RuntimeFault(invalid_response)
    content_length = headers.get(b"content-length")
    if content_length is None:
        if response_body:
            raise RuntimeFault(invalid_response)
    elif re.fullmatch(rb"[0-9]+", content_length) is None or len(response_body) != int(content_length):
        raise RuntimeFault(invalid_response)
    status_code = int(status_match.group(1))
    if status_code in {204, 205} and response_body:
        raise RuntimeFault(invalid_response)
    if status_code < 200 or status_code >= 300:
        raise RuntimeFault(f"Clash API {method} {path} returned HTTP {status_code}")
    if not response_body:
        return None
    try:
        return json.loads(response_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeFault(f"Clash API {method} {path} returned invalid JSON") from exc


def validate_singbox_config(payload: Any, *, expected_secret: str) -> None:
    if not isinstance(payload, dict):
        raise RuntimeFault("invalid sing-box configuration")
    inbounds = payload.get("inbounds")
    if not isinstance(inbounds, list):
        raise RuntimeFault("sing-box SOCKS inbound is unavailable")
    fixed_inbounds = [
        item
        for item in inbounds
        if isinstance(item, dict)
        and item.get("type") == "socks"
        and item.get("listen") in {"0.0.0.0", "::"}
        and item.get("listen_port") == 1081
    ]
    if len(inbounds) != 1 or len(fixed_inbounds) != 1:
        raise RuntimeFault("sing-box must expose exactly one SOCKS inbound on wildcard port 1081")
    if set(fixed_inbounds[0]) != FIXED_INBOUND_KEYS:
        raise RuntimeFault("sing-box SOCKS inbound contains unsupported topology fields")

    outbounds = payload.get("outbounds")
    if not isinstance(outbounds, list) or len(outbounds) != 4:
        raise RuntimeFault("invalid sing-box outbound configuration")
    selector_matches = [
        item
        for item in outbounds
        if isinstance(item, dict) and item.get("type") == "selector" and item.get("tag") == SELECTOR
    ]
    if len(selector_matches) != 1:
        raise RuntimeFault(f"sing-box selector {SELECTOR!r} must be defined exactly once")
    configured = selector_matches[0]
    if set(configured) != FIXED_SELECTOR_KEYS:
        raise RuntimeFault("sing-box selector contains unsupported topology fields")
    if configured.get("outbounds") != list(RING):
        raise RuntimeFault(f"sing-box selector outbounds must exactly match fixed ring: {list(RING)}")
    if configured.get("default") not in RING:
        raise RuntimeFault("sing-box selector default must be a member of the fixed ring")
    if configured.get("interrupt_exist_connections") is not False:
        raise RuntimeFault("sing-box selector interrupt_exist_connections must be false")

    for tag in RING:
        matches = [
            item
            for item in outbounds
            if isinstance(item, dict) and item.get("tag") == tag
        ]
        if len(matches) != 1:
            raise RuntimeFault(f"sing-box backend outbound {tag!r} must be defined exactly once")
        backend = matches[0]
        if (
            set(backend) != FIXED_BACKEND_KEYS
            or backend.get("type") != "socks"
            or backend.get("server") != tag
            or backend.get("server_port") != 1081
            or backend.get("version") != "5"
        ):
            raise RuntimeFault(f"sing-box backend outbound {tag!r} must target {tag}:1081 via SOCKS5")

    route = payload.get("route")
    if not isinstance(route, dict) or route.get("final") != SELECTOR:
        raise RuntimeFault(f"sing-box route.final must be {SELECTOR!r}")
    rules = route.get("rules")
    if rules is not None and rules != []:
        raise RuntimeFault("sing-box route.rules must be absent or empty")
    experimental = payload.get("experimental")
    clash_api = experimental.get("clash_api") if isinstance(experimental, dict) else None
    if not isinstance(clash_api, dict):
        raise RuntimeFault("sing-box Clash API configuration is unavailable")
    if clash_api.get("external_controller") != "127.0.0.1:9090":
        raise RuntimeFault("sing-box Clash API must listen on container loopback 127.0.0.1:9090")
    if not expected_secret or clash_api.get("secret") != expected_secret:
        raise RuntimeFault("sing-box Clash API secret must match the controller secret")


def verify_singbox_config() -> None:
    docker_network()
    secret = clash_secret()
    running, generation = container_info(SINGBOX_CONTAINER)
    if not running or not generation:
        raise RuntimeFault(f"{SINGBOX_CONTAINER} is not running")
    config_result = run_command(
        ["docker", "exec", SINGBOX_CONTAINER, "cat", SINGBOX_CONFIG_PATH],
        timeout=5,
    )
    stat_result = run_command(
        ["docker", "exec", SINGBOX_CONTAINER, "stat", "-c", "%y", SINGBOX_CONFIG_PATH],
        timeout=5,
    )
    if config_result.returncode != 0 or stat_result.returncode != 0:
        raise RuntimeFault("sing-box configuration is unavailable inside the container")
    try:
        payload = json.loads(
            config_result.stdout,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"invalid constant: {value}")),
        )
        config_mtime = dt.datetime.fromisoformat(stat_result.stdout.strip()).timestamp()
        started_at = dt.datetime.fromisoformat(generation.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError) as exc:
        raise RuntimeFault("sing-box configuration metadata is invalid") from exc
    validate_singbox_config(payload, expected_secret=secret)
    if config_mtime > started_at:
        raise RuntimeFault("sing-box configuration was modified after the running container started")


def validate_selector_payload(payload: Any, ring: tuple[str, ...] = RING) -> str:
    if not isinstance(payload, dict) or str(payload.get("type") or "").lower() != "selector":
        raise RuntimeFault("invalid Clash selector response")
    outbounds = payload.get("all")
    if outbounds != list(ring):
        raise RuntimeFault(f"selector outbound list must exactly match configured ring: {list(ring)}")
    current = payload.get("now")
    if current not in ring:
        raise RuntimeFault(f"selector is not in three-exit ring: {current!r}")
    return str(current)


def selector_now() -> str:
    selector_path = urllib.parse.quote(SELECTOR, safe="")
    return validate_selector_payload(clash_request(f"/proxies/{selector_path}"))


def selector_set(tag: str) -> None:
    if tag not in RING:
        raise ValueError(f"invalid selector target: {tag}")
    selector_path = urllib.parse.quote(SELECTOR, safe="")
    clash_request(f"/proxies/{selector_path}", method="PUT", payload={"name": tag})


def connections_payload() -> dict[str, Any]:
    payload = clash_request("/connections")
    if not isinstance(payload, dict):
        raise RuntimeFault("invalid Clash connections response")
    return payload


def connections_for_tag(tag: str) -> int:
    try:
        return connection_count_for_tag(connections_payload(), tag)
    except ValueError as exc:
        raise RuntimeFault(str(exc)) from exc


def probe_backend(tag: str, *, container_ref: str | None = None) -> tuple[str, str]:
    if tag not in RING:
        raise ValueError(f"invalid backend: {tag}")
    target = container_ref or tag
    if target not in RING and not (
        len(target) == 64 and all(ch in "0123456789abcdef" for ch in target)
    ):
        raise ValueError(f"invalid backend container reference: {target}")
    running, generation_before = container_info(target)
    if not running or not generation_before:
        raise RuntimeFault(f"backend {tag} is not running")
    proc = run_command(
        [
            "docker",
            "exec",
            "-e",
            "NO_PROXY=",
            "-e",
            "no_proxy=",
            target,
            "curl",
            "--disable",
            "-sS",
            "--max-time",
            "8",
            "--proxy",
            f"socks5h://127.0.0.1:{BACKEND_SOCKS_PORT}",
            "--noproxy",
            "",
            TRACE_URL,
        ],
        timeout=12,
    )
    values: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"ip", "warp"}:
            values[key] = value.strip()
    if proc.returncode != 0 or values.get("warp") != "on" or not values.get("ip"):
        raise RuntimeFault(f"backend {tag} WARP trace unavailable")
    running, generation_after = container_info(target)
    if not running or not generation_after:
        raise RuntimeFault(f"backend {tag} is not running")
    if generation_after != generation_before:
        raise RuntimeFault(f"backend {tag} generation changed during WARP trace")
    return values["ip"], generation_after


def front_socks_path_ready(tag: str) -> bool:
    """Prove the real front-to-backend SOCKS5 protocol path.

    A bare TCP connect is not enough: the frontend must complete method
    negotiation and a CONNECT request against the backend SOCKS listener.
    """
    if tag not in RING:
        raise ValueError(f"invalid backend: {tag}")
    # Fixed IPv4 CONNECT target used only to exercise SOCKS framing.
    # Success is protocol-level (reply status 0x00), not end-to-end HTTP.
    script = (
        "set -euo pipefail\n"
        "read_hex() {\n"
        "  local count=\"$1\" data\n"
        "  data=$(dd bs=1 count=\"$count\" status=none <&3 | od -An -tx1 | tr -d ' \\n')\n"
        "  [ \"${#data}\" -eq \"$((count * 2))\" ] || return 1\n"
        "  printf '%s' \"$data\"\n"
        "}\n"
        f"exec 3<>/dev/tcp/{tag}/{BACKEND_SOCKS_PORT}\n"
        "printf '\\x05\\x01\\x00' >&3\n"
        "method=$(read_hex 2)\n"
        '[ "$method" = "0500" ]\n'
        "printf '\\x05\\x01\\x00\\x01\\x01\\x01\\x01\\x01\\x01\\xbb' >&3\n"
        "header=$(read_hex 4)\n"
        '[ "${header:0:6}" = "050000" ]\n'
        "case \"${header:6:2}\" in\n"
        "  01) read_hex 6 >/dev/null ;;\n"
        "  04) read_hex 18 >/dev/null ;;\n"
        "  03)\n"
        "    domain_length_hex=$(read_hex 1)\n"
        "    domain_length=$((16#$domain_length_hex))\n"
        "    [ \"$domain_length\" -gt 0 ]\n"
        "    read_hex \"$((domain_length + 2))\" >/dev/null\n"
        "    ;;\n"
        "  *) exit 1 ;;\n"
        "esac\n"
        "exec 3>&-\n"
    )
    proc = run_command(
        [
            "docker",
            "exec",
            SINGBOX_CONTAINER,
            "timeout",
            "-k",
            "1",
            "6",
            "bash",
            "-c",
            script,
        ],
        timeout=8,
    )
    return proc.returncode == 0


def locally_ready(tag: str, entry: dict[str, Any]) -> bool:
    container_id = str(entry.get("container_id") or "")
    if len(container_id) != 64 or any(ch not in "0123456789abcdef" for ch in container_id):
        return False
    if not front_socks_path_ready(tag):
        return False
    try:
        ip, generation = probe_backend(tag, container_ref=container_id)
    except RuntimeFault:
        return False
    running, current_generation, current_container_id = container_identity(tag)
    if (
        not running
        or generation != entry.get("generation")
        or current_generation != generation
        or current_container_id != container_id
    ):
        return False
    entry.update({"ip": ip, "last_verified_at": utc_now()})
    return True


def refresh_entry_if_generation_changed(
    state: dict[str, Any], tag: str, *, force_probe: bool = False
) -> None:
    entry = state["tags"][tag]
    running, generation, container_id = container_identity(tag)
    if not running:
        entry["phase"] = "failed"
        entry["ip"] = ""
        entry["generation"] = ""
        entry["container_id"] = ""
        entry["last_error"] = "container_not_running"
        entry["retry_after"] = time.time() + FAILED_RETRY_S
        if force_probe:
            raise RuntimeFault(f"active backend {tag} is not running")
        return
    if (
        not force_probe
        and entry.get("generation") == generation
        and entry.get("container_id") == container_id
        and entry.get("ip")
    ):
        return
    try:
        ip, generation = probe_backend(tag, container_ref=container_id)
    except RuntimeFault as exc:
        entry["phase"] = "failed"
        entry["ip"] = ""
        entry["generation"] = generation
        entry["container_id"] = container_id
        entry["last_error"] = str(exc)
        entry["retry_after"] = time.time() + FAILED_RETRY_S
        if force_probe:
            raise
        return
    name_running, name_generation, name_container_id = container_identity(tag)
    if (
        not name_running
        or name_generation != generation
        or name_container_id != container_id
    ):
        fault = RuntimeFault(f"backend {tag} name no longer maps to the probed container")
        entry["phase"] = "failed"
        entry["ip"] = ""
        entry["generation"] = generation
        entry["container_id"] = container_id
        entry["last_error"] = str(fault)
        entry["retry_after"] = time.time() + FAILED_RETRY_S
        if force_probe:
            raise fault
        return
    entry.update(
        {
            "phase": "ready" if entry.get("phase") != "active" else "active",
            "ip": ip,
            "generation": generation,
            "container_id": container_id,
            "last_verified_at": utc_now(),
        }
    )
    entry.pop("last_error", None)
    entry.pop("retry_after", None)


def start_drain_worker(tag: str) -> bool:
    unit = SERVICE_TEMPLATE.format(tag=tag)
    proc = run_command(["systemctl", "start", "--no-block", unit], timeout=10)
    if proc.returncode != 0:
        log(f"drain worker start failed tag={tag} unit={unit} error={proc.stderr.strip()}")
        return False
    log(f"drain worker queued tag={tag} unit={unit}")
    return True


def reconcile() -> int:
    pending_workers: set[str] = set()
    try:
        with file_lock(LOCK_PATH, nonblocking=True):
            verify_singbox_config()
            current = selector_now()
            remove_admission_barrier(current)
            state = load_state()
            now = time.time()
            pending_workers.update(reconcile_selector_state(state, current, now=now))
            for tag in RING:
                phase = state["tags"][tag].get("phase")
                if phase == "failed":
                    recover_failed_entry(state, tag, now=now)
                    phase = state["tags"][tag].get("phase")
                if tag == current or phase in {"unknown", "ready"}:
                    try:
                        refresh_entry_if_generation_changed(state, tag, force_probe=tag == current)
                    except RuntimeFault:
                        save_state(state)
                        raise
                if tag != current and state["tags"][tag].get("phase") == "draining":
                    pending_workers.add(tag)
            save_state(state)
            phases = ",".join(f"{tag}:{state['tags'][tag].get('phase')}" for tag in RING)
            log(f"state reconciled active={current} phases={phases}")
    except RuntimeFault as exc:
        log(f"reconcile skipped fail-closed: {exc}")
        return 1
    worker_failed = False
    for tag in sorted(pending_workers):
        if tag != current and not start_drain_worker(tag):
            worker_failed = True
    return 1 if worker_failed else 0


def tick() -> int:
    pending_workers: set[str] = set()
    switched: tuple[str, str] | None = None
    current = ""
    try:
        with file_lock(LOCK_PATH, nonblocking=True):
            verify_singbox_config()
            current = selector_now()
            remove_admission_barrier(current)
            state = load_state()
            now = time.time()
            pending_workers.update(reconcile_selector_state(state, current, now=now))

            for tag in RING:
                phase = state["tags"][tag].get("phase")
                if phase == "failed":
                    recover_failed_entry(state, tag, now=now)
                    phase = state["tags"][tag].get("phase")
                if tag == current or phase in {"unknown", "ready"}:
                    try:
                        refresh_entry_if_generation_changed(state, tag, force_probe=tag == current)
                    except RuntimeFault:
                        save_state(state)
                        raise
                if tag != current and state["tags"][tag].get("phase") == "draining":
                    pending_workers.add(tag)

            target = choose_candidate(current, state, is_locally_ready=locally_ready)
            if target is None:
                save_state(state)
                phases = ",".join(f"{tag}:{state['tags'][tag].get('phase')}" for tag in RING)
                log(f"rotation skipped active={current} reason=no_ready_distinct_candidate phases={phases}")
            else:
                started = time.monotonic_ns()
                selector_set(target)
                observed = selector_now()
                switch_ms = (time.monotonic_ns() - started) / 1_000_000
                if observed != target:
                    raise RuntimeFault(f"selector verification mismatch expected={target} got={observed}")
                apply_switch(state, old=current, new=target, now=time.time(), switch_ms=switch_ms)
                save_state(state)
                pending_workers.add(current)
                switched = (current, target)
                log(
                    f"selector switched {current}->{target} control_ms={switch_ms:.3f} "
                    "existing_connections=preserved"
                )
    except RuntimeFault as exc:
        log(f"tick skipped fail-closed: {exc}")
        return 1

    active = switched[1] if switched else current
    worker_failed = False
    for tag in sorted(pending_workers):
        if tag != active and not start_drain_worker(tag):
            worker_failed = True
    return 1 if worker_failed else 0


def mark_drain_progress(
    tag: str,
    drain_id: str,
    *,
    clash_count: int,
    backend_count: int,
    elapsed: float,
) -> bool:
    with file_lock(LOCK_PATH):
        state = load_state()
        entry = state["tags"][tag]
        if entry.get("phase") not in {"draining", "refreshing"} or entry.get("drain_id") != drain_id:
            return False
        entry["phase"] = "draining"
        entry["last_connection_count"] = max(clash_count, backend_count)
        entry["last_clash_connection_count"] = clash_count
        entry["last_backend_client_count"] = backend_count
        entry["drain_wait_s"] = round(elapsed, 1)
        entry["last_drain_check_at"] = utc_now()
        save_state(state)
        return True


def mark_failed(tag: str, reason: str, *, drain_id: str | None = None) -> bool:
    with file_lock(LOCK_PATH):
        state = load_state()
        entry = state["tags"][tag]
        if drain_id is not None and entry.get("drain_id") != drain_id:
            return False
        entry["phase"] = "failed"
        entry["last_error"] = reason
        entry["failed_at"] = utc_now()
        entry["retry_after"] = time.time() + FAILED_RETRY_S
        save_state(state)
        return True


def drain_refresh(tag: str) -> int:
    if tag not in RING:
        raise ValueError(f"invalid backend: {tag}")
    DRAIN_LOCK_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with file_lock(DRAIN_LOCK_DIR / f"{tag}.lock", nonblocking=True):
            return _drain_refresh_locked(tag)
    except LockBusy as exc:
        log(f"drain worker duplicate skipped tag={tag}: {exc}")
        return 0
    except RuntimeFault as exc:
        log(f"drain worker failed tag={tag}: {exc}")
        return 1


def _drain_refresh_locked(tag: str) -> int:
    started = time.monotonic()
    zero_samples = 0
    last_reported: tuple[int, int, int] | None = None

    with file_lock(LOCK_PATH):
        verify_singbox_config()
        state = load_state()
        entry = state["tags"][tag]
        if entry.get("phase") not in {"draining", "refreshing"}:
            log(f"drain worker stale tag={tag} phase={entry.get('phase')}")
            return 0
        ensure_drain_identity(entry, now=time.time())
        drain_id = str(entry["drain_id"])
        drain_generation = str(entry.get("drain_generation") or "")
        drain_container_id = str(entry.get("drain_container_id") or "")
        valid_container_id = len(drain_container_id) == 64 and all(
            ch in "0123456789abcdef" for ch in drain_container_id
        )
        if not drain_generation or not valid_container_id:
            entry["phase"] = "unknown"
            entry["last_error"] = "missing_drain_identity_no_refresh"
            entry.pop("drain_id", None)
            entry.pop("drain_generation", None)
            entry.pop("drain_container_id", None)
            save_state(state)
            log(f"drain refused tag={tag}: missing immutable pre-refresh identity")
            return 1
        save_state(state)

    name_running, name_generation, name_container_id = container_identity(tag)
    if (
        not name_running
        or name_generation != drain_generation
        or name_container_id != drain_container_id
    ):
        if name_running and len(name_container_id) == 64:
            install_admission_barrier(name_container_id)
        with file_lock(LOCK_PATH):
            state = load_state()
            entry = state["tags"][tag]
            if entry.get("drain_id") == drain_id:
                mark_identity_change_failed(
                    entry,
                    generation=name_generation,
                    container_id=name_container_id,
                    reason="backend_identity_changed_before_drain_barrier",
                    now=time.time(),
                )
                save_state(state)
        return 1

    install_admission_barrier(drain_container_id)
    with file_lock(LOCK_PATH):
        state = load_state()
        entry = state["tags"][tag]
        if entry.get("drain_id") != drain_id:
            remove_admission_barrier(drain_container_id)
            return 0
        entry["admission_barrier_at"] = utc_now()
        save_state(state)

    log(f"drain begin tag={tag} drain_id={drain_id}; new backend admissions blocked, existing connections preserved")

    while True:
        current = selector_now()
        if current == tag:
            remove_admission_barrier(drain_container_id)
            with file_lock(LOCK_PATH):
                state = load_state()
                entry = state["tags"][tag]
                if entry.get("drain_id") == drain_id:
                    entry["phase"] = "active"
                    entry.pop("drain_id", None)
                    entry.pop("drain_generation", None)
                    entry.pop("drain_container_id", None)
                    state["active"] = tag
                    save_state(state)
            log(f"drain aborted tag={tag}: selector made it active")
            return 0
        install_admission_barrier(drain_container_id)
        try:
            clash_count = connections_for_tag(tag)
            backend_count = backend_client_connection_count(drain_container_id)
        except RuntimeFault as exc:
            log(f"drain status unknown tag={tag}: {exc}")
            zero_samples = 0
            time.sleep(DRAIN_POLL_S)
            continue
        zero_samples = zero_samples + 1 if clash_count == 0 and backend_count == 0 else 0
        elapsed = time.monotonic() - started
        report_key = (clash_count, backend_count, int(elapsed // 10))
        if report_key != last_reported:
            if not mark_drain_progress(
                tag,
                drain_id,
                clash_count=clash_count,
                backend_count=backend_count,
                elapsed=elapsed,
            ):
                log(f"drain worker stale tag={tag} drain_id={drain_id}")
                return 0
            log(
                f"drain waiting tag={tag} clash={clash_count} backend_clients={backend_count} "
                f"elapsed_s={elapsed:.1f}"
            )
            last_reported = report_key
        if zero_samples >= DRAIN_ZERO_SAMPLES:
            break
        time.sleep(DRAIN_POLL_S)

    with file_lock(LOCK_PATH):
        verify_singbox_config()
        if selector_now() == tag:
            remove_admission_barrier(drain_container_id)
            log(f"refresh refused tag={tag}: became active before refresh")
            return 0
        state = load_state()
        entry = state["tags"][tag]
        if entry.get("phase") not in {"draining", "refreshing"} or entry.get("drain_id") != drain_id:
            log(f"refresh refused tag={tag}: stale drain identity")
            return 0
        old_ip = str(entry.get("old_ip") or entry.get("ip") or "")
        expected_generation = str(entry.get("drain_generation") or "")
        entry["phase"] = "refreshing"
        entry["refresh_started_at"] = utc_now()
        save_state(state)

    for attempt in range(1, REFRESH_ATTEMPTS + 1):
        with file_lock(LOCK_PATH):
            verify_singbox_config()
            install_admission_barrier(drain_container_id)
            if selector_now() == tag:
                remove_admission_barrier(drain_container_id)
                log(f"refresh refused tag={tag}: became active attempt={attempt}")
                return 0
            state = load_state()
            entry = state["tags"][tag]
            if entry.get("phase") != "refreshing" or entry.get("drain_id") != drain_id:
                log(f"refresh stopped tag={tag}: stale drain identity attempt={attempt}")
                return 0
            try:
                final_clash_count = connections_for_tag(tag)
                final_backend_count = backend_client_connection_count(drain_container_id)
            except RuntimeFault as exc:
                log(f"refresh refused tag={tag}: final drain inventory unknown: {exc}")
                return 1
            if final_clash_count != 0 or final_backend_count != 0:
                entry["phase"] = "draining"
                entry["last_clash_connection_count"] = final_clash_count
                entry["last_backend_client_count"] = final_backend_count
                entry["last_connection_count"] = max(final_clash_count, final_backend_count)
                save_state(state)
                log(
                    f"refresh deferred tag={tag}: final clash={final_clash_count} "
                    f"backend_clients={final_backend_count}"
                )
                return 0
            running, final_generation = container_info(drain_container_id)
            if not running or not final_generation:
                entry["phase"] = "failed"
                entry["last_error"] = "container_not_running_at_final_refresh_gate"
                entry["failed_at"] = utc_now()
                entry["retry_after"] = time.time() + FAILED_RETRY_S
                save_state(state)
                return 1
            if final_generation != expected_generation:
                mark_identity_change_failed(
                    entry,
                    generation=final_generation,
                    container_id=drain_container_id,
                    reason="container_generation_changed_before_refresh",
                    now=time.time(),
                )
                entry["refresh_generation_seen"] = final_generation
                save_state(state)
                return 1
            refresh_script = (
                "set -f; umask 077; "
                "tmpdir=$(mktemp -d /run/warp-sticky-wg.XXXXXX); "
                "trap 'rm -rf \"$tmpdir\"' EXIT; "
                "cp /etc/wireguard/wg0.conf \"$tmpdir/wg0.conf\"; "
                "chmod 600 \"$tmpdir/wg0.conf\"; "
                f"if grep -Eiq '{WG_HOOK_PATTERN}' \"$tmpdir/wg0.conf\"; then exit 70; "
                "else grep_status=$?; [ \"$grep_status\" -eq 1 ] || exit 71; fi; "
                "wg-quick down \"$tmpdir/wg0.conf\" >/dev/null 2>&1 || "
                "ip link del wg0 >/dev/null 2>&1 || true; "
                "wg-quick up \"$tmpdir/wg0.conf\" >/dev/null 2>&1"
            )
            proc = run_command(
                [
                    "docker",
                    "exec",
                    drain_container_id,
                    "sh",
                    "-eu",
                    "-c",
                    refresh_script,
                ],
                timeout=40,
            )

        if proc.returncode != 0:
            log(f"in-place refresh failed tag={tag} attempt={attempt}: {proc.stderr.strip()}")
            continue

        deadline = time.monotonic() + REFRESH_READY_TIMEOUT_S
        last_error = "backend_not_ready"
        while time.monotonic() < deadline:
            if selector_now() == tag:
                remove_admission_barrier(drain_container_id)
                log(f"refresh stopped tag={tag}: became active while waiting")
                return 0
            try:
                verify_admission_barrier(drain_container_id)
                new_ip, generation = probe_backend(tag, container_ref=drain_container_id)
            except RuntimeFault as exc:
                last_error = str(exc)
                time.sleep(REFRESH_POLL_S)
                continue
            name_running, name_generation, name_container_id = container_identity(tag)
            if (
                not name_running
                or generation != expected_generation
                or name_container_id != drain_container_id
                or name_generation != expected_generation
            ):
                if name_running and len(name_container_id) == 64:
                    install_admission_barrier(name_container_id)
                with file_lock(LOCK_PATH):
                    state = load_state()
                    entry = state["tags"][tag]
                    if entry.get("drain_id") == drain_id:
                        mark_identity_change_failed(
                            entry,
                            generation=name_generation,
                            container_id=name_container_id,
                            reason="backend_name_no_longer_matches_bound_container",
                            now=time.time(),
                        )
                        save_state(state)
                log(f"refresh refused tag={tag}: backend name no longer matches bound container")
                return 1
            if old_ip and new_ip == old_ip:
                last_error = "egress_ip_unchanged"
                log(f"refresh unchanged tag={tag} attempt={attempt} ip={new_ip}")
                break
            remove_admission_barrier(drain_container_id)
            with file_lock(LOCK_PATH):
                if selector_now() == tag:
                    remove_admission_barrier(drain_container_id)
                    log(f"refresh result discarded tag={tag}: became active")
                    return 0
                state = load_state()
                entry = state["tags"][tag]
                if entry.get("phase") != "refreshing" or entry.get("drain_id") != drain_id:
                    log(f"refresh result discarded tag={tag}: stale drain identity")
                    return 0
                entry.update(
                    {
                        "phase": "ready",
                        "ip": new_ip,
                        "generation": generation,
                        "container_id": drain_container_id,
                        "last_verified_at": utc_now(),
                        "last_refresh_at": utc_now(),
                        "previous_ip": old_ip,
                        "last_connection_count": 0,
                        "last_clash_connection_count": 0,
                        "last_backend_client_count": 0,
                    }
                )
                entry.pop("retry_after", None)
                entry.pop("last_error", None)
                entry.pop("drain_id", None)
                entry.pop("drain_generation", None)
                entry.pop("drain_container_id", None)
                entry.pop("admission_barrier_at", None)
                save_state(state)
            log(f"refresh ready tag={tag} old_ip={old_ip or 'unknown'} new_ip={new_ip} attempt={attempt}")
            return 0
        log(f"refresh attempt failed tag={tag} attempt={attempt} reason={last_error}")

    with file_lock(LOCK_PATH):
        state = load_state()
        entry = state["tags"][tag]
        if entry.get("drain_id") == drain_id and selector_now() != tag:
            entry["phase"] = "failed"
            entry["last_error"] = "refresh_exhausted_or_ip_unchanged"
            entry["failed_at"] = utc_now()
            entry["retry_after"] = time.time() + FAILED_RETRY_S
            clear_drain_identity(entry)
            save_state(state)
            log(f"refresh failed tag={tag}; retry no earlier than {FAILED_RETRY_S:.0f}s")
    return 1


def status() -> int:
    try:
        verify_singbox_config()
        current = selector_now()
        payload = connections_payload()
        state = load_state()
        counts = {tag: connection_count_for_tag(payload, tag) for tag in RING}
        backend_clients = {tag: backend_client_connection_count(tag) for tag in RING}
        output = {
            "selector": current,
            "ring": list(RING),
            "connections": counts,
            "backend_clients": backend_clients,
            "state": state,
        }
        print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except (RuntimeFault, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 1


def validate_settings() -> None:
    if (
        RING != ("warp3", "warp4", "warp5")
        or SELECTOR != "warp-active"
        or SINGBOX_CONTAINER != "singbox-warp"
        or CLASH_PORT != 9090
        or BACKEND_SOCKS_PORT != 1081
    ):
        raise ValueError("fixed topology must remain singbox-warp:1081 with warp3/warp4/warp5")
    if len(RING) != 3 or len(set(RING)) != 3:
        raise ValueError("WARP_STICKY_RING must contain exactly three distinct tags")
    if DRAIN_ZERO_SAMPLES < 2:
        raise ValueError("WARP_STICKY_DRAIN_ZERO_SAMPLES must be at least 2")
    if REFRESH_ATTEMPTS <= 0:
        raise ValueError("positive setting required: WARP_STICKY_REFRESH_ATTEMPTS")
    ports = {
        "WARP_STICKY_CLASH_PORT": CLASH_PORT,
        "WARP_STICKY_BACKEND_SOCKS_PORT": BACKEND_SOCKS_PORT,
    }
    invalid_ports = [name for name, value in ports.items() if not 1 <= value <= 65535]
    if invalid_ports:
        raise ValueError(f"port must be between 1 and 65535: {', '.join(invalid_ports)}")
    try:
        trace_url = urllib.parse.urlsplit(TRACE_URL)
        trace_port = trace_url.port
    except ValueError as exc:
        raise ValueError("WARP_STICKY_TRACE_URL is invalid") from exc
    if (
        trace_url.scheme != "https"
        or not trace_url.hostname
        or trace_url.username is not None
        or trace_url.password is not None
        or trace_port is not None and not 1 <= trace_port <= 65535
    ):
        raise ValueError("WARP_STICKY_TRACE_URL must be credential-free HTTPS with a valid host")
    finite_positive = {
        "WARP_STICKY_DRAIN_POLL_S": DRAIN_POLL_S,
        "WARP_STICKY_REFRESH_POLL_S": REFRESH_POLL_S,
        "WARP_STICKY_REFRESH_READY_TIMEOUT_S": REFRESH_READY_TIMEOUT_S,
        "WARP_STICKY_FAILED_RETRY_S": FAILED_RETRY_S,
    }
    invalid = [name for name, value in finite_positive.items() if not math.isfinite(value) or value <= 0]
    if invalid:
        raise ValueError(f"finite positive setting required: {', '.join(invalid)}")
    if SERVICE_TEMPLATE.count("{tag}") != 1:
        raise ValueError("WARP_STICKY_DRAIN_SERVICE_TEMPLATE must contain exactly one {tag}")
    try:
        rendered = [SERVICE_TEMPLATE.format(tag=tag) for tag in RING]
    except (KeyError, ValueError) as exc:
        raise ValueError("invalid WARP_STICKY_DRAIN_SERVICE_TEMPLATE") from exc
    if (
        len(set(rendered)) != len(RING)
        or any(
            unit.startswith("-")
            or not unit.endswith(".service")
            or "/" in unit
            or any(ch.isspace() for ch in unit)
            for unit in rendered
        )
    ):
        raise ValueError("WARP_STICKY_DRAIN_SERVICE_TEMPLATE must render distinct valid service units")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("reconcile")
    subparsers.add_parser("tick")
    drain_parser = subparsers.add_parser("drain-refresh")
    drain_parser.add_argument("tag", choices=RING)
    subparsers.add_parser("status")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    validate_settings()
    args = parse_args(argv)
    if args.command == "reconcile":
        return reconcile()
    if args.command == "tick":
        return tick()
    if args.command == "drain-refresh":
        return drain_refresh(args.tag)
    return status()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeFault, subprocess.SubprocessError) as exc:
        log(f"fatal: {exc}")
        raise SystemExit(1)
