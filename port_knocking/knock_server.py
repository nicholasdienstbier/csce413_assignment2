#!/usr/bin/env python3
"""Starter template for the port knocking server."""

import argparse
import logging
import socket
import subprocess
import threading
import time
from collections import defaultdict


DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0
AUTO_CLOSE_DELAY = 30.0


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )

# ── Firewall helpers ──────────────────────────────────────────────────────────

def _run_iptables(args):
    """Run an iptables command, logging errors but not crashing."""
    try:
        subprocess.run(["iptables"] + args, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        logging.warning("iptables error: %s", e.stderr.decode().strip())
    except FileNotFoundError:
        logging.warning("iptables not found – skipping firewall rule (dev mode)")


def block_protected_port(protected_port):
    """Drop all inbound traffic to the protected port by default."""
    logging.info("Blocking port %s by default (iptables DROP)", protected_port)
    _run_iptables(["-I", "INPUT", "-p", "tcp", "--dport", str(protected_port),
                   "-j", "DROP"])


def open_protected_port(ip, protected_port):
    """Insert an ACCEPT rule for this specific IP before the DROP rule."""
    logging.info("Opening port %s for %s", protected_port, ip)
    _run_iptables(["-I", "INPUT", "-s", ip, "-p", "tcp",
                   "--dport", str(protected_port), "-j", "ACCEPT"])


def close_protected_port(ip, protected_port):
    """Remove the ACCEPT rule for this IP."""
    logging.info("Closing port %s for %s", protected_port, ip)
    _run_iptables(["-D", "INPUT", "-s", ip, "-p", "tcp",
                   "--dport", str(protected_port), "-j", "ACCEPT"])


# ── Per-IP state ──────────────────────────────────────────────────────────────

# state[ip] = {"progress": int, "last_knock": float}
state_lock = threading.Lock()
state = defaultdict(lambda: {"progress": 0, "last_knock": 0.0})


def handle_knock(ip, port, sequence, window_seconds, protected_port):
    """
    Called every time a knock arrives on `port` from `ip`.
    Advances the sequence counter if correct, resets on wrong port or timeout.
    Opens the protected port when the full sequence is complete.
    """
    logger = logging.getLogger("KnockServer")
    now = time.time()

    with state_lock:
        s = state[ip]

        # ── Timeout check ────────────────────────────────────────────────────
        if s["progress"] > 0 and (now - s["last_knock"]) > window_seconds:
            logger.info("[%s] Sequence timed out – resetting", ip)
            s["progress"] = 0

        expected_port = sequence[s["progress"]]

        # ── Correct knock ────────────────────────────────────────────────────
        if port == expected_port:
            s["progress"] += 1
            s["last_knock"] = now
            logger.info("[%s] Knock %d/%d correct (port %d)",
                        ip, s["progress"], len(sequence), port)

            # Full sequence received
            if s["progress"] == len(sequence):
                logger.info("[%s] Sequence complete! Opening port %d",
                            ip, protected_port)
                s["progress"] = 0   # reset for next round
                open_protected_port(ip, protected_port)
                # Schedule auto-close
                threading.Timer(
                    AUTO_CLOSE_DELAY,
                    close_protected_port,
                    args=[ip, protected_port]
                ).start()

        # ── Wrong knock ──────────────────────────────────────────────────────
        else:
            if s["progress"] > 0:
                logger.info("[%s] Wrong knock (got %d, expected %d) – resetting",
                            ip, port, expected_port)
            s["progress"] = 0
            s["last_knock"] = 0.0


# ── Per-port TCP listener ─────────────────────────────────────────────────────

def listen_on_port(knock_port, sequence, window_seconds, protected_port):
    """
    Accept TCP connections on `knock_port`, record the source IP,
    immediately close the connection (a knock is just a connection attempt),
    then call handle_knock().
    """
    logger = logging.getLogger("KnockServer")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", knock_port))
    except OSError as e:
        logger.error("Cannot bind to knock port %d: %s", knock_port, e)
        return

    srv.listen(16)
    logger.info("Listening for knocks on port %d", knock_port)

    while True:
        try:
            conn, (client_ip, _) = srv.accept()
            conn.close()   # knock = just a connection attempt
            handle_knock(client_ip, knock_port, sequence,
                         window_seconds, protected_port)
        except Exception as e:
            logger.error("Error on knock port %d: %s", knock_port, e)


# ── Main ──────────────────────────────────────────────────────────────────────

def listen_for_knocks(sequence, window_seconds, protected_port):
    logger = logging.getLogger("KnockServer")
    logger.info("=== Port Knocking Server ===")
    logger.info("Knock sequence : %s", sequence)
    logger.info("Protected port : %d", protected_port)
    logger.info("Timing window  : %.1f seconds", window_seconds)
    logger.info("Auto-close     : %.1f seconds after opening", AUTO_CLOSE_DELAY)

    # Block the protected port by default
    block_protected_port(protected_port)

    # Start one listener thread per knock port
    threads = []
    for kp in sequence:
        t = threading.Thread(
            target=listen_on_port,
            args=[kp, sequence, window_seconds, protected_port],
            daemon=True,
        )
        t.start()
        threads.append(t)

    logger.info("Server running. Waiting for knock sequences...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down.")


def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server")
    parser.add_argument(
        "--sequence",
        default=",".join(str(p) for p in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports (default: 1234,5678,9012)",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Port to protect (default: 2222)",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence (default: 10)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()
    try:
        sequence = [int(p) for p in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")
    listen_for_knocks(sequence, args.window, args.protected_port)


if __name__ == "__main__":
    main()