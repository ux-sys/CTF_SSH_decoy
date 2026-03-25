#!/usr/bin/env python3
"""
CTF SSH-like decoy.

- Sends an SSH-like banner.
- Optionally sends a "host authenticity / fingerprint" prompt (for UX; note: that
  prompt is normally produced by the client, not the server).
- Reads client input (but discards it; it is NOT stored).
- Waits `session_delay` seconds, then sends a polite timeout message and closes.

Usage:
  python3 ctf_ssh_decoy.py           # listens on 0.0.0.0:2222
  python3 ctf_ssh_decoy.py --port 2222 --delay 8 --fingerprint

Run as an unprivileged user on a non-privileged port (≥1024) unless you intend to
run as root and bind to port 22. This script logs only connection metadata to
the file specified by --logfile (default /tmp/ctf_ssh_decoy.log).
"""

import socket
import threading
import argparse
import datetime
import sys

BANNER_DEFAULT = "SSH-2.0-OpenSSH_8.4p1 Debian-5"
FINGERPRINT_SAMPLE = ("The authenticity of host '{}' can't be established.\r\n"
                      "RSA key fingerprint is {}.\r\n"
                      "Are you sure you want to continue connecting (yes/no)? ")

LOGFILE_DEFAULT = "/tmp/ctf_ssh_decoy.log"

# --- helper functions -----------------------------------------------------
def timestamp_utc():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def log_event(logfile, addr, msg):
    line = f"{timestamp_utc()} - {addr[0]}:{addr[1]} - {msg}\n"
    try:
        with open(logfile, "a") as f:
            f.write(line)
    except Exception:
        # never crash on logging failure
        pass

# --- connection handler ---------------------------------------------------
def handle_client(conn, addr, banner, do_fingerprint, fingerprint, session_delay, logfile):
    try:
        conn.settimeout(session_delay + 10)
        # Send SSH banner (ends with LF or CRLF; many clients expect LF)
        conn.sendall((banner + "\r\n").encode("utf-8"))

        # Optional UX: send a fingerprint-like message so the overall interaction
        # looks familiar to players. NOTE: this is only for cosmetic purposes.
        if do_fingerprint:
            prompt = FINGERPRINT_SAMPLE.format(f"{addr[0]}", fingerprint)
            # send the prompt but do NOT expect a real reply to be captured
            conn.sendall(prompt.encode("utf-8"))

        # Read some bytes from client but explicitly discard them. We read up to
        # `read_bytes` bytes in a non-blocking loop for the duration of session_delay.
        read_bytes = 1024
        start = datetime.datetime.utcnow()
        # We want to allow the client to send some data (maybe they type "yes")
        # but we will not save it. We will keep reading until session_delay elapses.
        while (datetime.datetime.utcnow() - start).total_seconds() < session_delay:
            try:
                data = conn.recv(read_bytes)
                if not data:
                    # client closed connection
                    break
                # intentionally discard -- do NOT log or store
                # optional: you could increment a counter or inspect length only
            except socket.timeout:
                # read timeout — keep waiting until overall session_delay passes
                pass
            except BlockingIOError:
                pass
            # small sleep to avoid busy loop
            # (we rely on socket timeouts too; this reduces CPU)
            threading.Event().wait(0.1)

        # After the delay, send a timeout/closed message and close
        try:
            conn.sendall(b"\r\nConnection timed out. Closing.\r\n")
        except Exception:
            pass

        log_event(logfile, addr, "session_closed (credentials discarded)")
    except Exception as e:
        # don't leak exception contents (avoid logging sensitive info)
        log_event(logfile, addr, f"error_handling_connection ({type(e).__name__})")
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass

# --- main server loop ----------------------------------------------------
def run_server(bind_host, bind_port, banner, do_fingerprint, fingerprint, session_delay, logfile):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_host, bind_port))
    sock.listen(100)
    print(f"CTF SSH decoy listening on {bind_host}:{bind_port}  (logfile: {logfile})")
    try:
        while True:
            try:
                conn, addr = sock.accept()
            except KeyboardInterrupt:
                break
            except Exception:
                continue
            # log connection metadata only
            log_event(logfile, addr, "connection_opened")
            # Handler thread (daemon so the program can exit)
            t = threading.Thread(target=handle_client,
                                 args=(conn, addr, banner, do_fingerprint, fingerprint, session_delay, logfile),
                                 daemon=True)
            t.start()
    finally:
        sock.close()

# --- CLI parsing ----------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="CTF SSH-like decoy (safe: does not store creds)")
    p.add_argument("--host", default="0.0.0.0", help="listen address (default: 0.0.0.0)")
    p.add_argument("--port", type=int, default=2222, help="listen port (default: 2222)")
    p.add_argument("--banner", default=BANNER_DEFAULT, help="SSH banner string to send")
    p.add_argument("--fingerprint", action="store_true",
                   help="send a fingerprint-like prompt after the banner (cosmetic only)")
    p.add_argument("--fingerprint-str", default="SHA256:EXAMPLEfINGeRpRinT",
                   help="fingerprint text to show when --fingerprint is used")
    p.add_argument("--delay", type=float, default=8.0,
                   help="how many seconds before simulating timeout (default: 8)")
    p.add_argument("--logfile", default=LOGFILE_DEFAULT, help="logfile path for connection metadata")
    return p.parse_args()

# --- entrypoint -----------------------------------------------------------
if __name__ == "__main__":
    args = parse_args()

    if args.port < 1024 and (os := getattr(sys, "platform", None)) is not None:
        # warn about privileged port usage (not a hard fail)
        print("Warning: ports <1024 require root privileges. Consider using a high port for testing.")

    try:
        run_server(args.host, args.port, args.banner, args.fingerprint, args.fingerprint_str, args.delay, args.logfile)
    except KeyboardInterrupt:
        print("\nDecoy stopped by user.")
