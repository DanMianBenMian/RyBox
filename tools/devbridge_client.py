#!/usr/bin/env python3
"""RyBox Developer Debug Bridge client.

Connect to the RyBox TCP listener on the device and drive it WITHOUT rebuilding
the IPA: push a recompiled guest binary / entitlements file, re-sign, launch,
eject, stream logs, run a sandbox shell command, inspect the virtual root.

Usage:
  python3 devbridge_client.py <host> <port> <command> [args...]

Examples:
  # push a freshly patched guest executable, then re-sign + launch
  python3 devbridge_client.py 192.168.1.50 2222 push \
      Apps/org.coolstar.SileoStore.app/Sileo ./Sileo
  python3 devbridge_client.py 192.168.1.50 2222 resign org.coolstar.SileoStore
  python3 devbridge_client.py 192.168.1.50 2222 launch org.coolstar.SileoStore

  python3 devbridge_client.py 192.168.1.50 2222 log rysign
  python3 devbridge_client.py 192.168.1.50 2222 exec "ls /var/mobile"

Commands: help info log ls cat push exec resign launch eject quit
`push <remote> <local-file>` uploads <local-file> to <remote> (relative =
under the virtual root, e.g. Apps/<bid>.app/<exe>).
"""
import socket
import sys
import os

MARKER = b"\n<<EOF>>\n"
BUFSZ = 65536


def recv_until(sock):
    buf = b""
    while MARKER not in buf:
        chunk = sock.recv(BUFSZ)
        if not chunk:
            break
        buf += chunk
    # Trim the trailing marker if present.
    if buf.endswith(MARKER):
        buf = buf[:-len(MARKER)]
    return buf.decode("utf-8", errors="replace")


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(2)
    host, port = sys.argv[1], int(sys.argv[2])
    cmd = sys.argv[3]
    args = sys.argv[4:]

    sock = socket.create_connection((host, port), timeout=30)
    try:
        if cmd == "push":
            if len(args) < 2:
                print("push requires <remote> <local-file>")
                sys.exit(2)
            remote, local = args[0], args[1]
            if not os.path.isfile(local):
                print(f"local file not found: {local}")
                sys.exit(2)
            data = open(local, "rb").read()
            sock.sendall(f"push {remote} {len(data)}\n".encode())
            # Read the server's first reply line. The server always answers
            # "OK push-ready <size>" (client must then stream the binary), or
            # "OK pushed ..." if the bytes were already coalesced into the
            # request line (rare). Only send the file after "push-ready".
            ack = b""
            try:
                while not ack.endswith(b"\n"):
                    c = sock.recv(1)
                    if not c:
                        break
                    ack += c
                    if b"<<EOF>>" in ack:
                        break
            except socket.timeout:
                pass
            if b"push-ready" in ack:
                sock.sendall(data)
                print(recv_until(sock))
            else:
                # Already finished ("OK pushed") or error: drain the marker.
                rest = b""
                try:
                    while MARKER not in rest:
                        ch = sock.recv(BUFSZ)
                        if not ch:
                            break
                        rest += ch
                except socket.timeout:
                    pass
                out = ack
                if rest:
                    out += rest
                if out.endswith(MARKER):
                    out = out[:-len(MARKER)]
                print(out.decode("utf-8", errors="replace"))
        else:
            line = " ".join([cmd] + args)
            sock.sendall((line + "\n").encode())
            print(recv_until(sock))
    finally:
        sock.close()


if __name__ == "__main__":
    main()
