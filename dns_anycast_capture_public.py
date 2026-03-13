#!/usr/bin/env python3
"""
DNS Anycast Path Capture
========================
Captures DNS resolution latency and network path to help determine whether
queries are being routed to distant or suboptimal anycast nodes due to BGP
routing or peering behavior. Works with any domain.

Requirements:
    pip install dnspython ipwhois

Run as Administrator for best traceroute results (ICMP may still be filtered
on corporate/VPN networks; the script reports what it can capture).

Output is written to both the console and a timestamped .txt file in the same
directory as this script.
"""

import sys
import os
import socket
import time
import datetime
import subprocess
import threading
import ctypes
from datetime import timezone

# ── Optional dependencies ──────────────────────────────────────────────────────
try:
    import dns.message
    import dns.query
    import dns.rdatatype
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    from ipwhois import IPWhois
    HAS_IPWHOIS = True
except ImportError:
    HAS_IPWHOIS = False

# ── Configuration ──────────────────────────────────────────────────────────────
RESOLVER         = "8.8.8.8"   # DNS server to query; change to system resolver if needed
ITERATIONS       = 5           # number of capture rounds
INTERVAL_SECS    = 5           # wait between iterations
TCP_PORT         = 443         # port for TCP connectivity check
TCP_TIMEOUT_SECS = 3
TRACERT_MAX_HOPS = 20
TRACERT_WAIT_MS  = 1000        # per-hop wait for tracert -w
# ──────────────────────────────────────────────────────────────────────────────


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ── DNS ───────────────────────────────────────────────────────────────────────

def dns_query_timed(domain: str, resolver_ip: str) -> tuple[list[str], float, str | None]:
    """
    Query the given resolver for A records of domain.
    Returns (ip_list, latency_ms, error_or_None).
    Uses dnspython for wire-level timing if available, else socket fallback.
    """
    if HAS_DNSPYTHON:
        try:
            request = dns.message.make_query(domain, dns.rdatatype.A)
            t0 = time.perf_counter()
            response = dns.query.udp(request, resolver_ip, timeout=5)
            latency_ms = (time.perf_counter() - t0) * 1000
            ips = [
                str(rr)
                for rrset in response.answer
                if rrset.rdtype == dns.rdatatype.A
                for rr in rrset
            ]
            return ips, latency_ms, None
        except Exception as exc:
            return [], 0.0, str(exc)
    else:
        # Fallback — getaddrinfo includes resolver cache latency, not wire latency
        try:
            t0 = time.perf_counter()
            ips = list({addr[4][0] for addr in socket.getaddrinfo(domain, None, socket.AF_INET)})
            latency_ms = (time.perf_counter() - t0) * 1000
            return ips, latency_ms, None
        except Exception as exc:
            return [], 0.0, str(exc)


# ── TCP connectivity ──────────────────────────────────────────────────────────

def tcp_check(ip: str, port: int = 443, timeout: float = 3) -> tuple[bool, float]:
    """Returns (success, latency_ms)."""
    try:
        t0 = time.perf_counter()
        with socket.create_connection((ip, port), timeout=timeout):
            pass
        return True, (time.perf_counter() - t0) * 1000
    except Exception:
        return False, 0.0


# ── Traceroute ────────────────────────────────────────────────────────────────

def traceroute(target_ip: str, max_hops: int = 20, wait_ms: int = 1000) -> list[tuple[int, str | None, float | None]]:
    """
    Run 'tracert -d' and parse output.
    Returns list of (hop_num, ip_or_None, rtt_ms_or_None).
    ICMP will be filtered on many corporate/Azure networks; partial paths
    (ISP hops before the Azure edge) are still valuable for WAN analysis.
    """
    hops: list[tuple[int, str | None, float | None]] = []
    try:
        proc = subprocess.run(
            ["tracert", "-d", "-h", str(max_hops), "-w", str(wait_ms), target_ip],
            capture_output=True,
            text=True,
            timeout=max_hops * (wait_ms / 1000) * 4 + 15,
        )
        for line in proc.stdout.splitlines():
            stripped = line.strip()
            parts = stripped.split()
            if not parts:
                continue
            try:
                hop_num = int(parts[0])
            except ValueError:
                continue

            if "timed out" in stripped.lower() or (len(parts) >= 4 and all(p == "*" for p in parts[1:4])):
                hops.append((hop_num, None, None))
            else:
                hop_ip = parts[-1] if parts else None
                rtt: float | None = None
                for p in parts[1:-1]:
                    candidate = p.lstrip("<").rstrip("ms").strip()
                    try:
                        rtt = float(candidate)
                        break
                    except ValueError:
                        continue
                hops.append((hop_num, hop_ip, rtt))
    except subprocess.TimeoutExpired:
        hops.append((0, "TIMEOUT — tracert took too long", None))
    except Exception as exc:
        hops.append((0, f"ERROR: {exc}", None))
    return hops


# ── Reverse DNS (non-blocking) ────────────────────────────────────────────────

def rdns(ip: str, timeout: float = 1.0) -> str | None:
    result: list[str | None] = [None]

    def _lookup():
        try:
            result[0] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

    t = threading.Thread(target=_lookup, daemon=True)
    t.start()
    t.join(timeout)
    return result[0]


# ── IP ASN/Org lookup ─────────────────────────────────────────────────────────

_whois_cache: dict[str, dict] = {}

def whois_info(ip: str) -> dict:
    """Return ASN and org for an IP using ipwhois (cached)."""
    if not HAS_IPWHOIS:
        return {}
    if ip in _whois_cache:
        return _whois_cache[ip]
    try:
        result = IPWhois(ip).lookup_rdap(depth=1)
        info = {
            "asn":      result.get("asn"),
            "asn_desc": result.get("asn_description", ""),
            "org":      result.get("network", {}).get("name", ""),
        }
    except Exception:
        info = {}
    _whois_cache[ip] = info
    return info


# ── Output helpers ────────────────────────────────────────────────────────────

class Tee:
    """Write to both stdout and a file simultaneously."""
    def __init__(self, filepath: str):
        self._file = open(filepath, "w", encoding="utf-8")
        self._stdout = sys.stdout

    def write(self, msg: str):
        self._stdout.write(msg)
        self._file.write(msg)

    def flush(self):
        self._stdout.flush()
        self._file.flush()

    def close(self):
        self._file.close()


def banner(title: str):
    print(f"\n{'═' * 62}")
    print(f"  {title}")
    print('═' * 62)


def section(title: str):
    print(f"\n  ── {title}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("DNS Anycast Path Capture")
    print("=" * 40)
    while True:
        domain_input = input("Enter domain to capture: ").strip()
        if domain_input:
            DOMAIN = domain_input
            break
        print("  Domain cannot be empty. Please enter a domain name.")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    ts_file = datetime.datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    outfile = os.path.join(script_dir, f"dns_anycast_{ts_file}.txt")
    tee = Tee(outfile)
    sys.stdout = tee

    admin   = is_admin()
    now_utc = datetime.datetime.now(timezone.utc)

    banner("DNS Anycast Path Capture")
    print(f"  Timestamp (UTC)  : {now_utc.strftime('%Y-%m-%d %H:%M:%SZ')}")
    print(f"  Domain           : {DOMAIN}")
    print(f"  Resolver         : {RESOLVER}")
    print(f"  Iterations       : {ITERATIONS}  (every {INTERVAL_SECS}s)")
    print(f"  DNS library      : {'dnspython ✓' if HAS_DNSPYTHON else 'socket (pip install dnspython for wire-level timing)'}")
    print(f"  ASN lookup       : {'ipwhois ✓' if HAS_IPWHOIS else 'unavailable (pip install ipwhois)'}")
    print(f"  Running as Admin : {admin}")
    if not admin:
        print("  NOTE: Some traceroute probes may be blocked without Admin rights.")
    print(f"\n  Output saved to  : {outfile}")

    all_results: list[dict] = []

    for i in range(1, ITERATIONS + 1):
        iter_ts = datetime.datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
        banner(f"Iteration {i}/{ITERATIONS}  —  {iter_ts}")

        # ── DNS query ─────────────────────────────────────────────────────────
        ips, dns_ms, err = dns_query_timed(DOMAIN, RESOLVER)

        if err or not ips:
            print(f"  DNS FAILED: {err or 'no A records returned'}")
            if i < ITERATIONS:
                print(f"\n  (sleeping {INTERVAL_SECS}s...)")
                time.sleep(INTERVAL_SECS)
            continue

        print(f"  DNS latency      : {dns_ms:.2f} ms")
        print(f"  Resolved IP(s)   : {', '.join(ips)}")

        for ip in ips:
            section(f"Target {ip}")

            # ASN / Org
            if HAS_IPWHOIS:
                info = whois_info(ip)
                if info:
                    print(f"    ASN   : AS{info.get('asn', '?')}  {info.get('asn_desc', '')}")
                    print(f"    Org   : {info.get('org', '?')}")

            # TCP check
            ok, tcp_ms = tcp_check(ip, TCP_PORT, TCP_TIMEOUT_SECS)
            status = f"SUCCESS  ({tcp_ms:.2f} ms)" if ok else "FAILED (timeout/refused)"
            print(f"    TCP {TCP_PORT}  : {status}")

            # Traceroute
            print(f"    Traceroute (tracert -d -h {TRACERT_MAX_HOPS} -w {TRACERT_WAIT_MS}):")
            hops = traceroute(ip, TRACERT_MAX_HOPS, TRACERT_WAIT_MS)
            responding = 0
            for hop_num, hop_ip, rtt in hops:
                if hop_ip:
                    responding += 1
                    rtt_str  = f"{rtt:.0f} ms" if rtt is not None else "<1 ms"
                    name     = rdns(hop_ip) or ""
                    name_str = f"  {name}" if name else ""
                    print(f"      {hop_num:>3}.  {hop_ip:<18}  {rtt_str:<8}{name_str}")
                else:
                    print(f"      {hop_num:>3}.  *  (filtered)")

            if responding == 0:
                print("           All hops filtered — ICMP is blocked end-to-end.")
                print("           This is typical on VPN/corporate networks and Azure endpoints.")
                print("           TCP connectivity above confirms reachability.")

            all_results.append({
                "iteration":      i,
                "timestamp_utc":  datetime.datetime.now(timezone.utc).isoformat(),
                "ip":             ip,
                "dns_latency_ms": round(dns_ms, 2),
                "tcp_ok":         ok,
                "tcp_latency_ms": round(tcp_ms, 2),
                "hops_responding": responding,
                "hops":           [(h, ip2, round(r, 1) if r else None) for h, ip2, r in hops],
            })

        if i < ITERATIONS:
            print(f"\n  (sleeping {INTERVAL_SECS}s...)")
            time.sleep(INTERVAL_SECS)

    # ── Summary ───────────────────────────────────────────────────────────────
    banner("Summary")
    if not all_results:
        print("  No data collected.")
    else:
        unique_ips  = sorted({r["ip"] for r in all_results})
        dns_samples = [r["dns_latency_ms"] for r in all_results]
        tcp_samples = [r["tcp_latency_ms"]  for r in all_results if r["tcp_ok"]]

        print(f"  Unique anycast endpoint IPs : {', '.join(unique_ips)}")
        if len(unique_ips) > 1:
            print(f"  *** DNS returned different IPs across iterations — anycast rotation observed ***")

        print(f"  DNS latency  avg / max      : {sum(dns_samples)/len(dns_samples):.1f} ms  /  {max(dns_samples):.1f} ms")
        if tcp_samples:
            print(f"  TCP-443 latency avg / max   : {sum(tcp_samples)/len(tcp_samples):.1f} ms  /  {max(tcp_samples):.1f} ms")

        print()
        print("  If all traceroute hops show '*', ICMP is filtered by your network or VPN.")
        print("  Please include the following in your Azure WAN support case:")
        print("   • This output file")
        print("   • Your ISP name and AS number (check https://bgp.he.net)")
        print("   • Your approximate location (city/country)")
        print("   • Whether you are behind a VPN or proxy")
        print()
        print(f"  Output file: {outfile}")

    tee.close()
    sys.stdout = tee._stdout
    print(f"\nDone. Results saved to: {outfile}")


if __name__ == "__main__":
    main()
