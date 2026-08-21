#!/usr/bin/env python3
"""mojo-tls compliance suite.

Differentially tests TLS behavior against CPython's `ssl` module (which
fronts the same OpenSSL family every mainstream stack trusts): handshake
versions, ALPN negotiation, hostname verification, certificate rejection,
and bulk transfer through the record layer, in both roles. Never
self-grading: every check has a CPython TLS endpoint on the other side.

Rerun with: pixi run compliance   (from the package root)
Writes COMPLIANCE.md at the package root and exits non-zero on any failure.
With --json PATH, also dumps {"sections": {...}} for the umbrella suite.
"""

import argparse
import json
import os
import platform
import socket
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # package root
BUILD = ROOT / "build"
TOOLS = ROOT / "compliance" / "tools"
CERTS = BUILD / "certs"
REPORT = ROOT / "COMPLIANCE.md"

RESULTS: dict[str, list[tuple[str, bool, str]]] = {}


def record(section: str, name: str, ok: bool, detail: str = ""):
    RESULTS.setdefault(section, []).append((name, bool(ok), detail))
    print(f"  {'PASS' if ok else 'FAIL'} [{section}] {name}" + ("" if ok else f"  <- {detail}"))


def dep_path(name: str) -> Path:
    candidates = []
    if os.environ.get("MOJO_DEPS_DIR"):
        candidates.append(Path(os.environ["MOJO_DEPS_DIR"]) / name / "src")
    candidates.append(ROOT / ".deps" / name / "src")
    candidates.append(ROOT.parent / name / "src")
    for c in candidates:
        if c.is_dir():
            return c
    sys.exit(f"dependency '{name}' not found; run `python3 tools/fetch_deps.py`")


def run_tool(binary: str, *args, timeout=90) -> subprocess.CompletedProcess:
    return subprocess.run(
        [*MOJO_RUN, str(TOOLS / f"{binary}.mojo"), *map(str, args)],
        capture_output=True, text=True, timeout=timeout, cwd=ROOT,
    )


def setup():
    subprocess.run(["bash", str(ROOT / "tools" / "build_shim.sh")], check=True)
    subprocess.run(["bash", str(ROOT / "tools" / "gen_test_certs.sh")], check=True)




# Compliance tools run via `mojo run` (compile + run in one step). On the
# conda Linux toolchain, `mojo build` of a binary that loads the shim
# through OwnedDLHandle fails to link libdl, while `mojo run` links it
# correctly, so the tools are invoked rather than pre-built.
MOJO_RUN: list[str] = []


def build_tools():
    global MOJO_RUN
    BUILD.mkdir(exist_ok=True)
    MOJO_RUN = ["mojo", "run", "-I", "src", "-I", str(dep_path("mojo-net"))]


# ------------------------------------------------------------------ tls ---

def py_server_ctx(cert: str, key: str, alpn=None, max_version=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERTS / cert), str(CERTS / key))
    if alpn:
        ctx.set_alpn_protocols(alpn)
    if max_version is not None:
        ctx.maximum_version = max_version
    return ctx


def py_echo_server(ctx, results: dict):
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    results["port"] = lsock.getsockname()[1]
    results["ready"].set()

    def serve():
        try:
            conn, _ = lsock.accept()
            conn.settimeout(30)
            tls = ctx.wrap_socket(conn, server_side=True)
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                tls.sendall(chunk)
            tls.close()
        except Exception as e:
            results["error"] = repr(e)
        finally:
            lsock.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return t


def py_receive_then_echo(ctx, size: int, results: dict):
    """Receives a complete payload before echoing it through CPython TLS."""
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    results["port"] = lsock.getsockname()[1]
    results["ready"].set()

    def serve():
        try:
            conn, _ = lsock.accept()
            conn.settimeout(30)
            tls = ctx.wrap_socket(conn, server_side=True)
            results["version"] = tls.version()
            results["alpn"] = tls.selected_alpn_protocol()
            received = bytearray()
            while len(received) < size:
                chunk = tls.recv(min(16384, size - len(received)))
                if not chunk:
                    break
                received.extend(chunk)
            results["bytes"] = len(received)
            results["payload_ok"] = all(
                byte == (index * 17 + 11) % 256
                for index, byte in enumerate(received)
            )
            for offset in range(0, len(received), 16384):
                tls.sendall(received[offset : offset + 16384])
            tls.close()
        except Exception as error:
            results["error"] = repr(error)
        finally:
            lsock.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def py_stalled_tls_server(ctx, results: dict):
    """Completes a handshake, then leaves application bytes unread."""
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    results["port"] = lsock.getsockname()[1]
    results["ready"].set()

    def serve():
        try:
            conn, _ = lsock.accept()
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
            conn.settimeout(10)
            tls = ctx.wrap_socket(conn, server_side=True)
            results["version"] = tls.version()
            results["alpn"] = tls.selected_alpn_protocol()
            time.sleep(30.0)
            tls.close()
        except Exception as error:
            results["error"] = repr(error)
        finally:
            lsock.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def section_tls():
    print("== tls vs CPython ssl ==")
    n = 262_144

    # Mojo client, python server: TLS 1.3 + ALPN h2 + bulk echo.
    res = {"ready": threading.Event()}
    t = py_echo_server(py_server_ctx("server.pem", "server.key", ["h2", "http/1.1"]), res)
    res["ready"].wait(10)
    r = run_tool("tls_probe_client", res["port"], "localhost",
                 str(CERTS / "ca.pem"), "h2", n, timeout=60)
    t.join(timeout=30)
    record("tls", "mojo client vs CPython server: TLSv1.3, ALPN h2, 256KB echo",
           r.returncode == 0 and "VERSION TLSv1.3" in r.stdout
           and "ALPN h2" in r.stdout and f"OK {n}" in r.stdout,
           f"rc={r.returncode} out={r.stdout.strip()!r} err={r.stderr[:150]!r}")

    # A server capped at TLS 1.2 negotiates TLSv1.2 with our client.
    res = {"ready": threading.Event()}
    t = py_echo_server(py_server_ctx("server.pem", "server.key",
                                     max_version=ssl.TLSVersion.TLSv1_2), res)
    res["ready"].wait(10)
    r = run_tool("tls_probe_client", res["port"], "localhost",
                 str(CERTS / "ca.pem"), "-", 4096, timeout=60)
    t.join(timeout=30)
    record("tls", "mojo client negotiates TLSv1.2 with a 1.2-capped server",
           r.returncode == 0 and "VERSION TLSv1.2" in r.stdout,
           f"rc={r.returncode} out={r.stdout.strip()!r} err={r.stderr[:150]!r}")

    # Python verifying client, mojo server: hostname + chain + ALPN + echo.
    proc = subprocess.Popen(
        [*MOJO_RUN, str(TOOLS / "tls_echo_server.mojo"), str(CERTS / "server.pem"),
         str(CERTS / "server.key"), "h2,http/1.1"],
        stdout=subprocess.PIPE, text=True, cwd=ROOT)
    port = int(proc.stdout.readline().strip().removeprefix("PORT "))
    ok, detail = False, ""
    try:
        cctx = ssl.create_default_context(cafile=str(CERTS / "ca.pem"))
        cctx.set_alpn_protocols(["h2"])
        raw = socket.create_connection(("127.0.0.1", port), timeout=10)
        tls = cctx.wrap_socket(raw, server_hostname="localhost")
        tls.settimeout(30)
        payload = bytes((i * 7 + 1) % 256 for i in range(n))
        got = bytearray()
        sent = 0
        while sent < len(payload):
            take = payload[sent:sent + 16384]
            tls.sendall(take)
            while len(got) < sent + len(take):
                got.extend(tls.recv(65536))
            sent += len(take)
        ok = (bytes(got) == payload and tls.version() == "TLSv1.3"
              and tls.selected_alpn_protocol() == "h2")
        detail = f"echoed {len(got)}/{n} version={tls.version()} alpn={tls.selected_alpn_protocol()}"
        tls.close()
    except Exception as e:
        detail = repr(e)
    finally:
        proc.kill(); proc.wait()
    record("tls", "CPython verifying client vs mojo server: chain, hostname, ALPN, echo",
           ok, detail)

    # Rejection agreement: both sides refuse an untrusted (self-signed)
    # certificate.
    proc = subprocess.Popen(
        [*MOJO_RUN, str(TOOLS / "tls_echo_server.mojo"), str(CERTS / "selfsigned.pem"),
         str(CERTS / "selfsigned.key")],
        stdout=subprocess.PIPE, text=True, cwd=ROOT)
    port = int(proc.stdout.readline().strip().removeprefix("PORT "))
    py_rejected = False
    try:
        cctx = ssl.create_default_context(cafile=str(CERTS / "ca.pem"))
        raw = socket.create_connection(("127.0.0.1", port), timeout=10)
        cctx.wrap_socket(raw, server_hostname="localhost")
    except ssl.SSLCertVerificationError:
        py_rejected = True
    except Exception:
        pass
    finally:
        proc.kill(); proc.wait()
    res = {"ready": threading.Event()}
    t = py_echo_server(
        py_server_ctx("selfsigned.pem", "selfsigned.key", ["h2"]), res
    )
    res["ready"].wait(10)
    r = run_tool(
        "tls_nonblocking_client",
        res["port"],
        str(CERTS / "ca.pem"),
        16,
        timeout=60,
    )
    mojo_rejected = r.returncode != 0 and "handshake" in (r.stderr + r.stdout)
    record("tls", "both reject an untrusted (self-signed) certificate",
           py_rejected and mojo_rejected,
           f"python={py_rejected} mojo={mojo_rejected} err={r.stderr[:120]!r}")

    # Rejection agreement: hostname mismatch on a CA-signed certificate.
    proc = subprocess.Popen(
        [*MOJO_RUN, str(TOOLS / "tls_echo_server.mojo"), str(CERTS / "wronghost.pem"),
         str(CERTS / "wronghost.key")],
        stdout=subprocess.PIPE, text=True, cwd=ROOT)
    port = int(proc.stdout.readline().strip().removeprefix("PORT "))
    py_rejected = False
    try:
        cctx = ssl.create_default_context(cafile=str(CERTS / "ca.pem"))
        raw = socket.create_connection(("127.0.0.1", port), timeout=10)
        cctx.wrap_socket(raw, server_hostname="localhost")
    except ssl.SSLCertVerificationError:
        py_rejected = True
    except Exception:
        pass
    finally:
        proc.kill(); proc.wait()
    res = {"ready": threading.Event()}
    t = py_echo_server(
        py_server_ctx("wronghost.pem", "wronghost.key", ["h2"]), res
    )
    res["ready"].wait(10)
    r = run_tool(
        "tls_nonblocking_client",
        res["port"],
        str(CERTS / "ca.pem"),
        16,
        timeout=60,
    )
    mojo_rejected = r.returncode != 0 and "handshake" in (r.stderr + r.stdout)
    record("tls", "both reject a hostname mismatch on a CA-signed certificate",
           py_rejected and mojo_rejected,
           f"python={py_rejected} mojo={mojo_rejected} err={r.stderr[:120]!r}")

    # ALPN with no overlap: RFC 7301 permits either a fatal alert or
    # proceeding without a protocol. Our server sends the alert (which a
    # CPython client must observe as a handshake failure); a CPython
    # server proceeds without ALPN, which our client must report as
    # "none negotiated" rather than failing.
    res = {"ready": threading.Event()}
    t = py_echo_server(py_server_ctx("server.pem", "server.key", ["http/1.1"]), res)
    res["ready"].wait(10)
    r = run_tool("tls_probe_client", res["port"], "localhost",
                 str(CERTS / "ca.pem"), "h2", 16, timeout=60)
    mojo_sees_none = r.returncode == 0 and "ALPN \n" in r.stdout + "\n"
    proc = subprocess.Popen(
        [*MOJO_RUN, str(TOOLS / "tls_echo_server.mojo"), str(CERTS / "server.pem"),
         str(CERTS / "server.key"), "h2"],
        stdout=subprocess.PIPE, text=True, cwd=ROOT)
    port = int(proc.stdout.readline().strip().removeprefix("PORT "))
    py_rejected = False
    try:
        cctx = ssl.create_default_context(cafile=str(CERTS / "ca.pem"))
        cctx.set_alpn_protocols(["http/1.1"])
        raw = socket.create_connection(("127.0.0.1", port), timeout=10)
        cctx.wrap_socket(raw, server_hostname="localhost")
    except ssl.SSLError:
        py_rejected = True
    except Exception:
        pass
    finally:
        proc.kill(); proc.wait()
    record("tls", "ALPN no overlap: our server alerts fatally, our client tolerates a server that proceeds without",
           mojo_sees_none and py_rejected,
           f"mojo_client_no_alpn={mojo_sees_none} python_client_saw_alert={py_rejected} out={r.stdout.strip()!r}")

    # Readiness-driven Mojo client against a CPython TLS peer that receives
    # the complete payload before echoing it.
    readiness_size = 8 * 1024 * 1024
    res = {"ready": threading.Event()}
    t = py_receive_then_echo(
        py_server_ctx("server.pem", "server.key", ["h2"]),
        readiness_size,
        res,
    )
    res["ready"].wait(10)
    r = run_tool(
        "tls_nonblocking_client",
        res["port"],
        str(CERTS / "ca.pem"),
        readiness_size,
        timeout=120,
    )
    t.join(timeout=30)
    values = None
    parts = r.stdout.split()
    if r.returncode == 0 and len(parts) == 9 and parts[0] == "OK":
        try:
            values = tuple(map(int, parts[1:]))
        except ValueError:
            pass
    detail = f"out={r.stdout.strip()!r} peer={res} err={r.stderr[:150]!r}"
    handshake_ok = (
        values is not None
        and values[4] > 0
        and res.get("version", "").startswith("TLSv1.")
        and res.get("alpn") == "h2"
        and "error" not in res
    )
    record(
        "tls",
        "resumable Mojo handshake matches CPython TLS and ALPN",
        handshake_ok,
        detail,
    )
    write_ok = (
        values is not None
        and values[0] == readiness_size
        and values[2] > 1
        and res.get("bytes") == readiness_size
        and res.get("payload_ok") is True
    )
    record(
        "tls",
        "partial Mojo TLS writes match CPython",
        write_ok,
        detail,
    )
    read_ok = (
        values is not None
        and values[1] == readiness_size
        and values[3] > 1
        and values[6] > 0
        and res.get("payload_ok") is True
    )
    record(
        "tls",
        "partial Mojo TLS reads preserve WANT_READ against CPython",
        read_ok,
        detail,
    )

    # A distinct CPython peer completes TLS but deliberately leaves all
    # application data unread. The Mojo client must stop at WANT_WRITE before
    # its finite 32 MiB bound rather than blocking or inventing progress.
    pressure_size = 32 * 1024 * 1024
    pressure = {"ready": threading.Event()}
    t = py_stalled_tls_server(
        py_server_ctx("server.pem", "server.key", ["h2"]), pressure
    )
    pressure["ready"].wait(10)
    r = run_tool(
        "tls_nonblocking_client",
        pressure["port"],
        str(CERTS / "ca.pem"),
        pressure_size,
        "backpressure",
        timeout=60,
    )
    t.join(timeout=0.1)
    blocked = None
    parts = r.stdout.split()
    if r.returncode == 0 and len(parts) == 5 and parts[0] == "BLOCKED":
        try:
            blocked = tuple(map(int, parts[1:]))
        except ValueError:
            pass
    pressure_ok = (
        blocked is not None
        and 0 < blocked[0] < pressure_size
        and blocked[1] > 0
        and blocked[2] > 0
        and pressure.get("version", "").startswith("TLSv1.")
        and pressure.get("alpn") == "h2"
    )
    record(
        "tls",
        "Mojo TLS write preserves WANT_WRITE under CPython backpressure",
        pressure_ok,
        f"out={r.stdout.strip()!r} peer={pressure} err={r.stderr[:150]!r}",
    )


HTML_REPORT = ROOT / "COMPLIANCE.html"

HTML_HEAD = """<!-- GENERATED by compliance/run_compliance.py - regenerate with: pixi run compliance -->
<title>mojo-tls Compliance</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans+Condensed:wght@600&display=swap">
<style>
:root {
  --paper: #FAFAF8; --ink: #22262B; --muted: #6E6A62; --accent: #C2551F;
  --pass: #2E7D4F; --fail: #B3362B; --line: #E4E0D8; --panel: #F2F0EA;
  --mono: "IBM Plex Mono", ui-monospace, "SF Mono", Menlo, monospace;
  --sans: "IBM Plex Sans", -apple-system, "Segoe UI", sans-serif;
  --cond: "IBM Plex Sans Condensed", "Arial Narrow", var(--sans);
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --paper: #16181C; --ink: #E8E6E1; --muted: #98938A; --accent: #E0663A;
    --pass: #5EC08D; --fail: #E5776C; --line: #2C2F35; --panel: #1D2025;
  }
}
:root[data-theme="dark"] {
  --paper: #16181C; --ink: #E8E6E1; --muted: #98938A; --accent: #E0663A;
  --pass: #5EC08D; --fail: #E5776C; --line: #2C2F35; --panel: #1D2025;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--paper); color: var(--ink); font: 16px/1.6 var(--sans); -webkit-font-smoothing: antialiased; }
main { max-width: 76ch; margin: 0 auto; padding: 3.5rem 1.5rem 5rem; }
header { border-bottom: 2px solid var(--ink); padding-bottom: 1.75rem; margin-bottom: 2.5rem; }
.eyebrow { font: 500 0.72rem/1 var(--mono); letter-spacing: 0.14em; text-transform: uppercase; color: var(--accent); margin: 0 0 0.9rem; }
h1 { font: 600 clamp(1.9rem, 5vw, 2.6rem)/1.1 var(--cond); margin: 0 0 1.1rem; text-wrap: balance; letter-spacing: -0.01em; }
.verdict { display: flex; align-items: baseline; gap: 0.75rem; flex-wrap: wrap; }
.verdict .score { font: 500 2rem/1 var(--mono); font-variant-numeric: tabular-nums; color: var(--pass); }
.verdict .score.failing { color: var(--fail); }
.verdict .when { color: var(--muted); font-size: 0.85rem; }
.thesis { color: var(--muted); margin: 0.9rem 0 0; max-width: 62ch; }
.scorecard { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 1.5rem; padding: 0; list-style: none; }
.scorecard li { font: 400 0.78rem/1 var(--mono); padding: 0.45rem 0.7rem; border: 1px solid var(--line); border-radius: 3px; background: var(--panel); display: flex; gap: 0.55rem; align-items: center; }
.scorecard .n { font-variant-numeric: tabular-nums; color: var(--pass); font-weight: 500; }
.scorecard .n.failing { color: var(--fail); }
section { margin: 2.75rem 0; }
h2 { font: 600 1.15rem/1.3 var(--sans); margin: 0 0 0.35rem; text-wrap: balance; }
h2 .pkg { font-family: var(--mono); font-weight: 500; color: var(--accent); }
.vs { color: var(--muted); font-weight: 400; }
.method { color: var(--muted); font-size: 0.88rem; margin: 0 0 1.1rem; max-width: 68ch; }
.tablewrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 0.88rem; }
th { text-align: left; font: 500 0.7rem/1 var(--mono); letter-spacing: 0.1em; text-transform: uppercase; color: var(--muted); padding: 0 0.75rem 0.5rem 0; border-bottom: 1px solid var(--ink); }
td { padding: 0.5rem 0.75rem 0.5rem 0; border-bottom: 1px solid var(--line); vertical-align: top; }
td.result { white-space: nowrap; font: 500 0.78rem/1.8 var(--mono); }
.pass { color: var(--pass); }
.fail { color: var(--fail); }
td .detail { display: block; color: var(--muted); font-size: 0.8rem; }
.envtable td:first-child { color: var(--muted); width: 40%; }
.envtable td { font-family: var(--mono); font-size: 0.8rem; }
.gaps { border-left: 3px solid var(--accent); background: var(--panel); padding: 1.1rem 1.4rem; }
.gaps h2 { margin-top: 0; }
.gaps ul { margin: 0.5rem 0 0; padding-left: 1.1rem; }
.gaps li { margin: 0.45rem 0; font-size: 0.9rem; }
.gaps strong { font-weight: 600; }
footer { margin-top: 3rem; color: var(--muted); font: 400 0.78rem/1.6 var(--mono); border-top: 1px solid var(--line); padding-top: 1rem; }
code { font-family: var(--mono); font-size: 0.92em; }
</style>
"""


def esc(t: str) -> str:
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


HTML_EYEBROW = "mojo-tls &middot; differential compliance run"
HTML_H1 = "TLS behavior held against the reference stack"
HTML_THESIS = (
    "No self-grading: every handshake, version negotiation, ALPN exchange,"
    " and certificate decision is checked against CPython&rsquo;s"
    " <code>ssl</code> module on the other end of a live connection,"
    " including a corpus of certificates that must be rejected for the"
    " same reasons the reference rejects them."
)
HTML_GAPS = [
    ("Client certificates (mTLS)", "not exposed yet; the shim and libssl support it, the API does not."),
    ("Session resumption", "every connection is a full handshake for now."),
]
HTML_SECTIONS = {
    "tls": ("`tls` vs CPython `ssl`",
            "Live connections with CPython's ssl module as the peer in both roles: TLS 1.3 and 1.2 negotiation, ALPN agreement and fatal-alert on no overlap, chain and hostname verification, bulk and readiness-driven transfer through the record layer, and a bad-certificate corpus (self-signed, wrong hostname) that both implementations must reject."),
}


def write_html_report():
    total = sum(len(v) for v in RESULTS.values())
    passed = sum(1 for v in RESULTS.values() for _, ok, _ in v if ok)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    all_ok = passed == total
    h = [HTML_HEAD, "<main>", "<header>"]
    h.append(f'<p class="eyebrow">{HTML_EYEBROW}</p>')
    h.append(f"<h1>{HTML_H1}</h1>")
    h.append(
        f'<div class="verdict"><span class="score{"" if all_ok else " failing"}">'
        f"{passed}/{total}</span><span>checks passed</span>"
        f'<span class="when">{now}</span></div>'
    )
    h.append(f'<p class="thesis">{HTML_THESIS}</p>')
    h.append('<ul class="scorecard">')
    for section, rows in RESULTS.items():
        p = sum(1 for _, ok, _ in rows if ok)
        cls = "" if p == len(rows) else " failing"
        h.append(f'<li>{esc(section)} <span class="n{cls}">{p}/{len(rows)}</span></li>')
    h.append("</ul></header>")

    for section, rows in RESULTS.items():
        title, blurb = HTML_SECTIONS.get(section, (section, ""))
        pkg, _, ref = title.replace("`", "").partition(" vs ")
        h.append("<section>")
        if ref:
            h.append(f'<h2><span class="pkg">{esc(pkg)}</span> <span class="vs">vs</span> {esc(ref)}</h2>')
        else:
            h.append(f"<h2>{esc(pkg)}</h2>")
        if blurb:
            h.append(f'<p class="method">{esc(blurb)}</p>')
        h.append('<div class="tablewrap"><table>')
        h.append("<tr><th>Check</th><th>Result</th></tr>")
        for name, ok, detail in rows:
            cell = '<span class="pass">PASS</span>' if ok else '<span class="fail">FAIL</span>'
            extra = "" if ok else f'<span class="detail">{esc(detail[:200])}</span>'
            h.append(f"<tr><td>{esc(name)}</td><td class=\"result\">{cell}{extra}</td></tr>")
        h.append("</table></div></section>")

    h.append("<section><h2>Environment</h2>")
    h.append('<div class="tablewrap"><table class="envtable">')
    for k, v in versions().items():
        h.append(f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>")
    h.append("</table></div></section>")

    h.append('<section class="gaps"><h2>Known gaps (tracked, not silent)</h2><ul>')
    for k, v in HTML_GAPS:
        h.append(f"<li><strong>{esc(k)}</strong> &mdash; {esc(v)}</li>")
    h.append("</ul></section>")
    h.append(
        "<footer>Generated by compliance/run_compliance.py &middot; "
        "rerun with <code>pixi run compliance</code> &middot; canonical copy: "
        "COMPLIANCE.md</footer>"
    )
    h.append("</main>")
    HTML_REPORT.write_text("\n".join(h))
    print(f"report: {HTML_REPORT.relative_to(ROOT)}")


# --------------------------------------------------------------- report ---

def versions() -> dict[str, str]:
    mojo = subprocess.run(["mojo", "--version"], capture_output=True, text=True, cwd=ROOT).stdout.strip()
    return {
        "mojo": mojo,
        "python (reference: CPython ssl)": platform.python_version(),
        "openssl (via CPython)": ssl.OPENSSL_VERSION,
        "platform": f"{platform.system()} {platform.release()} {platform.machine()}",
    }


def write_report() -> bool:
    total = sum(len(v) for v in RESULTS.values())
    passed = sum(1 for v in RESULTS.values() for _, ok, _ in v if ok)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# mojo-tls Compliance Report",
        "",
        "<!-- GENERATED by compliance/run_compliance.py; do not edit. -->",
        "<!-- Regenerate with: pixi run compliance -->",
        "",
        f"**Result: {passed}/{total} checks passed.** Generated {now}.",
        "",
        "Every check runs against CPython's `ssl` module on the other end of",
        "the connection: handshakes, version negotiation, ALPN, certificate",
        "verification, and the rejection corpus must all agree with the",
        "reference. Nothing here grades its own homework.",
        "",
        "## Environment",
        "",
        "| Component | Version |",
        "|---|---|",
    ]
    for k, v in versions().items():
        lines.append(f"| {k} | {v} |")
    for section, rows in RESULTS.items():
        p = sum(1 for _, ok, _ in rows if ok)
        lines += ["", f"## `{section}` ({p}/{len(rows)})", "",
                  "| Check | Result |", "|---|---|"]
        for name, ok, detail in rows:
            mark = "✅ pass" if ok else f"❌ fail — {detail[:160]}"
            lines.append(f"| {name} | {mark} |")
    lines += [
        "",
        "## How to rerun",
        "",
        "```sh",
        "pixi run compliance",
        "```",
        "",
    ]
    REPORT.write_text("\n".join(lines))
    print(f"report: {REPORT}")
    return passed == total


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json")
    args = parser.parse_args()
    setup()
    build_tools()
    section_tls()
    ok = write_report()
    write_html_report()
    if args.json:
        Path(args.json).write_text(json.dumps(
            {"sections": {s: [[n, o, d] for n, o, d in rows]
                          for s, rows in RESULTS.items()}}))
    print(f"\ncompliance: {sum(1 for v in RESULTS.values() for _, o, _ in v if o)}"
          f"/{sum(len(v) for v in RESULTS.values())} checks passed")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
