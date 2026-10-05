#!/usr/bin/env python3
"""ipIntel - look up an IP address across Shodan and other threat-intel sources.

Standard library only (Python 3.8+); nothing to pip install.
Run `python3 ipIntel.py --help` for usage.
"""

import sys

if sys.version_info < (3, 8):
    sys.exit("ipIntel needs Python 3.8 or newer")

import argparse
import concurrent.futures
import getpass
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

VERSION = "1.6.0"
USER_AGENT = "ipIntel/" + VERSION
DEFAULT_TIMEOUT = 15
MAX_RESPONSE_BYTES = 16 * 1024 * 1024  # Shodan host records with many banners can run to a few MB
MAX_ERROR_BYTES = 64 * 1024

# API keys: env var first, then a file. Paths are written with ~ so messages never show a username.
API_KEYS = {
    "shodan": {
        "label": "Shodan API key",
        "service": "Shodan",
        "env": "SHODAN_API_KEY",
        "file": "~/.config/shodan/api_key",
        "pattern": r"[A-Za-z0-9]{16,64}",
    },
    "threatfox": {
        "label": "abuse.ch Auth-Key",
        "service": "abuse.ch",
        "env": "ABUSECH_AUTH_KEY",
        "file": "~/.config/ipintel/abusech_auth_key",
        "pattern": r"[A-Za-z0-9_-]{16,128}",
    },
    "virustotal": {
        "label": "VirusTotal API key",
        "service": "VirusTotal",
        "env": "VIRUSTOTAL_API_KEY",
        "file": "~/.config/ipintel/virustotal_api_key",
        "pattern": r"[A-Za-z0-9]{32,128}",
    },
}

SHODAN_API = "https://api.shodan.io"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
THREATFOX_IOC_URL = "https://threatfox.abuse.ch/ioc/{id}/"
VIRUSTOTAL_API = "https://www.virustotal.com/api/v3/ip_addresses/"
VIRUSTOTAL_GUI_URL = "https://www.virustotal.com/gui/ip-address/{ip}"
VIRUSTOTAL_QUOTAS_API = "https://www.virustotal.com/api/v3/users/{key}/overall_quotas"
GREYNOISE_API = "https://api.greynoise.io/v3/community"
PROXYCHECK_API = "https://proxycheck.io/v2"

SPUR_URL = "https://spur.us/context/{ip}"
CENSYS_URL = "https://platform.censys.io/search?q={query}"


# --------------------------------------------------------------------------- HTTP

class SourceError(Exception):
    pass


class HTTPFailure(SourceError):
    def __init__(self, code, body):
        self.code = code
        self.body = body
        detail = api_message(body)
        super().__init__("HTTP %d%s" % (code, ": " + detail if detail else ""))


def api_message(body):
    if isinstance(body, dict):
        for field in ("error", "message", "detail"):
            if body.get(field):
                return str(body[field])
    return ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Treat redirects as errors so a request carrying the Shodan key can't be bounced elsewhere."""

    def redirect_request(self, *args, **kwargs):
        return None


def _build_opener():
    tls = ssl.create_default_context()  # verifies certificates and hostnames
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    return urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=tls))


OPENER = _build_opener()


def http_json(url, params=None, timeout=DEFAULT_TIMEOUT, body=None, headers=None):
    """GET a JSON object, or POST `body` as JSON. Error text never includes the URL or headers,
    which may carry API keys."""
    if not url.startswith("https://"):
        raise SourceError("refusing a non-HTTPS request")
    if params:
        url = url + "?" + urllib.parse.urlencode(params)
    all_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    all_headers.update(headers or {})
    payload = None
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        all_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=payload, headers=all_headers)
    try:
        with OPENER.open(req, timeout=timeout) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read(MAX_ERROR_BYTES).decode("utf-8", "replace"))
        except Exception:
            body = None
        raise HTTPFailure(e.code, body)
    except urllib.error.URLError as e:
        raise SourceError("network error: %s" % (e.reason,))
    except (socket.timeout, TimeoutError):
        raise SourceError("timed out after %ss" % timeout)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise SourceError("response larger than %d MB, ignored" % (MAX_RESPONSE_BYTES // 1024 // 1024))
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        raise SourceError("response was not valid JSON")
    if not isinstance(data, dict):
        raise SourceError("unexpected response format")
    return data


class Throttle:
    """Keeps calls to one service at least `interval` seconds apart."""

    def __init__(self, interval):
        self.interval = interval
        self.lock = threading.Lock()
        self.next_ok = 0.0

    def wait(self):
        with self.lock:
            delay = self.next_ok - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self.next_ok = time.monotonic() + self.interval


SHODAN_THROTTLE = Throttle(1.1)       # Shodan allows ~1 request/second
VIRUSTOTAL_THROTTLE = Throttle(15.1)  # VirusTotal's public API allows 4 requests/minute


# --------------------------------------------------------------------------- sources
# Each lookup returns a dict: {"kind": ..., "data": ...} plus optional "note" / "skipped" / "needs_key".
# Raising SourceError marks the source as failed for that IP.

def key_missing(service):
    return {"kind": service, "needs_key": service,
            "message": "%s required" % API_KEYS[service]["label"]}


def lookup_shodan(ip, ctx):
    key = ctx["keys"].get("shodan")
    if not key:
        return key_missing("shodan")
    url = SHODAN_API + "/shodan/host/" + ip
    for attempt in (1, 2):
        SHODAN_THROTTLE.wait()
        try:
            return {"kind": "shodan", "data": http_json(url, {"key": key}, ctx["timeout"])}
        except HTTPFailure as e:
            if e.code == 404:
                return {"kind": "shodan", "data": None}  # Shodan simply has no record of this IP
            if e.code == 429 and attempt == 1:
                time.sleep(2)
                continue
            raise SourceError({
                401: "IP lookups need a Shodan API key",
                403: "access denied for this API key",
                429: "rate limited by Shodan, try again shortly",
            }.get(e.code, str(e)))


def ioc_host(ioc):
    """Host part of a ThreatFox IOC: '1.2.3.4:443', '[2001:db8::1]:443', a bare IP, or a URL."""
    ioc = str(ioc)
    if "://" in ioc:
        return urllib.parse.urlsplit(ioc).hostname or ""
    if ioc.startswith("[") or ioc.count(":") == 1:
        ioc = ioc.rsplit(":", 1)[0]
    return ioc.strip("[]")


def ioc_is_ip(item, ip):
    try:
        return ipaddress.ip_address(ioc_host(item.get("ioc", ""))) == ipaddress.ip_address(ip)
    except ValueError:
        return False


def lookup_threatfox(ip, ctx):
    key = ctx["keys"].get("threatfox")
    if not key:
        return key_missing("threatfox")
    try:
        body = http_json(THREATFOX_API, timeout=ctx["timeout"], headers={"Auth-Key": key},
                         body={"query": "search_ioc", "search_term": ip})
    except HTTPFailure as e:
        if e.code in (401, 403):
            raise SourceError("Auth-Key rejected by abuse.ch")
        raise
    status = body.get("query_status")
    if status == "no_result":
        return {"kind": "threatfox", "data": []}
    if status != "ok":
        raise SourceError("ThreatFox query failed: %s" % status)
    # search_ioc matches substrings (8.8.8.8 also hits 8.8.8.80), so keep only IOCs whose host is this IP.
    matches = [item for item in body.get("data") or [] if isinstance(item, dict) and ioc_is_ip(item, ip)]
    matches.sort(key=lambda item: str(item.get("first_seen") or ""), reverse=True)
    return {"kind": "threatfox", "data": matches}


def virustotal_error(e):
    error = e.body.get("error") if isinstance(e.body, dict) else None
    code = error.get("code") if isinstance(error, dict) else None
    if e.code == 401:
        return "VirusTotal rejected the API key"
    if e.code == 429:
        return ("VirusTotal quota used up (the public API allows 4 lookups/minute, 500/day)"
                if code == "QuotaExceededError" else "rate limited by VirusTotal, try again shortly")
    return "HTTP %d%s" % (e.code, ": " + clean(code) if code else "")


def lookup_virustotal(ip, ctx):
    key = ctx["keys"].get("virustotal")
    if not key:
        return key_missing("virustotal")
    VIRUSTOTAL_THROTTLE.wait()
    try:
        body = http_json(VIRUSTOTAL_API + ip, timeout=ctx["timeout"], headers={"x-apikey": key})
    except HTTPFailure as e:
        if e.code == 404:  # VirusTotal has no report for this IP
            return {"kind": "virustotal", "data": None, "link": VIRUSTOTAL_GUI_URL.format(ip=ip)}
        raise SourceError(virustotal_error(e))
    data = body.get("data")
    attributes = data.get("attributes") if isinstance(data, dict) else None
    if not isinstance(attributes, dict):
        raise SourceError("unexpected response format")
    return {"kind": "virustotal", "data": attributes, "link": VIRUSTOTAL_GUI_URL.format(ip=ip)}


def lookup_greynoise(ip, ctx):
    if ipaddress.ip_address(ip).version != 4:
        return {"kind": "greynoise", "skipped": "IPv4 only"}
    try:
        data = http_json(GREYNOISE_API + "/" + ip, timeout=ctx["timeout"])
    except HTTPFailure as e:
        # 404 is a normal answer here: "IP not observed scanning the internet".
        if e.code == 404 and isinstance(e.body, dict):
            data = e.body
        elif e.code == 429:
            raise SourceError("rate limited (community API has a small daily allowance)")
        else:
            raise
    return {"kind": "greynoise", "data": data}


def lookup_proxycheck(ip, ctx):
    body = http_json(PROXYCHECK_API + "/" + ip, {"vpn": 1, "asn": 1, "risk": 1}, ctx["timeout"])
    if body.get("status") not in ("ok", "warning"):
        raise SourceError(body.get("message") or "status: %s" % body.get("status"))
    # The result is keyed by the IP as proxycheck normalised it, so don't rely on our spelling.
    entry = next((v for v in body.values() if isinstance(v, dict) and "proxy" in v), None)
    if entry is None:
        raise SourceError("no result in response")
    return {"kind": "proxycheck", "data": entry, "note": body.get("message") if body.get("status") == "warning" else None}


SOURCES = {
    "shodan": ("Shodan", lookup_shodan),
    "threatfox": ("ThreatFox (abuse.ch)", lookup_threatfox),
    "virustotal": ("VirusTotal", lookup_virustotal),
    "greynoise": ("GreyNoise", lookup_greynoise),
    "proxycheck": ("proxycheck.io", lookup_proxycheck),
}
DEFAULT_SOURCES = tuple(SOURCES)


def run_source(fn, ip, ctx):
    try:
        return fn(ip, ctx)
    except SourceError as e:
        return {"error": str(e)}
    except Exception as e:  # a malformed response shouldn't kill the other sources
        return {"error": "unexpected %s: %s" % (type(e).__name__, e)}


def lookup_ip(ip, sources, ctx):
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(sources)) as pool:
        futures = {name: pool.submit(run_source, SOURCES[name][1], ip, ctx) for name in sources}
    return {name: futures[name].result() for name in sources}


def manual_links(ip):
    query = urllib.parse.quote('host.ip="%s"' % ip, safe="")
    return {"spur": SPUR_URL.format(ip=ip), "censys": CENSYS_URL.format(query=query)}


# --------------------------------------------------------------------------- output

def clean(value):
    """Strip control/escape characters: banners and titles are attacker-controlled text."""
    text = str(value)
    text = "".join(" " if ch in "\t\r\n" else ch for ch in text
                   if ch in "\t\r\n" or not unicodedata.category(ch).startswith("C"))
    return re.sub(r" {2,}", " ", text).strip()


def shorten(text, width=70):
    return text if len(text) <= width else text[: width - 1] + "…"


class Printer:
    LABEL_WIDTH = 12

    def __init__(self, color):
        self.color = color

    def paint(self, text, code):
        return "\033[%sm%s\033[0m" % (code, text) if self.color else text

    def bad(self, text):
        return self.paint(text, "31")

    def warn(self, text):
        return self.paint(text, "33")

    def good(self, text):
        return self.paint(text, "32")

    def dim(self, text):
        return self.paint(text, "2")

    def banner(self, ip):
        bar = "━" * max(4, 58 - len(ip))
        print()
        print(self.paint("━━ %s %s" % (ip, bar), "1;36"))

    def section(self, title, suffix=""):
        print(self.paint(title, "1") + (" " + self.dim(suffix) if suffix else ""))

    def kv(self, label, value, painter=None):
        """Print one field. `value` is remote data and gets cleaned; painters are applied after."""
        text = clean(value) if value not in (None, "") else ""
        text = painter(text) if painter and text else text or "—"
        print("  " + self.dim(label.ljust(self.LABEL_WIDTH)) + text)

    def sub(self, text, indent=4):
        print(" " * indent + text)

    def error(self, text):
        print("  " + self.bad("✗ " + clean(text)))


def join_nonempty(*parts, sep=", "):
    return sep.join(clean(x) for x in parts if x)


def fmt_timestamp(ts):
    if not ts:
        return None
    try:
        return datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S").strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return ts


def fmt_cert_date(raw):
    try:
        return datetime.strptime(raw, "%Y%m%d%H%M%SZ").strftime("%Y-%m-%d")
    except (TypeError, ValueError):
        return raw


def render_vulns(p, vulns):
    if isinstance(vulns, dict):
        vulns = list(vulns)
    vulns = sorted(vulns or [])
    if not vulns:
        p.kv("Vulns", "none listed")
        return
    shown = ", ".join(clean(v) for v in vulns[:8])
    more = " (+%d more)" % (len(vulns) - 8) if len(vulns) > 8 else ""
    p.kv("Vulns", "%d CVEs, version-based (unverified): %s%s" % (len(vulns), shown, more), p.bad)


def render_shodan(p, data):
    if not data:
        p.kv("Result", "Shodan has no record of this IP")
        return
    asn = data.get("asn")
    isp = data.get("isp")
    org = data.get("org")
    extra = join_nonempty(asn, "ISP " + isp if isp and isp != org else None)
    p.kv("Org", join_nonempty(org) + ("  (%s)" % extra if extra else ""))
    p.kv("Location", join_nonempty(data.get("city"), data.get("region_code"), data.get("country_name")))
    p.kv("Hostnames", ", ".join(data.get("hostnames") or []))
    p.kv("Domains", ", ".join(data.get("domains") or []))
    if data.get("os"):
        p.kv("OS", data["os"])
    p.kv("Tags", ", ".join(data.get("tags") or []))
    render_vulns(p, data.get("vulns"))
    p.kv("Last update", fmt_timestamp(data.get("last_update")))

    services = sorted(data.get("data") or [], key=lambda s: (s.get("port") or 0, s.get("transport") or ""))
    p.kv("Services", str(len(services)) if services else "none")
    for svc in services:
        port = "%s/%s" % (svc.get("port", "?"), svc.get("transport", "?"))
        product = join_nonempty(svc.get("product"), svc.get("version"), sep=" ")
        module = (svc.get("_shodan") or {}).get("module")
        desc = product or clean(module or "")
        vhost = ((svc.get("_shodan") or {}).get("options") or {}).get("hostname")
        if vhost:
            desc += p.dim("  (seen as %s)" % clean(vhost))
        p.sub("%-10s %s" % (clean(port), desc))

        http = svc.get("http") or {}
        details = []
        if http.get("status"):
            details.append("HTTP %s" % clean(http["status"]))
        if http.get("title"):
            details.append('"%s"' % shorten(clean(http["title"]), 50))
        if http.get("server"):
            details.append("server: " + shorten(clean(http["server"]), 40))
        if details:
            p.sub(p.dim("  ".join(details)), indent=15)

        cert = (svc.get("ssl") or {}).get("cert") or {}
        if cert:
            subject = (cert.get("subject") or {}).get("CN")
            issuer = cert.get("issuer") or {}
            issuer_name = issuer.get("O") or issuer.get("CN")
            line = "TLS cert %s  issuer: %s  expires %s" % (
                clean(subject or "?"), clean(issuer_name or "?"), clean(fmt_cert_date(cert.get("expires")) or "?"))
            if cert.get("expired"):
                line += "  " + p.bad("EXPIRED")
            p.sub(p.dim(line) if not cert.get("expired") else line, indent=15)


def render_greynoise(p, data):
    if data.get("riot"):
        p.kv("Verdict", "known benign service: %s" % clean(data.get("name") or "?"), p.good)
    elif data.get("noise"):
        cls = clean(data.get("classification") or "unknown")
        painter = p.bad if cls == "malicious" else p.warn if cls == "unknown" else p.good
        p.kv("Verdict", "seen scanning the internet, classified %s" % cls, painter)
        if data.get("name") and data["name"] != "unknown":
            p.kv("Actor", data["name"])
    else:
        p.kv("Verdict", data.get("message") or "not observed scanning")
    if data.get("last_seen"):
        p.kv("Last seen", data["last_seen"])


def render_proxycheck(p, data):
    is_proxy = str(data.get("proxy", "")).lower() == "yes"
    verdict = (p.warn("yes") if is_proxy else "no") + "  " + p.dim("(type: %s, risk %s/100)" % (
        clean(data.get("type") or "?"), clean(data.get("risk", "?"))))
    print("  " + p.dim("Proxy / VPN".ljust(Printer.LABEL_WIDTH)) + verdict)
    operator = (data.get("operator") or {}).get("name") if isinstance(data.get("operator"), dict) else None
    if operator:
        p.kv("Operator", operator, p.warn)
    p.kv("Provider", join_nonempty(data.get("provider"), data.get("organisation")
                                   if data.get("organisation") != data.get("provider") else None, sep=" / "))
    p.kv("Range", join_nonempty(data.get("range"), data.get("asn"), sep="  "))
    p.kv("Location", join_nonempty(data.get("city"), data.get("region"), data.get("isocode")))


THREATFOX_SHOWN = 10


def render_threatfox(p, matches):
    if not matches:
        p.kv("Verdict", "not in ThreatFox's IOC database")
        return
    p.kv("Verdict", "listed as %d IOC%s" % (len(matches), "" if len(matches) == 1 else "s"), p.bad)
    for item in matches[:THREATFOX_SHOWN]:
        threat = clean(item.get("threat_type_desc") or item.get("threat_type") or "?")
        p.sub("%s  %s · %s · confidence %s%%" % (
            p.bad(clean(item.get("ioc") or "?")), clean(item.get("malware_printable") or "unknown malware"),
            threat, clean(item.get("confidence_level", "?"))))
        seen = "first seen %s · last seen %s" % (clean(item.get("first_seen") or "?"), clean(item.get("last_seen") or "—"))
        if item.get("tags"):
            seen += " · tags: " + ", ".join(clean(t) for t in item["tags"])
        p.sub(p.dim(seen), indent=6)
        if str(item.get("id", "")).isdigit():
            p.sub(p.dim(THREATFOX_IOC_URL.format(id=item["id"])), indent=6)
    if len(matches) > THREATFOX_SHOWN:
        p.sub(p.dim("+%d older entries (use --json to see all)" % (len(matches) - THREATFOX_SHOWN)))


VIRUSTOTAL_ENGINES_SHOWN = 8


def fmt_unix_time(value):
    try:
        return datetime.fromtimestamp(int(value), timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def render_virustotal(p, data):
    if not data:
        p.kv("Result", "VirusTotal has no report for this IP")
        return
    stats = data.get("last_analysis_stats") or {}
    counts = {k: stats.get(k) if isinstance(stats.get(k), int) else 0
              for k in ("malicious", "suspicious", "harmless", "undetected")}
    total = sum(v for v in stats.values() if isinstance(v, int))
    summary = "%d malicious · %d suspicious · %d harmless · %d undetected  (%d engines)" % (
        counts["malicious"], counts["suspicious"], counts["harmless"], counts["undetected"], total)
    painter = p.bad if counts["malicious"] else p.warn if counts["suspicious"] else None
    p.kv("Detections", summary, painter)

    results = data.get("last_analysis_results") or {}
    flagged = []
    for engine, verdict in sorted(results.items()):
        if isinstance(verdict, dict) and verdict.get("category") in ("malicious", "suspicious"):
            flagged.append("%s (%s)" % (clean(verdict.get("engine_name") or engine),
                                        clean(verdict.get("result") or verdict["category"])))
    if flagged:
        more = " (+%d more)" % (len(flagged) - VIRUSTOTAL_ENGINES_SHOWN) if len(flagged) > VIRUSTOTAL_ENGINES_SHOWN else ""
        p.kv("Flagged by", ", ".join(flagged[:VIRUSTOTAL_ENGINES_SHOWN]) + more, p.bad)

    votes = data.get("total_votes") or {}
    reputation = data.get("reputation")
    p.kv("Reputation", "%s  (community votes: %s harmless, %s malicious)" % (
        reputation if isinstance(reputation, int) else "—", votes.get("harmless", 0), votes.get("malicious", 0)))
    asn = data.get("asn")
    owner = clean(data.get("as_owner") or "")
    if asn:
        owner = "%s (AS%s)" % (owner, clean(asn)) if owner else "AS%s" % clean(asn)
    p.kv("Owner", join_nonempty(owner, data.get("country")))
    p.kv("Network", data.get("network"))
    if data.get("tags"):
        p.kv("Tags", ", ".join(clean(t) for t in data["tags"]))
    p.kv("Last scan", fmt_unix_time(data.get("last_analysis_date")))


RENDERERS = {
    "shodan": render_shodan,
    "threatfox": render_threatfox,
    "virustotal": render_virustotal,
    "greynoise": render_greynoise,
    "proxycheck": render_proxycheck,
}


def key_hint(service):
    return "add it with `python3 ipIntel.py --init %s`" % service


def print_report(p, ip, results, show_links):
    p.banner(ip)
    for name, result in results.items():
        title = SOURCES[name][0]
        p.section(title, "(%s)" % clean(result["note"]) if result.get("note") else "")
        if "error" in result:
            p.error(result["error"])
        elif "needs_key" in result:
            service = result["needs_key"]
            p.kv("API key", "%s required, %s" % (API_KEYS[service]["label"], key_hint(service)), p.warn)
        elif "skipped" in result:
            p.kv("Skipped", result["skipped"])
        else:
            RENDERERS[result["kind"]](p, result["data"])
            if result.get("link"):
                p.kv("Link", result["link"])
        print()
    if show_links:
        p.section("Check manually", "(browser; rate-limited, may show a bot check)")
        for label, url in (("Spur", manual_links(ip)["spur"]), ("Censys", manual_links(ip)["censys"])):
            print("  " + p.dim(label.ljust(Printer.LABEL_WIDTH)) + url)
        print()


# --------------------------------------------------------------------------- input

DEFANG = re.compile(r"[\[\(\{]\s*\.\s*[\]\)\}]")


def parse_targets(tokens, warn):
    """Turn raw tokens into a de-duplicated list of public IPs, warning about the rest."""
    seen, ips = set(), []
    for raw in tokens:
        tok = DEFANG.sub(".", raw.strip().strip("\"'<>"))
        if not tok:
            continue
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}:\d+", tok):  # 1.2.3.4:443
            tok = tok.rsplit(":", 1)[0]
        try:
            addr = ipaddress.ip_address(tok.strip("[]"))
        except ValueError:
            warn("skipping %r: not an IP address" % raw)
            continue
        if not addr.is_global:
            warn("skipping %s: private/reserved address, public intel sources have nothing on it" % addr)
            continue
        ip = str(addr)
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips


def read_tokens(stream):
    tokens = []
    for line in stream:
        line = line.split("#", 1)[0]
        tokens.extend(t for t in re.split(r"[\s,;]+", line) if t)
    return tokens


# --------------------------------------------------------------------------- key / account

def warn(msg):
    print("ipIntel: " + msg, file=sys.stderr)


def key_path(service):
    return os.path.expanduser(API_KEYS[service]["file"])


def load_key(service):
    spec = API_KEYS[service]
    key = os.environ.get(spec["env"], "").strip()
    if key:
        return key
    path, shown = key_path(service), spec["file"]
    try:
        f = open(path, encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as e:
        warn("can't read %s: %s" % (shown, e.strerror))
        return None
    with f:
        st = os.fstat(f.fileno())
        if st.st_uid != os.getuid():
            warn("ignoring %s: it's owned by another user" % shown)
            return None
        if st.st_mode & 0o077:
            warn("%s is readable by other users; fix with: chmod 600 %s" % (shown, shown))
        return f.read(4096).strip() or None


def save_key(service, key):
    """Write the key atomically with owner-only permissions."""
    path = key_path(service)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = "%s.tmp-%d" % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(key + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)  # replaces a symlink at the destination rather than writing through it
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


VIRUSTOTAL_QUOTAS = (("api_requests_daily", "today"), ("api_requests_hourly", "this hour"),
                     ("api_requests_monthly", "this month"))


def virustotal_quotas(key, timeout):
    """Used/allowed lookups per period. VirusTotal documents this call as not consuming quota."""
    url = VIRUSTOTAL_QUOTAS_API.format(key=urllib.parse.quote(key, safe=""))
    body = http_json(url, timeout=timeout, headers={"x-apikey": key})
    data = body.get("data")
    if not isinstance(data, dict):
        raise SourceError("unexpected response format")
    usage = []
    for field, period in VIRUSTOTAL_QUOTAS:
        quota = data.get(field)
        if isinstance(quota, dict) and isinstance(quota.get("user"), dict):
            quota = quota["user"]  # per-user figures, as opposed to a group's shared allowance
        if isinstance(quota, dict) and isinstance(quota.get("allowed"), int):
            used = quota.get("used") if isinstance(quota.get("used"), int) else 0
            usage.append("%s %s of %s used" % (period, "{:,}".format(used), "{:,}".format(quota["allowed"])))
    return usage


def check_key(service, key, timeout):
    """Ask the service whether a key works, without spending any lookups.
    Returns (accepted, detail); accepted is None when the service couldn't be asked."""
    try:
        if service == "shodan":
            info = http_json(SHODAN_API + "/api-info", {"key": key}, timeout)
            return True, "plan %s · query credits %s · scan credits %s" % (
                clean(info.get("plan") or "?"), clean(info.get("query_credits", "?")), clean(info.get("scan_credits", "?")))
        if service == "threatfox":
            # Fetch one IOC by ID: tiny response, and abuse.ch checks the Auth-Key before anything else.
            http_json(THREATFOX_API, timeout=timeout, headers={"Auth-Key": key}, body={"query": "ioc", "id": 1})
            return True, "key accepted (abuse.ch publishes no usage quota)"
        usage = virustotal_quotas(key, timeout)
        return True, " · ".join(usage) if usage else "key accepted (no quota details returned)"
    except HTTPFailure as e:
        if e.code == 401 or (service == "threatfox" and e.code == 403):
            return False, "key rejected"
        return None, str(e)
    except SourceError as e:
        return None, str(e)


def init_one(service, timeout, optional):
    spec = API_KEYS[service]
    label, shown = spec["label"], spec["file"]
    if os.path.exists(key_path(service)):
        answer = input("Your %s is already saved at %s. Replace it? [y/N] " % (label, shown))
        if answer.strip().lower() not in ("y", "yes"):
            print("Kept your existing %s." % label)
            return True
    prompt = "%s (input hidden%s): " % (label, ", Enter to skip" if optional else "")
    key = getpass.getpass(prompt).strip()
    if not key:
        print("Skipped." if optional else "No key entered; nothing saved.", file=sys.stderr)
        return optional
    if not re.fullmatch(spec["pattern"], key):
        print("That doesn't look like a %s; nothing saved." % label, file=sys.stderr)
        return False
    accepted, message = check_key(service, key, timeout)
    if accepted is False:
        print("%s rejected that key; nothing saved." % spec["service"], file=sys.stderr)
        return False
    if accepted:
        print("%s accepted the key: %s" % (spec["service"], message))
    else:
        print("Couldn't verify the key (%s); saving it anyway." % message, file=sys.stderr)
    try:
        save_key(service, key)
    except OSError as e:
        print("Couldn't save the key to %s: %s" % (shown, e.strerror), file=sys.stderr)
        return False
    print("Saved to %s (readable only by you)." % shown)
    if os.environ.get(spec["env"]):
        print("Note: %s is set in your environment and takes priority over this file." % spec["env"])
    return True


def cmd_init(which, timeout):
    services = list(API_KEYS) if which == "all" else [which]
    ok = True
    for service in services:
        if len(services) > 1:
            print("\n== %s ==" % API_KEYS[service]["label"])
        ok = init_one(service, timeout, optional=len(services) > 1) and ok
    return 0 if ok else 1


def cmd_account(keys, timeout, p):
    """Check every saved key and show what each service reports about its plan or quota."""
    names = {"shodan": "Shodan", "threatfox": "ThreatFox", "virustotal": "VirusTotal"}
    all_ok = True
    for service in API_KEYS:
        name = names.get(service, service).ljust(Printer.LABEL_WIDTH)
        if not keys.get(service):
            print("  " + p.dim(name) + p.warn("no key saved, %s" % key_hint(service)))
            all_ok = False
            continue
        accepted, detail = check_key(service, keys[service], timeout)
        if accepted:
            print("  " + p.dim(name) + detail)
        elif accepted is False:
            print("  " + p.dim(name) + p.bad("key rejected, replace it with `python3 ipIntel.py --init %s`" % service))
            all_ok = False
        else:
            print("  " + p.dim(name) + p.bad("couldn't check: %s" % clean(detail)))
            all_ok = False
    return 0 if all_ok else 1


# --------------------------------------------------------------------------- main

def timeout_seconds(text):
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError("not a number: %r" % text)
    if not 1 <= value <= 120:
        raise argparse.ArgumentTypeError("must be between 1 and 120 seconds")
    return value


def build_parser():
    parser = argparse.ArgumentParser(
        prog="ipIntel.py",
        description="Look up IP addresses in Shodan, ThreatFox, VirusTotal, GreyNoise and proxycheck.io, "
                    "and print Spur/Censys links for manual checks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""sources (-s):
  shodan      Shodan host lookup (ports, services, certs, CVEs)       [API key required]
  threatfox   abuse.ch ThreatFox: is this IP a known malware / C2 IOC? [API key required]
  virustotal  VirusTotal: antivirus engine verdicts, reputation, owner  [API key required]
  greynoise   GreyNoise community: is this IP scanning the internet / a known benign service?
  proxycheck  proxycheck.io: proxy/VPN verdict, risk score, operator

examples:
  python3 ipIntel.py 8.8.8.8
  python3 ipIntel.py 8.8.8[.]8 1.1.1.1 -s shodan,greynoise
  python3 ipIntel.py -f iocs.txt --json > results.json

first time:
  python3 ipIntel.py --init            save your Shodan, abuse.ch and VirusTotal keys
  python3 ipIntel.py --init threatfox  save or replace just one of them

API keys:
  Shodan      ~/.config/shodan/api_key
              Get an API key from https://account.shodan.io
  ThreatFox   ~/.config/ipintel/abusech_auth_key
              Get an Auth-Key from https://auth.abuse.ch
  VirusTotal  ~/.config/ipintel/virustotal_api_key
              Sign up at https://www.virustotal.com/gui/join-us; the key is in your account settings""",
    )
    parser.add_argument("ips", nargs="*", metavar="IP", help="IPs to look up (defanged 1.2.3[.]4 is fine)")
    parser.add_argument("-f", "--file", help="read IPs from a file, one or more per line ('-' for stdin)")
    parser.add_argument("-s", "--sources", default=",".join(DEFAULT_SOURCES),
                        help="comma-separated sources to query (default: %s)" % ",".join(DEFAULT_SOURCES))
    parser.add_argument("--json", action="store_true", help="print raw results as JSON instead of a report")
    parser.add_argument("--no-links", action="store_true", help="don't print the Spur/Censys links")
    parser.add_argument("--no-color", action="store_true", help="disable colours (also honours NO_COLOR)")
    parser.add_argument("--timeout", type=timeout_seconds, default=DEFAULT_TIMEOUT,
                        help="per-request timeout in seconds, 1-120 (default: %d)" % DEFAULT_TIMEOUT)
    parser.add_argument("--init", nargs="?", const="all", choices=("all",) + tuple(API_KEYS), metavar="SERVICE",
                        help="save API keys, prompted and hidden: shodan, threatfox, virustotal, or all (default)")
    parser.add_argument("--account", action="store_true",
                        help="check your saved API keys and show each service's plan or quota usage")
    parser.add_argument("--version", action="version", version="ipIntel " + VERSION)
    return parser


def main(argv=None):
    sys.stdout.reconfigure(errors="replace")  # don't crash on a non-UTF-8 locale
    parser = build_parser()
    args = parser.parse_args(argv)

    color = not args.no_color and not args.json and sys.stdout.isatty() \
        and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"
    printer = Printer(color)

    if args.init:
        return cmd_init(args.init, args.timeout)
    keys = {service: load_key(service) for service in API_KEYS}
    if args.account:
        return cmd_account(keys, args.timeout, printer)

    sources = [s.strip().lower() for s in args.sources.split(",") if s.strip()]
    sources = list(dict.fromkeys(sources))
    unknown = [s for s in sources if s not in SOURCES]
    if unknown or not sources:
        parser.error("unknown source(s): %s (choose from %s)"
                     % (", ".join(unknown) or "none", ", ".join(SOURCES)))

    tokens = list(args.ips)
    if args.file == "-":
        tokens += read_tokens(sys.stdin)
    elif args.file:
        try:
            with open(args.file, encoding="utf-8", errors="replace") as f:
                tokens += read_tokens(f)
        except OSError as e:
            parser.error("can't read %s: %s" % (args.file, e.strerror))
    elif not tokens and not sys.stdin.isatty():
        tokens += read_tokens(sys.stdin)
    if not tokens:
        parser.print_usage(sys.stderr)
        print("ipIntel: give one or more IPs, -f FILE, or pipe IPs on stdin", file=sys.stderr)
        return 2

    ips = parse_targets(tokens, warn)
    if not ips:
        return 1

    ctx = {"keys": keys, "timeout": args.timeout}

    all_results, any_success = {}, False
    try:
        for ip in ips:
            results = lookup_ip(ip, sources, ctx)
            any_success = any_success or any("error" not in r and "needs_key" not in r for r in results.values())
            if args.json:
                all_results[ip] = dict(results, links=manual_links(ip))
            else:
                print_report(printer, ip, results, not args.no_links)
                sys.stdout.flush()
    except KeyboardInterrupt:
        print("\nipIntel: interrupted", file=sys.stderr)
        return 130

    if args.json:
        # ensure_ascii (the default) escapes control characters in remote data, so the JSON is terminal-safe.
        json.dump(all_results, sys.stdout, indent=2)
        print()
    return 0 if any_success else 3


if __name__ == "__main__":
    sys.exit(main())
