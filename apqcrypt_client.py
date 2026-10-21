#!/usr/bin/env python3
"""
APQCrypt Python client + command-line tool (wrapper for programs that use the REST API).
Needs only the Python standard library.

Command line:
  python apqcrypt_client.py health
  python apqcrypt_client.py decide --protocol HTTPS --port 443 [--payload-hex ...] [--resource AVAILABLE]
  python apqcrypt_client.py analyze capture.pcapng [--mode adaptive] [--encrypt]
  python apqcrypt_client.py decisions <job_id> [--csv]
  python apqcrypt_client.py config
Options for every command:  --url http://127.0.0.1:5000  --key <API key>   (key: file data/api_key.txt, or env APQ_KEY)

In your own code:
  from apqcrypt_client import APQCryptClient
  c = APQCryptClient("http://127.0.0.1:5000", key)
  print(c.decide(protocol="HTTPS", dest_port=443)["decision"])
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid


class APQCryptError(Exception):
    pass


class APQCryptClient:
    def __init__(self, base_url="http://127.0.0.1:5000", api_key=None, timeout=60):
        self.base = base_url.rstrip("/") + "/api/v1"
        self.key = api_key
        self.timeout = timeout

    def _call(self, method, path, body=None, headers=None, raw=False):
        h = {"Accept": "application/json"}
        if self.key:
            h["X-API-Key"] = self.key
        h.update(headers or {})
        req = urllib.request.Request(self.base + path, data=body, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = r.read()
                return data if raw else json.loads(data.decode())
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read().decode())
            except Exception:
                msg = {"error": str(e)}
            raise APQCryptError(f"HTTP {e.code}: {msg.get('error')} {msg.get('details') or ''}".strip())
        except urllib.error.URLError as e:
            raise APQCryptError(f"cannot reach {self.base}: {e.reason}")

    def health(self):
        return self._call("GET", "/health")

    def decide(self, **fields):
        return self._call("POST", "/decide", json.dumps(fields).encode(), {"Content-Type": "application/json"})

    def analyze(self, pcap_path, mode="adaptive", force_resource=None, encrypt=False, wait=True, poll=1.0):
        boundary = uuid.uuid4().hex
        parts = []
        for k, v in (("mode", mode), ("encrypt", "true" if encrypt else "false"), ("force_resource", force_resource or "")):
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
        with open(pcap_path, "rb") as f:
            content = f.read()
        parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="pcap"; filename="{os.path.basename(pcap_path)}"\r\n'
                      'Content-Type: application/octet-stream\r\n\r\n').encode() + content + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        job = self._call("POST", "/analyze", b"".join(parts), {"Content-Type": f"multipart/form-data; boundary={boundary}"})
        if not wait:
            return job
        while True:
            j = self.job(job["job_id"])
            if j["status"] in ("done", "failed"):
                return j
            time.sleep(poll)

    def job(self, job_id):
        return self._call("GET", f"/jobs/{job_id}")

    def decisions(self, job_id, csv=False):
        if csv:
            return self._call("GET", f"/jobs/{job_id}/decisions?format=csv", raw=True).decode()
        return self._call("GET", f"/jobs/{job_id}/decisions")

    def config(self):
        return self._call("GET", "/config")


def _key(args):
    if args.key:
        return args.key
    if os.environ.get("APQ_KEY"):
        return os.environ["APQ_KEY"]
    try:
        return open("data/api_key.txt").read().strip()
    except OSError:
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description="APQCrypt API client")
    ap.add_argument("--url", default="http://127.0.0.1:5000")
    ap.add_argument("--key", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("health")
    d = sub.add_parser("decide")
    d.add_argument("--protocol", default="TCP"); d.add_argument("--port", type=int, required=True)
    d.add_argument("--source-port", type=int, default=0); d.add_argument("--payload-hex", default="")
    d.add_argument("--resource", choices=["AVAILABLE", "CONSTRAINED"]); d.add_argument("--mode", default="adaptive")
    a = sub.add_parser("analyze")
    a.add_argument("pcap"); a.add_argument("--mode", default="adaptive"); a.add_argument("--encrypt", action="store_true")
    a.add_argument("--resource", choices=["AVAILABLE", "CONSTRAINED"])
    j = sub.add_parser("decisions")
    j.add_argument("job_id"); j.add_argument("--csv", action="store_true")
    sub.add_parser("config")
    args = ap.parse_args(argv)
    c = APQCryptClient(args.url, _key(args))
    try:
        if args.cmd == "health":
            out = c.health()
        elif args.cmd == "decide":
            body = {"protocol": args.protocol, "dest_port": args.port, "source_port": args.source_port, "mode": args.mode}
            if args.payload_hex:
                body["payload_hex"] = args.payload_hex
            if args.resource:
                body["resource_status"] = args.resource
            out = c.decide(**body)
        elif args.cmd == "analyze":
            out = c.analyze(args.pcap, args.mode, args.resource, args.encrypt)
        elif args.cmd == "decisions":
            out = c.decisions(args.job_id, args.csv)
        else:
            out = c.config()
    except APQCryptError as e:
        print("Error:", e, file=sys.stderr)
        return 1
    print(out if isinstance(out, str) else json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
