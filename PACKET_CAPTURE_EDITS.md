# packet_capture.py edits (do these on the Linux VM)

These are small copy-paste edits. They make the test traffic realistic (website names, DNS MX questions, SSH) and fix the test DNS server.
After the edits, run one capture and look at `data/features.csv`.


These edits are inside the long generated script, so copy them carefully. After the edits, run one capture and check `data/features.csv`.

**C1. Fix the test DNS server (it very likely crashes today).** Find:
```python
        "ip=bytes(map(int,'{{h2_ip}}'.split('.')));"
```
Replace with:
```python
        "ip=bytes(map(int,'" + h2_ip + "'.split('.')));"
```
Check afterwards: `cat /tmp/dns_server.log` should be empty (no ValueError).

**C2. Ask DNS for MX records sometimes.** In `do_dns`, find the last line of the bytes list:
```python
                       3, 99, 111, 109, 0, 0, 1, 0, 1])
```
Replace with:
```python
                       3, 99, 111, 109, 0, 0, (15 if i % 5 == 0 else 1), 0, 1])
```

**C3. HTTPS with a website name (SNI).** Replace the whole `do_https` function in `h1_gen_script` with:
```python
def do_https():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    names = ["bank.example.com", "www.example.com", "health.example.org", "cdn.example.net"]
    for i in range(n_https):
        try:
            raw = socket.create_connection((h2_ip, 8443), timeout=1)
            tls = ctx.wrap_socket(raw, server_hostname=names[i % len(names)])
            tls.sendall(b"GET / HTTP/1.0" + bytes([13, 10, 13, 10]))
            tls.recv(512)
            tls.close()
        except Exception:
            pass
```
(Connecting to a plain IP sends no name; `server_hostname` is what puts the name into the hello message.)

**C4. SSH greeting traffic.**
(a) In `h1_gen_script`, add this function next to `do_https`:
```python
def do_ssh():
    for i in range(20):
        try:
            s = socket.create_connection((h2_ip, 22), timeout=1)
            s.recv(64)
            s.sendall(b"SSH-2.0-APQClient" + bytes([13, 10]))
            s.close()
        except Exception:
            pass
```
and change the "TCP-heavy" block at the bottom of that script to:
```python
with ThreadPoolExecutor(max_workers=3) as ex:
    f1 = ex.submit(do_http)
    f2 = ex.submit(do_https)
    f3 = ex.submit(do_ssh)
    f1.result()
    f2.result()
    f3.result()
```
(b) In the generated Mininet script, right after the `dns_server_script` line (`h2.cmd(f'python3 -c "{{dns_server_script}}" ...`) add:
```python
    ssh_srv = ("import socket;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
               "s.bind(('0.0.0.0',22));s.listen(8);"
               "[(lambda c:(c.sendall(b'SSH-2.0-OpenSSH_9.6'+bytes([13,10])),c.close()))(s.accept()[0]) for _ in iter(int,1)]")
    h2.cmd(f'python3 -c "{{ssh_srv}}" > /tmp/ssh_server.log 2>&1 &')
```
(I tested this one-liner on another port; it answers every connection with the SSH greeting.)

**C5. Optional: scan-like traffic so the behaviour score has something to react to.** Before the line that runs `/tmp/h1_gen.py`, add (works only if `nmap` is installed):
```python
    h1.cmd('which nmap > /dev/null && nmap -sS -p 1-200 ' + h2_ip)
```
This is a small scan inside your own isolated test network. If the capture stops before the scan, raise `target_packets`.

**C6. Make the Settings page control the traffic generator (needed for the "Capture" settings).**
At the top of `packet_capture.py` add:
```python
import config as cfgmod
```
In `__init__`, find `self.target_packets = 1000` and replace it with:
```python
        self.target_packets = int(cfgmod.get("capture.target_packets", 1000))
```
In `capture_packets()`, find the lines `n_http = 60`, `n_https = 40`, `n_dns = 150`, `n_udp = 150`, `ping_count = 40` and replace all five with:
```python
            cap = cfgmod.get("capture")
            n_http, n_https, n_dns = cap["n_http"], cap["n_https"], cap["n_dns"]
            n_udp, ping_count = cap["n_udp"], cap["ping_count"]
```
Without C6 everything else still works. Only the "Capture" box on the Settings page has no effect.
