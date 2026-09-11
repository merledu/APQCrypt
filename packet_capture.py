import subprocess
import os
import time
from status_manager import StatusManager


class PacketCapture:
    def __init__(self):
        self.output_file = "data/traffic.pcapng"
        self.interface = "s1-eth1"
        self.min_acceptable_packets = 50
        # Raised default target from 70 -> 1000 packets.
        self.target_packets = 1000

    def capture_packets(self, count=1000):
        """
        Starts a small Mininet topology (h1 -- s1 -- h2), generates
        diverse traffic (ARP, ICMP, TCP, UDP/DNS, HTTP, HTTPS),
        then captures packets on the switch interface using tshark.

        OPTIMIZATIONS vs the original version:
          1. Traffic generation for HTTP/HTTPS/DNS/UDP now runs as
             ONE Python process per host (a small script written to
             /tmp and invoked via a single h1.cmd() call) instead of
             dozens of separate curl/python3 -c subprocess calls.
             Each subprocess spawn previously cost real overhead
             (process fork/exec, mininet's own cmd()/waitOutput()
             round trip) -- collapsing ~20+ calls into 1-2 removes
             most of that.
          2. tshark is told the EXACT target packet count
             ("-a packets:{target}") instead of target*3, so it
             auto-stops as soon as it has enough packets instead of
             over-capturing and then waiting on a long fixed timeout.
          3. Fixed sleep() calls trimmed to the minimum needed for
             interfaces/servers to come up, instead of conservative
             round numbers.
          4. File permission fixup (chown/chmod/rm) combined into a
             single sudo bash -c call instead of 3 separate
             subprocess spawns.

        Targets ~1000 packets but does NOT hard-fail if fewer are
        captured -- whatever is captured (as long as it's > 0) is
        passed along to the rest of the pipeline.
        """
        try:
            os.makedirs("data", exist_ok=True)
            abs_output = os.path.abspath(self.output_file)
            tmp_output = "/tmp/traffic_capture.pcapng"

            StatusManager.update_status("Capture", "Cleaning previous Mininet state...", 10)
            subprocess.run(["sudo", "mn", "-c"], capture_output=True, timeout=20)
            time.sleep(0.5)

            target = max(count, self.target_packets)

            # Traffic volume knobs. DNS/UDP are cheap (1-2 packets per
            # send, no handshake) so they carry most of the volume.
            # HTTP/HTTPS carry fewer requests each but multiple packets
            # per request (TCP/TLS handshake + data + teardown).
            n_http = 60
            n_https = 40
            n_dns = 150
            n_udp = 150
            ping_count = 40
            ping_interval = 0.05

            StatusManager.update_status(
                "Capture",
                f"Starting Mininet topology and capturing traffic "
                f"(target ~{target} packets across TCP/UDP/DNS/HTTP/HTTPS/ICMP/ARP)...",
                15
            )

            # Single-process traffic generator run on h1. Doing all
            # requests inside one Python process (loops) instead of
            # spawning curl/python3 -c per request removes per-call
            # process-spawn overhead, which was the main cost in the
            # original sequential-subprocess traffic generation.
            h1_gen_script = '''
import socket, ssl, sys, urllib.request
from concurrent.futures import ThreadPoolExecutor

h2_ip = sys.argv[1]
n_http = int(sys.argv[2])
n_https = int(sys.argv[3])
n_dns = int(sys.argv[4])
n_udp = int(sys.argv[5])

def do_dns():
    # DNS/UDP run FIRST and with a near-zero receive timeout.
    # Previously this ran AFTER HTTP/HTTPS with a 0.5s recv timeout
    # per query -- tshark's packet-count cap was almost always hit
    # by HTTP/HTTPS traffic alone before DNS/UDP even started, so
    # every one of those 0.5s waits (up to 150 x 0.5s = 75s) was
    # pure wasted time capturing nothing. Running DNS/UDP first with
    # a tiny timeout means (a) they actually get captured within the
    # packet budget, and (b) no more multi-second wasted stalls.
    dsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dsock.settimeout(0.03)
    for i in range(n_dns):
        try:
            b0 = i % 256
            q = bytes([b0, b0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
                       3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101,
                       3, 99, 111, 109, 0, 0, 1, 0, 1])
            dsock.sendto(q, (h2_ip, 53))
            try:
                dsock.recvfrom(512)
            except socket.timeout:
                pass
        except Exception:
            pass

def do_udp():
    usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(n_udp):
        try:
            usock.sendto(b"ping", (h2_ip, 9999))
        except Exception:
            pass

def do_http():
    for i in range(n_http):
        try:
            urllib.request.urlopen(f"http://{h2_ip}:8000/", timeout=1)
        except Exception:
            pass

def do_https():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for i in range(n_https):
        try:
            urllib.request.urlopen(f"https://{h2_ip}:8443/", timeout=1, context=ctx)
        except Exception:
            pass

# ---- Cheap protocols first (guarantees they land inside the packet
#      budget), run concurrently to cut wall-clock time further ----
with ThreadPoolExecutor(max_workers=2) as ex:
    f1 = ex.submit(do_dns)
    f2 = ex.submit(do_udp)
    f1.result()
    f2.result()

# ---- TCP-heavy protocols last, also run concurrently ----
with ThreadPoolExecutor(max_workers=2) as ex:
    f1 = ex.submit(do_http)
    f2 = ex.submit(do_https)
    f1.result()
    f2.result()

print("h1_gen done")
'''

            script = f'''
import time
import subprocess
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.node import OVSSwitch
from mininet.log import setLogLevel

setLogLevel('error')

class SimpleTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        s1 = self.addSwitch('s1')
        self.addLink(h1, s1)
        self.addLink(h2, s1)

try:
    net = Mininet(topo=SimpleTopo(), link=TCLink, switch=OVSSwitch, controller=None)
    net.start()

    # Configure switch to forward all traffic
    for sw in net.switches:
        sw.cmd('ovs-ofctl add-flow ' + sw.name + ' action=normal')

    h1 = net.get('h1')
    h2 = net.get('h2')
    s1 = net.get('s1')

    # Get the correct interface for capturing
    iface = None
    for intf_name in s1.intfNames():
        if intf_name != 'lo' and 's1-eth' in intf_name:
            iface = intf_name
            break

    if not iface:
        ifaces = [i for i in s1.intfNames() if i != 'lo']
        if ifaces:
            iface = ifaces[0]

    print(f"Switch interfaces: {{s1.intfNames()}}")
    print(f"Using interface: {{iface}}")

    if not iface:
        raise Exception("No switch interface found for tshark capture")

    # ============ WRITE THE SINGLE-PROCESS TRAFFIC GENERATOR ============
    with open("/tmp/h1_gen.py", "w") as gf:
        gf.write({h1_gen_script!r})

    # ============ START CAPTURE FIRST ============
    print("Starting tshark capture...")
    tshark_cmd = [
        "tshark", "-i", iface, "-w", "{tmp_output}",
        "-a", "packets:{target}",
        "-a", "duration:25"
    ]

    tshark_proc = subprocess.Popen(
        tshark_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # Give tshark time to actually attach to the interface
    time.sleep(0.5)

    h1_ip = h1.IP()
    h2_ip = h2.IP()
    print(f"h1 IP: {{h1_ip}}, h2 IP: {{h2_ip}}")

    # ============ SETUP SERVERS ON h2 (still individual, but only 3 calls) ============
    # Plain HTTP server (port 8000)
    h2.cmd('python3 -m http.server 8000 > /tmp/http_server.log 2>&1 &')

    # Self-signed HTTPS server (port 8443)
    h2.cmd(
        "openssl req -x509 -newkey rsa:2048 -keyout /tmp/key.pem "
        "-out /tmp/cert.pem -days 1 -nodes "
        "-subj '/CN=h2.local' > /tmp/ssl_gen.log 2>&1"
    )
    https_server_script = (
        "import http.server, ssl;"
        "h=http.server.HTTPServer(('0.0.0.0',8443),http.server.SimpleHTTPRequestHandler);"
        "ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);"
        "ctx.load_cert_chain('/tmp/cert.pem','/tmp/key.pem');"
        "h.socket=ctx.wrap_socket(h.socket,server_side=True);"
        "h.serve_forever()"
    )
    h2.cmd(f'python3 -c "{{https_server_script}}" > /tmp/https_server.log 2>&1 &')

    # Tiny DNS server (UDP/53) -- responds to any A query with h2's IP
    dns_server_script = (
        "import socket,struct;"
        "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
        "s.bind(('0.0.0.0',53));"
        "ip=bytes(map(int,'{{h2_ip}}'.split('.')));"
        "[s.sendto(d[:2]+b'\\\\x81\\\\x80'+d[4:6]+d[4:6]+b'\\\\x00\\\\x00\\\\x00\\\\x00'+"
        "d[12:]+b'\\\\xc0\\\\x0c\\\\x00\\\\x01\\\\x00\\\\x01\\\\x00\\\\x00\\\\x00\\\\x3c\\\\x00\\\\x04'+ip,a) "
        "for d,a in iter(lambda: s.recvfrom(512), None)]"
    )
    h2.cmd(f'python3 -c "{{dns_server_script}}" > /tmp/dns_server.log 2>&1 &')

    time.sleep(1.0)

    # ============ GENERATE TRAFFIC WHILE CAPTURE IS ACTIVE ============

    # --- ARP: force fresh ARP resolution between h1 and h2 ---
    print("Generating ARP traffic...")
    h1.cmd('arp -d {{h2_ip}} 2>/dev/null; true')
    h2.cmd('arp -d {{h1_ip}} 2>/dev/null; true')

    # --- ICMP: ping in both directions (still 2 calls, but higher count/tighter interval) ---
    print("Generating ICMP (ping) traffic h1 -> h2...")
    h1.cmd(f'ping -c {ping_count} -i {ping_interval} {{h2_ip}}')

    print("Generating ICMP (ping) traffic h2 -> h1...")
    h2.cmd(f'ping -c {ping_count} -i {ping_interval} {{h1_ip}}')

    # --- HTTP/HTTPS/DNS/UDP: ONE combined in-process generator call ---
    print("Generating HTTP/HTTPS/DNS/UDP traffic (single batched process)...")
    h1.cmd(f'python3 /tmp/h1_gen.py {{h2_ip}} {n_http} {n_https} {n_dns} {n_udp}')

    print("Traffic generation done, waiting for tshark to finish...")

    try:
        out, err = tshark_proc.communicate(timeout=25)
        print("TSHARK completed normally")
    except subprocess.TimeoutExpired:
        print("Tshark timeout - terminating...")
        tshark_proc.terminate()
        try:
            out, err = tshark_proc.communicate(timeout=5)
        except:
            tshark_proc.kill()
            out, err = b"", b"Killed"

    print(f"TSHARK Return Code: {{tshark_proc.returncode}}")
    if tshark_proc.returncode not in [0, -15, -9]:
        print(f"STDERR: {{err.decode(errors='ignore')[:500]}}")

    # Stop background servers
    h2.cmd('kill %python3 2>/dev/null')
    h2.cmd('pkill -f http.server 2>/dev/null')

    net.stop()
    print("Mininet stopped successfully")

except Exception as e:
    print(f"ERROR in script: {{str(e)}}")
    import traceback
    traceback.print_exc()
    raise
'''

            script_path = "/tmp/mininet_capture.py"
            with open(script_path, "w") as f:
                f.write(script)

            print("[DEBUG] Running mininet capture script...")
            proc = subprocess.run(
                ["sudo", "python3", script_path],
                capture_output=True,
                text=True,
                timeout=90
            )

            print(f"[DEBUG] Script return code: {proc.returncode}")
            print(f"[DEBUG] Script stdout:\n{proc.stdout}")
            if proc.stderr:
                print(f"[DEBUG] Script stderr:\n{proc.stderr}")

            if proc.returncode != 0:
                StatusManager.update_status(
                    "Capture",
                    f"Mininet error (check permissions): {proc.stderr[-200:] if proc.stderr else 'unknown error'}"
                )
                return None

            if os.path.exists(tmp_output) and os.path.getsize(tmp_output) > 0:
                print(f"[DEBUG] Copying {tmp_output} to {abs_output}")
                try:
                    import pwd
                    current_user = pwd.getpwuid(os.getuid()).pw_name
                    # Combined cp + chown + chmod + rm into ONE sudo call
                    # instead of 4 separate subprocess spawns.
                    combo_cmd = (
                        f"cp '{tmp_output}' '{abs_output}' && "
                        f"chown {current_user}:{current_user} '{abs_output}' && "
                        f"chmod 644 '{abs_output}' && "
                        f"rm -f '{tmp_output}'"
                    )
                    subprocess.run(["sudo", "bash", "-c", combo_cmd],
                                    capture_output=True, timeout=15, check=True)
                except Exception as e:
                    print(f"[DEBUG] Permission/copy error: {e}")

            if os.path.exists(self.output_file) and os.path.getsize(self.output_file) > 0:
                packet_count = self._count_packets(self.output_file)
                file_size = os.path.getsize(self.output_file)
                print(f"[DEBUG] Captured {packet_count} packets, size: {file_size} bytes")

                try:
                    n = int(packet_count)
                except (ValueError, TypeError):
                    n = 0

                if n > 0 and n < self.min_acceptable_packets:
                    # Fewer than the ideal minimum, but still usable --
                    # proceed with whatever was captured instead of failing.
                    StatusManager.update_status(
                        "Capture",
                        f"⚠ Captured only {packet_count} packets "
                        f"(below target of {self.min_acceptable_packets}), "
                        f"continuing pipeline with available packets...",
                        50
                    )
                else:
                    StatusManager.update_status(
                        "Capture",
                        f"✓ Captured {packet_count} packets ({file_size} bytes)",
                        50
                    )

                return self.output_file
            else:
                StatusManager.update_status(
                    "Capture",
                    f"Error: No packets captured. File size: {os.path.getsize(self.output_file) if os.path.exists(self.output_file) else 'file not found'}"
                )
                return None

        except subprocess.TimeoutExpired:
            StatusManager.update_status("Capture", "Error: Mininet capture timed out")
            return None
        except Exception as e:
            StatusManager.update_status("Capture", f"Error: {str(e)}")
            return None
        finally:
            self.stop_capture()

    def _count_packets(self, pcap_file):
        """Count packets in pcap file. capinfos is tried first since it
        just reads header/summary info instead of dissecting every
        packet like `tshark -r` does -- meaningfully faster at 1000+
        packets."""
        try:
            cap_result = subprocess.run(
                ["capinfos", "-c", "-M", pcap_file],
                capture_output=True, text=True, timeout=30
            )
            for line in cap_result.stdout.splitlines():
                if "Number of packets" in line:
                    digits = "".join(ch for ch in line if ch.isdigit())
                    if digits:
                        return digits
        except Exception as e:
            print(f"[DEBUG] capinfos count failed, falling back to tshark: {e}")

        try:
            result = subprocess.run(
                ["tshark", "-r", pcap_file],
                capture_output=True, text=True, timeout=30
            )
            lines = [l for l in result.stdout.splitlines() if l.strip()]
            count = len(lines)
            return str(count) if count > 0 else "0"
        except Exception as e:
            print(f"[DEBUG] Error counting packets: {e}")
            return "Unknown"

    def stop_capture(self):
        """Final cleanup of any leftover Mininet state."""
        try:
            subprocess.run(["sudo", "mn", "-c"], capture_output=True, timeout=20)
            print("[DEBUG] Mininet cleanup successful")
        except Exception as e:
            print(f"[DEBUG] Cleanup error: {e}")
