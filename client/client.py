import socket
import os
import time
import datetime
import sys
import struct
import zlib
import secrets
from dataclasses import dataclass

SERVER_IP = '192.168.100.10'
SERVER_TCP_PORT = 3000
SERVER_UDP_PORT = 3001
FILES_PATH = "./clientFiles"

if not os.path.exists(FILES_PATH):
    os.makedirs(FILES_PATH)

@dataclass
class Settings:
    protocol: str = "udp"   
    window: int = 100        
    timeout: float = 0.5   
    udp_chunk: int = 8196   
    ack_every: int = 10      

SETTINGS = Settings()

def log_msg(msg: str):
    t = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{t}] {msg}")

def set_keepalive(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if sys.platform == "win32":
        sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 5000, 1000))
    elif sys.platform == "darwin":
        TCP_KEEPALIVE = getattr(socket, 'TCP_KEEPALIVE', 0x10)
        sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPALIVE, 5)
    elif sys.platform == "linux":
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 5)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 20)

def create_packet(m_type, filename="", offset=0, payload=b""):
    f_bytes = filename.encode('utf-8')
    return (
        m_type.to_bytes(1, 'big') +
        len(f_bytes).to_bytes(2, 'big') +
        f_bytes +
        offset.to_bytes(8, 'big') +
        len(payload).to_bytes(4, 'big') +
        payload
    )

RUDP_MAGIC = b"RU"
RUDP_VER = 1

PT_DATA = 0x01
PT_ACK  = 0x02
PT_FIN  = 0x03

RUDP_HDR = struct.Struct("!2sBBBBIIIH")  


def _rudp_pack(ptype: int, session: int, seq: int, ack: int, payload: bytes) -> bytes:
    return RUDP_HDR.pack(RUDP_MAGIC, RUDP_VER, ptype, 0, 0, session, seq, ack, len(payload)) + payload

def _rudp_unpack(data: bytes):
    if len(data) < RUDP_HDR.size:
        return None
    magic, ver, ptype, flags, _r, session, seq, ack, plen = RUDP_HDR.unpack(data[:RUDP_HDR.size])
    if magic != RUDP_MAGIC or ver != RUDP_VER:
        return None
    payload = data[RUDP_HDR.size:RUDP_HDR.size + plen]
    if len(payload) != plen:
        return None
    return ("OK", session, ptype, seq, ack, payload)

class ReliableUDP:
    def __init__(self, server_addr, window: int, timeout: float):
        self.server_addr = server_addr
        self.window = max(1, int(window))
        self.timeout = float(timeout)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(0.05)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

    def send_stream(self, chunk_iter, session: int | None = None, on_acked_bytes=None) -> int:
        """Send stream of bytes chunks reliably. Returns session id."""
        sid = session if session is not None else secrets.randbits(32)
        base = 1
        next_seq = 1
        outstanding: dict[int, tuple[bytes, float]] = {}
        seq_sizes: dict[int, int] = {}
        acked_bytes = 0
        eof = False

        def send_seq(s: int, payload: bytes):
            pkt = _rudp_pack(PT_DATA, sid, s, 0, payload)
            self.sock.sendto(pkt, self.server_addr)
            outstanding[s] = (pkt, time.time())
            seq_sizes[s] = len(payload)

        start_t = time.time()
        it = iter(chunk_iter)
        while True:
            
            while not eof and (next_seq - base) < self.window:
                try:
                    payload = next(it)
                except StopIteration:
                    eof = True
                    break
                send_seq(next_seq, payload)
                next_seq += 1

            
            now = time.time()
            for s, (pkt, t0) in list(outstanding.items()):
                if now - t0 >= self.timeout:
                    self.sock.sendto(pkt, self.server_addr)
                    outstanding[s] = (pkt, time.time())

            
            try:
                data, _addr = self.sock.recvfrom(2048)
                parsed = _rudp_unpack(data)
                if parsed:
                    status, psid, ptype, _pseq, pack, _pl = parsed
                    if status == "OK" and psid == sid and ptype == PT_ACK:
                        ack_seq = pack
                        if ack_seq >= base:
                            
                            for s in list(outstanding.keys()):
                                if s <= ack_seq:
                                    outstanding.pop(s, None)
                            while base <= ack_seq:
                                acked_bytes += seq_sizes.pop(base, 0)
                                base += 1
                            if on_acked_bytes:
                                try:
                                    on_acked_bytes(acked_bytes)
                                except Exception:
                                    pass
            except socket.timeout:
                pass

            if eof and not outstanding:
                break

            if time.time() - start_t > 30 * 60:
                raise TimeoutError("UDP send timeout (too long)")

        fin = RUDP_HDR.pack(RUDP_MAGIC, RUDP_VER, PT_FIN, 0, 0, sid, next_seq, 0, 0)
        for _ in range(20):
            self.sock.sendto(fin, self.server_addr)
            time.sleep(0.005)
        return sid

    def recv_stream(self, session: int, on_chunk, timeout_s: float = 120.0) -> None:
        """Receive stream reliably; calls on_chunk(payload) in-order."""
        expected = 1
        buffer: dict[int, bytes] = {}
        fin_seq: int | None = None
        start_t = time.time()

        last_acked_in_order = 0
        while True:
            if time.time() - start_t > timeout_s:
                raise TimeoutError("UDP receive timeout")
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue

            parsed = _rudp_unpack(data)
            if not parsed:
                continue
            status, sid, ptype, seq, _ack, payload = parsed
            if sid != session:
                continue

            if ptype == PT_DATA:
                if seq >= expected and seq not in buffer:
                    buffer[seq] = payload
            elif ptype == PT_FIN:
                fin_seq = seq
            else:
                continue

            while expected in buffer:
                on_chunk(buffer.pop(expected))
                expected += 1

            
            in_order = expected - 1
            if in_order > last_acked_in_order:
                
                
                need_ack = (in_order == 1 and last_acked_in_order == 0) or ((in_order - last_acked_in_order) >= max(1, int(SETTINGS.ack_every)))
                if ptype == PT_FIN:
                    need_ack = True
                if need_ack:
                    ack_pkt = RUDP_HDR.pack(RUDP_MAGIC, RUDP_VER, PT_ACK, 0, 0, session, 0, in_order, 0)
                    self.sock.sendto(ack_pkt, addr)
                    last_acked_in_order = in_order

            if fin_seq is not None and expected >= fin_seq:
                break

    def send_message(self, payload: bytes, session: int | None = None) -> int:
        """Send a reliable message (payload) to server. Returns session id."""
        sid = session if session is not None else secrets.randbits(32)
        base = 1
        next_seq = 1
        view = memoryview(payload)
        chunk_size = max(200, int(SETTINGS.udp_chunk))
        total_packets = (len(view) + (chunk_size - 1)) // chunk_size
        outstanding: dict[int, tuple[bytes, float]] = {}

        def send_pkt(s: int, start: int, end: int):
            pkt = _rudp_pack(PT_DATA, sid, s, 0, view[start:end])
            self.sock.sendto(pkt, self.server_addr)
            outstanding[s] = (pkt, time.time())

        start_t = time.time()
        while base <= total_packets:
            while next_seq <= total_packets and (next_seq - base) < self.window:
                start = (next_seq - 1) * chunk_size
                end = min(start + chunk_size, len(view))
                send_pkt(next_seq, start, end)
                next_seq += 1

            now = time.time()
            for s, (pkt, t0) in list(outstanding.items()):
                if now - t0 >= self.timeout:
                    self.sock.sendto(pkt, self.server_addr)
                    outstanding[s] = (pkt, time.time())

            try:
                data, _addr = self.sock.recvfrom(2048)
                parsed = _rudp_unpack(data)
                if not parsed:
                    continue
                status, psid, ptype, pseq, pack, _pl = parsed
                if status != "OK" or psid != sid or ptype != PT_ACK:
                    continue
                ack_seq = pack
                if ack_seq >= base:
                    for s in list(outstanding.keys()):
                        if s <= ack_seq:
                            outstanding.pop(s, None)
                    base = ack_seq + 1
            except socket.timeout:
                pass

            if time.time() - start_t > 30 * 60:
                raise TimeoutError("UDP send timeout (too long)")

        fin = _rudp_pack(PT_FIN, sid, total_packets + 1, 0, b"")
        for _ in range(10):
            self.sock.sendto(fin, self.server_addr)
            time.sleep(0.01)
        return sid

    def recv_message(self, session: int, timeout_s: float = 30.0) -> bytes:
        """Receive a reliable message from server for a given session."""
        expected = 1
        buffer: dict[int, bytes] = {}
        got_fin = False
        fin_seq = None
        start_t = time.time()

        last_acked_in_order = 0
        while True:
            if time.time() - start_t > timeout_s:
                raise TimeoutError("UDP receive timeout")
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue

            parsed = _rudp_unpack(data)
            if not parsed:
                continue
            status, sid, ptype, seq, _ack, payload = parsed
            if sid != session:
                continue

            if ptype == PT_DATA:
                if seq < expected:
                    continue
                if seq not in buffer:
                    buffer[seq] = payload
            elif ptype == PT_FIN:
                got_fin = True
                fin_seq = seq
            else:
                continue

            if expected in buffer:
                while expected in buffer:
                    expected += 1

            in_order = expected - 1
            if in_order > last_acked_in_order:
                need_ack = (in_order == 1 and last_acked_in_order == 0) or ((in_order - last_acked_in_order) >= max(1, int(SETTINGS.ack_every)))
                if ptype == PT_FIN:
                    need_ack = True
                if need_ack:
                    ack_pkt = RUDP_HDR.pack(RUDP_MAGIC, RUDP_VER, PT_ACK, 0, 0, session, 0, in_order, 0)
                    self.sock.sendto(ack_pkt, addr)
                    last_acked_in_order = in_order

            if got_fin and fin_seq is not None and expected >= fin_seq:
                break

        parts = [buffer[i] for i in range(1, expected) if i in buffer]
        return b"".join(parts)

def _udp_request(app_packet: bytes, response: bool = True) -> bytes | None:
    ru = ReliableUDP((SERVER_IP, SERVER_UDP_PORT), SETTINGS.window, SETTINGS.timeout)
    try:
        sid = ru.send_message(app_packet)
        if not response:
            return b"OK"
        return ru.recv_message(sid)
    except Exception as e:
        log_msg(f"UDP Error: {e}")
        return None
    finally:
        ru.close()

def send_and_receive(packet, wait_response=True):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        set_keepalive(sock)
        sock.connect((SERVER_IP, SERVER_TCP_PORT))
        sock.sendall(packet)
        if wait_response:
            data = sock.recv(8192) 
            return data
        return b"OK"
    except Exception as e:
        log_msg(f"Error: {e}")
        return None
    finally:
        sock.close()

def get_remote_size(filename):
    if SETTINGS.protocol == "udp":
        res = _udp_request(create_packet(0x06, filename), True)
    else:
        res = send_and_receive(create_packet(0x06, filename), True)
    return int.from_bytes(res, 'big') if res else 0

def do_upload(args):
    if not args:
        print("Usage: upload <filename>")
        return
    filename = args[0]
    local_path = os.path.join(FILES_PATH, filename)
    if not os.path.exists(local_path):
        print(f"File {local_path} not found")
        return

    file_size = os.path.getsize(local_path)
    max_retry_time = 30
    start_recovery_t = None

    while True:
        try:
            remote_offset = get_remote_size(filename)
            if remote_offset >= file_size:
                print("\nFile already fully uploaded.")
                break

            if start_recovery_t:
                log_msg(f"\nConnection restored! Resuming upload from {remote_offset}...")
                start_recovery_t = None

            bytes_to_send = file_size - remote_offset

            if SETTINGS.protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                set_keepalive(sock)
                sock.connect((SERVER_IP, SERVER_TCP_PORT))

                header = create_packet(0x05, filename, remote_offset, payload=b"")
                header_fixed = header[:-4] + bytes_to_send.to_bytes(4, 'big')
                sock.sendall(header_fixed)

                session_start_t = time.time()
                bytes_at_session_start = 0

                with open(local_path, "rb") as f:
                    f.seek(remote_offset)
                    while True:
                        chunk = f.read(65536)
                        if not chunk: break
                        sock.sendall(chunk)
                        bytes_at_session_start += len(chunk)

                        duration = time.time() - session_start_t
                        bitrate = ((bytes_at_session_start * 8) / (1024 * 1024 * duration)) if duration > 0 else 0
                        print(f"\rProgress: {remote_offset + bytes_at_session_start}/{file_size} | Speed: {bitrate:.2f} Mbit/s", end="")

                total_d = time.time() - session_start_t
                avg = ((bytes_at_session_start * 8) / (1024 * 1024 * total_d)) if total_d > 0 else 0
                print(f"\nUpload of {filename} completed. Time: {total_d:.2f}s | Avg: {avg:.2f} Mbit/s")
                sock.close()
                break

            
            ru = ReliableUDP((SERVER_IP, SERVER_UDP_PORT), SETTINGS.window, SETTINGS.timeout)
            try:
                header = create_packet(0x05, filename, remote_offset, payload=b"")
                header_fixed = header[:-4] + bytes_to_send.to_bytes(4, "big")

                def gen_chunks():
                    yield header_fixed
                    with open(local_path, "rb") as f:
                        f.seek(remote_offset)
                        while True:
                            chunk = f.read(max(200, int(SETTINGS.udp_chunk)))
                            if not chunk:
                                break
                            yield chunk

                session_start_t = time.time()
                last_print_t = 0.0

                def on_acked(acked_bytes: int):
                    nonlocal last_print_t
                    now = time.time()
                    if now - last_print_t < 0.5:
                        return
                    last_print_t = now
                    duration = now - session_start_t
                    speed = ((acked_bytes * 8) / (1024 * 1024 * duration)) if duration > 0 else 0
                    done = min(bytes_to_send, acked_bytes)
                    print(f"\rProgress: {remote_offset + done}/{file_size} | Speed: {speed:.2f} Mbit/s", end="")

                sid = ru.send_stream(gen_chunks(), on_acked_bytes=on_acked)

                
                _ = ru.recv_message(sid, timeout_s=20.0)

                total_d = time.time() - session_start_t
                avg = ((bytes_to_send * 8) / (1024 * 1024 * total_d)) if total_d > 0 else 0
                print(f"\nUpload of {filename} completed. Time: {total_d:.2f}s | Avg: {avg:.2f} Mbit/s")
                break
            finally:
                ru.close()

        except (socket.error, ConnectionError) as e:
            if not start_recovery_t:
                start_recovery_t = time.time()
                print(f"\n[!] Connection lost: {e}")
            if (time.time() - start_recovery_t) > max_retry_time:
                log_msg("Recovery timeout. Upload failed.")
                break
            time.sleep(5)
        finally:
            try: sock.close()
            except: pass

def do_download(args):
    if not args:
        print("Usage: download <filename>")
        return
    filename = args[0]
    local_path = os.path.join(FILES_PATH, filename)
    
    max_retry_time = 30
    start_recovery_t = None

    while True:
        try:
            current_offset = os.path.getsize(local_path) if os.path.exists(local_path) else 0
            if start_recovery_t:
                log_msg(f"\nConnection restored! Resuming download from {current_offset}...")
                start_recovery_t = None

            if SETTINGS.protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                set_keepalive(sock)
                sock.connect((SERVER_IP, SERVER_TCP_PORT))

                packet = create_packet(0x04, filename, current_offset)
                sock.sendall(packet)

                header_data = sock.recv(1024)
                if not header_data or not header_data.startswith(b'\x04'):
                    print("\nServer error or file not found.")
                    break

                name_len = int.from_bytes(header_data[1:3], 'big')
                header_size = 15 + name_len
                payload_total_size = int.from_bytes(header_data[11 + name_len : 15 + name_len], 'big')

                if payload_total_size == 0:
                    print("\nFile is already up to date.")
                    break

                session_start_t = time.time()
                received_in_session = 0

                with open(local_path, "ab") as f:
                    initial_payload = header_data[header_size:]
                    if initial_payload:
                        f.write(initial_payload)
                        received_in_session += len(initial_payload)

                    while received_in_session < payload_total_size:
                        data = sock.recv(65536)
                        if not data:
                            raise ConnectionError("Connection lost")
                        f.write(data)
                        received_in_session += len(data)

                        duration = time.time() - session_start_t
                        bitrate = (received_in_session * 8) / (1024 * 1024 * (duration if duration > 0 else 1))
                        print(f"\rDownloaded: {current_offset + received_in_session} bytes | Speed: {bitrate:.2f} Mbit/s", end="")

                total_d = time.time() - session_start_t
                avg = ((received_in_session * 8) / (1024 * 1024 * total_d)) if total_d > 0 else 0
                print(f"\nDownload finished. Time: {total_d:.2f}s | Avg: {avg:.2f} Mbit/s")
                sock.close()
                break

            
            ru = ReliableUDP((SERVER_IP, SERVER_UDP_PORT), SETTINGS.window, SETTINGS.timeout)
            try:
                req = create_packet(0x04, filename, current_offset, payload=b"")
                sid = secrets.randbits(32)
                ru.send_message(req, session=sid)

                session_start_t = time.time()
                received = 0
                header_buf = bytearray()
                total_expected = None

                f = open(local_path, "ab")

                def on_chunk(chunk: bytes):
                    nonlocal received, total_expected
                    if total_expected is None:
                        header_buf.extend(chunk)
                        if len(header_buf) >= 8:
                            total_expected = int.from_bytes(header_buf[:8], "big")
                            rest = header_buf[8:]
                            header_buf.clear()
                            if total_expected == 0:
                                
                                return
                            if rest:
                                f.write(rest)
                                received += len(rest)
                    else:
                        if total_expected and received < total_expected:
                            take = chunk[: max(0, total_expected - received)]
                            if take:
                                f.write(take)
                                received += len(take)
                            duration = time.time() - session_start_t
                            bitrate = (received * 8) / (1024 * 1024 * (duration if duration > 0 else 1))
                            print(f"\rDownloaded: {current_offset + received} bytes | Speed: {bitrate:.2f} Mbit/s", end="")

                ru.recv_stream(sid, on_chunk, timeout_s=180.0)
                f.close()

                if total_expected is None:
                    print("\nServer error or file not found.")
                    break
                if total_expected == 0:
                    print("\nFile is already up to date.")
                    break

                total_d = time.time() - session_start_t
                avg = ((received * 8) / (1024 * 1024 * total_d)) if total_d > 0 else 0
                print(f"\nDownload finished. Time: {total_d:.2f}s | Avg: {avg:.2f} Mbit/s")
                break
            finally:
                ru.close()

        except (socket.error, ConnectionError) as e:
            if not start_recovery_t:
                start_recovery_t = time.time()
                print(f"\n[!] Connection lost: {e}")
            if (time.time() - start_recovery_t) > max_retry_time:
                log_msg("Recovery timeout. Download failed.")
                break
            time.sleep(5)
        finally:
            try: sock.close()
            except: pass

def show_help():
    print("""
Available commands:
  echo <msg>, time, ls, upload <file>, download <file>, settings, exit_server, quit

Settings:
  settings show
  settings protocol udp|tcp
  settings window <n>
  settings timeout <sec>
  settings udp_chunk <bytes>
  settings ack_every <n>
    """)

print("File Transfer Client Started (TCP/UDP). Default protocol: UDP.")
while True:
    try:
        user_input = input("\nclient> ").strip().split()
        if not user_input: continue
        cmd = user_input[0].lower()
        args = user_input[1:]

        if cmd == "help": show_help()
        elif cmd == "settings":
            
            if not args or args[0] == "show":
                print(f"protocol={SETTINGS.protocol} window={SETTINGS.window} timeout={SETTINGS.timeout} udp_chunk={SETTINGS.udp_chunk} ack_every={SETTINGS.ack_every}")
            elif args[0] == "protocol" and len(args) >= 2:
                v = args[1].lower()
                if v not in ("udp", "tcp"):
                    print("Usage: settings protocol udp|tcp")
                else:
                    SETTINGS.protocol = v
                    print(f"protocol={SETTINGS.protocol}")
            elif args[0] == "window" and len(args) >= 2:
                try:
                    SETTINGS.window = max(1, int(args[1]))
                    print(f"window={SETTINGS.window}")
                except ValueError:
                    print("Usage: settings window <n>")
            elif args[0] == "timeout" and len(args) >= 2:
                try:
                    SETTINGS.timeout = max(0.01, float(args[1]))
                    print(f"timeout={SETTINGS.timeout}")
                except ValueError:
                    print("Usage: settings timeout <sec>")
            elif args[0] == "udp_chunk" and len(args) >= 2:
                try:
                    SETTINGS.udp_chunk = max(200, int(args[1]))
                    print(f"udp_chunk={SETTINGS.udp_chunk}")
                except ValueError:
                    print("Usage: settings udp_chunk <bytes>")
            elif args[0] == "ack_every" and len(args) >= 2:
                try:
                    SETTINGS.ack_every = max(1, int(args[1]))
                    print(f"ack_every={SETTINGS.ack_every}")
                except ValueError:
                    print("Usage: settings ack_every <n>")
            else:
                print("Usage: settings [show] | settings protocol udp|tcp | settings window <n> | settings timeout <sec> | settings udp_chunk <bytes> | settings ack_every <n>")
        elif cmd == "echo":
            pkt = create_packet(0x00, payload=" ".join(args).encode())
            res = _udp_request(pkt) if SETTINGS.protocol == "udp" else send_and_receive(pkt)
            if res: print("Server:", res.decode(errors='ignore'))
        elif cmd == "time":
            pkt = create_packet(0x01)
            res = _udp_request(pkt) if SETTINGS.protocol == "udp" else send_and_receive(pkt)
            if res: print("Time:", res.decode())
        elif cmd == "ls":
            pkt = create_packet(0x03)
            res = _udp_request(pkt) if SETTINGS.protocol == "udp" else send_and_receive(pkt)
            if res: print("Files:\n", res.decode())
        elif cmd == "upload": do_upload(args)
        elif cmd == "download": do_download(args)
        elif cmd == "exit_server":
            pkt = create_packet(0x02)
            if SETTINGS.protocol == "udp":
                _udp_request(pkt, response=False)
            else:
                send_and_receive(pkt, False)
        elif cmd in ["quit", "exit"]: break
        else: print(f"Unknown command '{cmd}'")
    except KeyboardInterrupt: break