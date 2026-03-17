import socket
import datetime
import sys
import os
import time
from os.path import basename
import struct
import zlib
import threading

PATH = "./serverFiles"
TCP_PORT = 3000
UDP_PORT = 3001
CHUNK_SIZE = 65536


UDP_SEND_WINDOW = 100         
UDP_SEND_TIMEOUT = 1      
UDP_MAX_NO_ACK = 15          
UDP_CHUNK_SIZE = 1472        
UDP_ACK_EVERY = 10             

if not os.path.exists(PATH):
    os.makedirs(PATH)

def logStr(strLog: str):
    timeStr = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timeStr} - {strLog}")

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





RUDP_MAGIC = b"RU"
RUDP_VER = 1

PT_DATA = 0x01
PT_ACK  = 0x02
PT_FIN  = 0x03

RUDP_HDR = struct.Struct("!2sBBBBIIIH")  

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

def _ack_packet(session: int, ack_seq: int) -> bytes:
    
    return RUDP_HDR.pack(RUDP_MAGIC, RUDP_VER, PT_ACK, 0, 0, session, 0, ack_seq, 0)

class _UDPReceiverState:
    __slots__ = ("expected", "buf", "fin_seq", "last_seen", "handler", "last_acked")
    def __init__(self, handler):
        self.expected = 1
        self.buf: dict[int, bytes] = {}
        self.fin_seq: int | None = None
        self.last_seen = time.time()
        self.handler = handler
        self.last_acked = 0

    def feed(self, ptype: int, seq: int, payload: bytes):
        self.last_seen = time.time()
        if ptype == PT_DATA:
            if seq >= self.expected and seq not in self.buf:
                self.buf[seq] = payload
        elif ptype == PT_FIN:
            self.fin_seq = seq

    def drain_in_order(self):
        while self.expected in self.buf:
            chunk = self.buf.pop(self.expected)
            self.handler.on_chunk(chunk)
            self.expected += 1

    def maybe_complete(self) -> bool:
        return self.fin_seq is not None and self.expected >= self.fin_seq

class _UDPSessionHandler:
    def __init__(self, udp_sock: socket.socket, addr, session: int):
        self.udp_sock = udp_sock
        self.addr = addr
        self.session = session
        self.buf = bytearray()
        self.stage = "need_header"  
        self.header_parsed = None
        self.file = None
        self.file_expected = 0
        self.file_received = 0
        self.start_t = time.time()
        self.upload_name = None
        self.last_log_time = self.start_t

    def _send(self, payload: bytes):
        _udp_send_message(self.udp_sock, self.addr, self.session, payload)

    def on_chunk(self, chunk: bytes):
        if self.stage == "need_header":
            self.buf.extend(chunk)
            parsed_h = _parse_app_header(self.buf)
            if not parsed_h:
                return
            m_type, fname, offset, p_len, h_size = parsed_h
            rest = bytes(self.buf[h_size:])
            self.buf = bytearray(self.buf[:h_size])

            if m_type == 0x05:
                
                safe_name = basename(fname)
                full_path = os.path.join(PATH, safe_name)
                self.upload_name = safe_name
                self.file_expected = p_len
                self.file_received = 0
                mode = "ab" if offset > 0 else "wb"
                self.file = open(full_path, mode)
                if offset > 0:
                    self.file.seek(offset)
                self.stage = "upload"
                logStr(f"UDP START UPLOAD: {safe_name} ({p_len} bytes) from offset {offset}")
                if rest:
                    self._write_file(rest)
            else:
                
                self.stage = "cmd"
                if rest:
                    self.buf.extend(rest)
        elif self.stage == "cmd":
            self.buf.extend(chunk)
        elif self.stage == "upload":
            self._write_file(chunk)

    def _write_file(self, data: bytes):
        if not self.file or self.file_expected <= 0:
            return
        remaining = self.file_expected - self.file_received
        if remaining <= 0:
            return
        take = data[:remaining]
        if take:
            self.file.write(take)
            self.file_received += len(take)
            now = time.time()
            if now - self.last_log_time > 2.0:
                speed = (self.file_received * 8) / ((now - self.start_t) * 1024 * 1024) if now > self.start_t else 0
                logStr(f"UDP PROG UPLOAD: {self.upload_name or 'unknown'} | {self.file_received}/{self.file_expected} | {speed:.2f} Mbps")
                self.last_log_time = now

    def on_complete(self):
        try:
            if self.stage == "cmd":
                parsed = _parse_app_packet(bytes(self.buf))
                if not parsed:
                    return
                m_type, fname, offset, _p_len, payload = parsed
                if m_type == 0x00:
                    self._send(payload + b"\n")
                elif m_type == 0x01:
                    self._send(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S\n").encode("utf-8"))
                elif m_type == 0x03:
                    self._send(("\n".join(os.listdir(PATH)) + "\n").encode("utf-8"))
                elif m_type == 0x06:
                    safe_name = basename(fname)
                    f_path = os.path.join(PATH, safe_name)
                    size = os.path.getsize(f_path) if os.path.exists(f_path) else 0
                    self._send(size.to_bytes(8, "big"))
                elif m_type == 0x02:
                    logStr("UDP CMD: EXIT")
                    try:
                        self._send(b"OK")
                    finally:
                        os._exit(0)
                elif m_type == 0x04:
                    safe_name = basename(fname)
                    full_path = os.path.join(PATH, safe_name)
                    if not os.path.isfile(full_path):
                        self._send(b"")
                        return
                    file_size = os.path.getsize(full_path)
                    data_len = max(0, file_size - offset)
                    
                    def gen():
                        yield data_len.to_bytes(8, "big")
                        if data_len > 0:
                            with open(full_path, "rb") as f:
                                f.seek(offset)
                                while True:
                                    c = f.read(UDP_CHUNK_SIZE)
                                    if not c:
                                        break
                                    yield c
                    
                    chunks = gen()
                    
                    try:
                        _udp_send_stream(self.udp_sock, self.addr, self.session, chunks)
                        logStr(f"UDP DOWNLOAD: {safe_name} sent from offset {offset}")
                    except TimeoutError as e:
                        logStr(f"UDP DOWNLOAD ABORTED: {safe_name} ({e})")
                else:
                    self._send(b"")
            elif self.stage == "upload":
                safe_name = self.upload_name or "unknown"
                if self.file:
                    try:
                        self.file.flush()
                        self.file.close()
                    except Exception:
                        pass
                
                if self.file_expected and self.file_received != self.file_expected:
                    logStr(f"UDP UPLOAD INCOMPLETE: {safe_name} | got {self.file_received}/{self.file_expected} bytes")
                total_time = time.time() - self.start_t
                final_speed = (self.file_received * 8) / (total_time * 1024 * 1024) if total_time > 0 else 0
                logStr(f"UDP FINISH UPLOAD: {safe_name} | {self.file_received} bytes | Avg Speed: {final_speed:.2f} Mbps")
                self._send(b"OK")
        finally:
            try:
                if self.file:
                    self.file.close()
            except Exception:
                pass

def _udp_send_stream(sock: socket.socket, client_addr, session: int, chunk_iter,
                     window: int = UDP_SEND_WINDOW,
                     timeout: float = UDP_SEND_TIMEOUT,
                     max_no_ack_s: float = UDP_MAX_NO_ACK):
    
    
    tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx_sock.bind(("", 0))
    base = 1
    next_seq = 1
    outstanding: dict[int, tuple[bytes, float]] = {}
    seq_sizes: dict[int, int] = {}
    acked_bytes = 0
    eof = False
    last_ack_t = time.time()
    last_log_t = time.time()
    start_t = last_log_t

    def pack_data(seq: int, pl: bytes) -> bytes:
        return RUDP_HDR.pack(RUDP_MAGIC, RUDP_VER, PT_DATA, 0, 0, session, seq, 0, len(pl)) + pl

    it = iter(chunk_iter)
    tx_sock.settimeout(0.05)
    try:
        while True:
            while not eof and (next_seq - base) < max(1, int(window)):
                try:
                    pl = next(it)
                except StopIteration:
                    eof = True
                    break
                pkt = pack_data(next_seq, pl)
                tx_sock.sendto(pkt, client_addr)
                outstanding[next_seq] = (pkt, time.time())
                seq_sizes[next_seq] = len(pl)
                next_seq += 1

            now = time.time()
            for s, (pkt, t0) in list(outstanding.items()):
                if now - t0 >= timeout:
                    logStr(f"UDP RETX DOWNLOAD: session={session} seq={s}")
                    tx_sock.sendto(pkt, client_addr)
                    outstanding[s] = (pkt, time.time())

            try:
                data, addr = tx_sock.recvfrom(2048)
                if addr != client_addr:
                    continue
                parsed = _rudp_unpack(data)
                if not parsed:
                    continue
                status, sid, ptype, _seq, ack, _pl = parsed
                if status == "OK" and sid == session and ptype == PT_ACK:
                    last_ack_t = time.time() 
                    ack_seq = ack
                    if ack_seq >= base:
                        for s in list(outstanding.keys()):
                            if s <= ack_seq:
                                outstanding.pop(s, None)
                        while base <= ack_seq:
                            acked_bytes += seq_sizes.pop(base, 0)
                            base += 1
            except socket.timeout:
                pass

            now = time.time()
            if now - last_log_t > 2.0:
                speed = (acked_bytes * 8) / ((now - start_t) * 1024 * 1024) if now > start_t else 0
                logStr(f"UDP PROG DOWNLOAD: session={session} | acked={acked_bytes} bytes | {speed:.2f} Mbps")
                last_log_t = now

            if time.time() - last_ack_t > max_no_ack_s:
                logStr(f"UDP TIMEOUT DOWNLOAD: session={session} no ACK for {max_no_ack_s}s")
                raise TimeoutError("UDP transfer stalled (no ACK)")

            if eof and not outstanding:
                break
            if time.time() - start_t > 30 * 60:
                raise TimeoutError("UDP send timeout (too long)")

        fin = RUDP_HDR.pack(RUDP_MAGIC, RUDP_VER, PT_FIN, 0, 0, session, next_seq, 0, 0)
        for _ in range(20):
            tx_sock.sendto(fin, client_addr)
            time.sleep(0.005)
        total_time = time.time() - start_t
        avg = (acked_bytes * 8) / (total_time * 1024 * 1024) if total_time > 0 else 0
        logStr(f"UDP FINISH DOWNLOAD: session={session} | acked={acked_bytes} bytes | Avg Speed: {avg:.2f} Mbps")
    finally:
        try:
            tx_sock.close()
        except Exception:
            pass

def _parse_app_packet(packet: bytes):
    
    if len(packet) < 1 + 2 + 8 + 4:
        return None
    m_type = packet[0]
    n_len = int.from_bytes(packet[1:3], "big")
    h_size = 15 + n_len
    if len(packet) < h_size:
        return None
    fname = packet[3:3+n_len].decode("utf-8", errors="ignore")
    offset = int.from_bytes(packet[3+n_len:11+n_len], "big")
    p_len = int.from_bytes(packet[11+n_len:15+n_len], "big")
    payload = packet[h_size:h_size+p_len]
    return m_type, fname, offset, p_len, payload

def _parse_app_header(packet: bytes):
    """Parse only header fields, without requiring full payload bytes."""
    if len(packet) < 1 + 2:
        return None
    m_type = packet[0]
    n_len = int.from_bytes(packet[1:3], "big")
    h_size = 15 + n_len
    if len(packet) < h_size:
        return None
    fname = packet[3:3+n_len].decode("utf-8", errors="ignore")
    offset = int.from_bytes(packet[3+n_len:11+n_len], "big")
    p_len = int.from_bytes(packet[11+n_len:15+n_len], "big")
    return m_type, fname, offset, p_len, h_size

def _udp_send_message(sock: socket.socket, client_addr, session: int, payload: bytes, window: int = 32, timeout: float = 0.25, max_no_ack_s: float = 5.0):
    
    
    chunks = [payload[i:i+UDP_CHUNK_SIZE] for i in range(0, len(payload), UDP_CHUNK_SIZE)]
    total = len(chunks)
    base = 1
    next_seq = 1
    outstanding: dict[int, tuple[bytes, float]] = {}
    last_ack_t = time.time()

    tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx_sock.bind(("", 0))

    def pack_data(seq: int, pl: bytes) -> bytes:
        return RUDP_HDR.pack(RUDP_MAGIC, RUDP_VER, PT_DATA, 0, 0, session, seq, 0, len(pl)) + pl

    start_t = time.time()
    tx_sock.settimeout(0.05)
    try:
        while base <= total:
            while next_seq <= total and (next_seq - base) < max(1, int(window)):
                pkt = pack_data(next_seq, chunks[next_seq - 1])
                tx_sock.sendto(pkt, client_addr)
                outstanding[next_seq] = (pkt, time.time())
                next_seq += 1

            now = time.time()
            for s, (pkt, t0) in list(outstanding.items()):
                if now - t0 >= timeout:
                    logStr(f"UDP RETX MSG: session={session} seq={s}")
                    tx_sock.sendto(pkt, client_addr)
                    outstanding[s] = (pkt, time.time())

            try:
                data, addr = tx_sock.recvfrom(2048)
                if addr != client_addr:
                    continue
                parsed = _rudp_unpack(data)
                if not parsed:
                    continue
                status, sid, ptype, _seq, ack, _pl = parsed
                if status != "OK" or sid != session or ptype != PT_ACK:
                    continue
                last_ack_t = time.time()  
                ack_seq = ack
                if ack_seq >= base:
                    for s in list(outstanding.keys()):
                        if s <= ack_seq:
                            outstanding.pop(s, None)
                    base = ack_seq + 1
            except socket.timeout:
                pass

            if time.time() - last_ack_t > max_no_ack_s:
                logStr(f"UDP TIMEOUT MSG: session={session} no ACK for {max_no_ack_s}s")
                raise TimeoutError("UDP transfer stalled (no ACK)")

            if time.time() - start_t > 30 * 60:
                raise TimeoutError("UDP send timeout (too long)")

        
        fin = RUDP_HDR.pack(RUDP_MAGIC, RUDP_VER, PT_FIN, 0, 0, session, total + 1, 0, 0)
        for _ in range(20):
            tx_sock.sendto(fin, client_addr)
            time.sleep(0.005)
    finally:
        try:
            tx_sock.close()
        except Exception:
            pass

def _udp_server_loop():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind(("", UDP_PORT))
    udp_sock.settimeout(0.2)
    logStr(f"UDP SERVER STARTED - Port {UDP_PORT}")

    sessions: dict[tuple[str, int, int], _UDPReceiverState] = {}
    

    while True:
        try:
            data, addr = udp_sock.recvfrom(65535)
        except socket.timeout:
            
            now = time.time()
            for k in list(sessions.keys()):
                if now - sessions[k].last_seen > 120:
                    sessions.pop(k, None)
            continue
        except Exception as e:
            logStr(f"UDP SOCKET ERROR: {e}")
            continue

        parsed = _rudp_unpack(data)
        if not parsed:
            continue
        status, session, ptype, seq, ack, payload = parsed
        if status != "OK":
            continue

        
        if ptype == PT_ACK:
            
            continue

        key = (addr[0], addr[1], session)
        st = sessions.get(key)
        if not st:
            handler = _UDPSessionHandler(udp_sock, addr, session)
            st = _UDPReceiverState(handler)
            sessions[key] = st

        if ptype in (PT_DATA, PT_FIN):
            # НОВОЕ: Если пришел старый пакет, значит отправитель не получил наш ACK 
            # и переотправил данные. Нужно срочно отправить ACK еще раз!
            if ptype == PT_DATA and seq < st.expected:
                udp_sock.sendto(_ack_packet(session, st.expected - 1), addr)
                continue

            st.feed(ptype, seq, payload)
            st.drain_in_order()

            in_order = st.expected - 1
            if in_order > 0:
                need_ack = False
                
                # Всегда отправляем ACK на финальный пакет или если достигли порога UDP_ACK_EVERY
                if ptype == PT_FIN:
                    need_ack = True
                elif in_order > st.last_acked:
                    if (in_order == 1 and st.last_acked == 0) or \
                       ((in_order - st.last_acked) >= max(1, int(UDP_ACK_EVERY))):
                        need_ack = True
                
                if need_ack:
                    udp_sock.sendto(_ack_packet(session, in_order), addr)
                    st.last_acked = in_order

            if st.maybe_complete():
                try:
                    try:
                        st.handler.on_complete()
                    except Exception as e:
                        logStr(f"UDP SESSION ERROR: {e}")
                finally:
                    sessions.pop(key, None)

def upload_stream(conn, fileName, offset, total_payload_len, initial_data=b""):
    safe_name = basename(fileName)
    full_path = os.path.join(PATH, safe_name)
    mode = "ab" if offset > 0 else "wb"
    
    bytes_received = len(initial_data)
    start_time = time.time()
    last_log_time = start_time

    try:
        with open(full_path, mode) as f:
            if offset > 0:
                f.seek(offset)
            if initial_data:
                f.write(initial_data)

            while bytes_received < total_payload_len:
                to_read = min(total_payload_len - bytes_received, CHUNK_SIZE)
                chunk = conn.recv(to_read)
                if not chunk:
                    raise ConnectionError("Connection lost during upload stream")
                
                f.write(chunk)
                bytes_received += len(chunk)

                now = time.time()
                if now - last_log_time > 2.0:
                    speed = (bytes_received * 8) / ((now - start_time) * 1024 * 1024)
                    logStr(f"PROG: {safe_name} | {bytes_received}/{total_payload_len} | {speed:.2f} Mbps")
                    last_log_time = now

        total_time = time.time() - start_time
        final_speed = (bytes_received * 8) / (total_time * 1024 * 1024) if total_time > 0 else 0
        logStr(f"FINISH: {safe_name} | {bytes_received} bytes | Avg Speed: {final_speed:.2f} Mbps")
    except Exception as e:
        logStr(f"UPLOAD ERROR: {e}")

def download_command(conn, fileName, offset=0):
    safe_name = basename(fileName)
    full_path = os.path.join(PATH, safe_name)
    
    if not os.path.isfile(full_path):
        logStr(f"DOWNLOAD ERROR: {safe_name} not found")
        conn.sendall(b"\x04" + b"\x00" * 14)
        return

    try:
        file_size = os.path.getsize(full_path)
        data_len = max(0, file_size - offset)
        name_bytes = safe_name.encode('utf-8')

        header = (
            b'\x04' + 
            len(name_bytes).to_bytes(2, 'big') + 
            name_bytes + 
            offset.to_bytes(8, 'big') + 
            data_len.to_bytes(4, 'big')
        )
        conn.sendall(header)

        if data_len > 0:
            with open(full_path, "rb") as f:
                f.seek(offset)
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk: break
                    conn.sendall(chunk)
        logStr(f"DOWNLOAD: {safe_name} sent from offset {offset}")
    except Exception as e:
        logStr(f"DOWNLOAD ERROR: {e}")

def handle_client(client_sock):
    buffer = bytearray()
    while True:
        try:
            data = client_sock.recv(CHUNK_SIZE)
            if not data: break
            buffer.extend(data)

            while len(buffer) >= 3:
                m_type = buffer[0]
                n_len = int.from_bytes(buffer[1:3], byteorder='big')
                h_size = 15 + n_len
                
                if len(buffer) < h_size:
                    break
                
                fname = buffer[3 : 3+n_len].decode('utf-8', errors='ignore')
                offset = int.from_bytes(buffer[3+n_len : 11+n_len], byteorder='big')
                p_len = int.from_bytes(buffer[11+n_len : 15+n_len], byteorder='big')

                if m_type == 0x05:
                    payload_in_buffer = buffer[h_size : h_size + p_len]
                  
                    del buffer[:h_size + len(payload_in_buffer)] 
                    logStr(f"START UPLOAD: {fname} ({p_len} bytes)")
                    upload_stream(client_sock, fname, offset, p_len, payload_in_buffer)

                elif m_type == 0x06:
                    safe_name = basename(fname)
                    f_path = os.path.join(PATH, safe_name)
                    size = os.path.getsize(f_path) if os.path.exists(f_path) else 0
                    client_sock.sendall(size.to_bytes(8, 'big'))
                    del buffer[:h_size]

                elif m_type == 0x02: 
                    logStr("CMD: EXIT")
                    client_sock.close()
                    os._exit(0)

                else:
                    total_msg_size = h_size + p_len
                    if len(buffer) < total_msg_size:
                        break
                    
                    payload = buffer[h_size : total_msg_size]
                    
                    if m_type == 0x00: 
                        client_sock.sendall(payload + b"\n")
                    elif m_type == 0x01:
                        t_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S\n")
                        client_sock.sendall(t_str.encode("utf-8"))
                    elif m_type == 0x03: 
                        files_list = "\n".join(os.listdir(PATH)) + "\n"
                        client_sock.sendall(files_list.encode("utf-8"))
                    elif m_type == 0x04: 
                        download_command(client_sock, fname, offset)

                    del buffer[:total_msg_size]

        except Exception as e:
            logStr(f"CLIENT ERROR: {e}")
            break

udp_thread = threading.Thread(target=_udp_server_loop, daemon=True)
udp_thread.start()

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
serverSocket.bind(('', TCP_PORT))
serverSocket.listen(5)

logStr(f"File Transfer Server Started (TCP:{TCP_PORT} UDP:{UDP_PORT})")

try:
    while True:
        clientSock, clientAddr = serverSocket.accept()
        set_keepalive(clientSock)
        logStr(f"CONNECT: {clientAddr}")
        try:
            handle_client(clientSock)
        finally:
            clientSock.close()
            logStr(f"DISCONNECT: {clientAddr}")
except KeyboardInterrupt:
    logStr("SHUTDOWN")
    serverSocket.close()