import socket
import select
import datetime
import sys
import os
import time
from os.path import basename
import struct
import zlib

PATH = "./serverFiles"
TCP_PORT = 3000
UDP_PORT = 3001
CHUNK_SIZE = 65536


UDP_SEND_WINDOW = 100         
UDP_SEND_TIMEOUT = 0.1       
UDP_MAX_NO_ACK = 15        
UDP_CHUNK_SIZE = 8196        
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
        schedule_udp_message(self.udp_sock, self.addr, self.session, payload)

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
                    schedule_udp_stream(self.udp_sock, self.addr, self.session, chunks, log_tag=f"{safe_name} {offset}")
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


_UDP_OUTGOING_TASKS: dict[tuple[str, int, int], "_UDPSenderState"] = {}


class _UDPSenderState:
    __slots__ = (
        "udp_sock",
        "client_addr",
        "session",
        "window",
        "timeout",
        "max_no_ack_s",
        "kind",
        "log_tag",
        "base",
        "next_seq",
        "outstanding",
        "seq_sizes",
        "acked_bytes",
        "eof",
        "it",
        "last_ack_t",
        "last_log_t",
        "start_t",
        "fin_phase",
        "fin_attempts",
        "next_fin_t",
        "fin_seq",
    )

    def __init__(self, udp_sock: socket.socket, client_addr, session: int, chunk_iter, window: int, timeout: float,
                 max_no_ack_s: float, kind: str, log_tag: str = ""):
        self.udp_sock = udp_sock
        self.client_addr = client_addr
        self.session = session
        self.window = max(1, int(window))
        self.timeout = float(timeout)
        self.max_no_ack_s = float(max_no_ack_s)
        self.kind = kind
        self.log_tag = log_tag
        self.base = 1
        self.next_seq = 1
        self.outstanding: dict[int, tuple[bytes, float]] = {}
        self.seq_sizes: dict[int, int] = {}
        self.acked_bytes = 0
        self.eof = False
        self.it = iter(chunk_iter)
        self.last_ack_t = time.time()
        self.last_log_t = self.last_ack_t
        self.start_t = self.last_ack_t
        self.fin_phase = False
        self.fin_attempts = 0
        self.next_fin_t = 0.0
        self.fin_seq = 0

    def on_ack(self, ack_seq: int, now: float):
        if ack_seq < self.base:
            return
        self.last_ack_t = now
        for s in list(self.outstanding.keys()):
            if s <= ack_seq:
                self.outstanding.pop(s, None)
        for s in range(self.base, ack_seq + 1):
            self.acked_bytes += self.seq_sizes.pop(s, 0)
        self.base = ack_seq + 1

    def step(self, now: float) -> bool:
        if self.fin_phase:
            if self.fin_attempts >= 20:
                return True
            if now >= self.next_fin_t:
                fin = RUDP_HDR.pack(RUDP_MAGIC, RUDP_VER, PT_FIN, 0, 0, self.session, self.fin_seq, 0, 0)
                self.udp_sock.sendto(fin, self.client_addr)
                self.fin_attempts += 1
                self.next_fin_t = now + 0.005
            return False

        if now - self.last_ack_t > self.max_no_ack_s:
            raise TimeoutError("UDP transfer stalled (no ACK)")

        sent_new = 0
        while not self.eof and (self.next_seq - self.base) < self.window and sent_new < 32:
            try:
                pl = next(self.it)
            except StopIteration:
                self.eof = True
                break
            pkt = RUDP_HDR.pack(RUDP_MAGIC, RUDP_VER, PT_DATA, 0, 0, self.session, self.next_seq, 0, len(pl)) + pl
            self.udp_sock.sendto(pkt, self.client_addr)
            self.outstanding[self.next_seq] = (pkt, now)
            self.seq_sizes[self.next_seq] = len(pl)
            self.next_seq += 1
            sent_new += 1

        for s, (pkt, t0) in list(self.outstanding.items()):
            if now - t0 >= self.timeout:
                self.udp_sock.sendto(pkt, self.client_addr)
                self.outstanding[s] = (pkt, now)

        if now - self.last_log_t > 2.0:
            speed = (self.acked_bytes * 8) / ((now - self.start_t) * 1024 * 1024) if now > self.start_t else 0
            if self.kind == "message":
                logStr(f"UDP PROG MSG: session={self.session} {self.log_tag} | acked={self.acked_bytes} bytes | {speed:.2f} Mbps")
            else:
                logStr(f"UDP PROG SEND: session={self.session} {self.log_tag} | acked={self.acked_bytes} bytes | {speed:.2f} Mbps")
            self.last_log_t = now

        if self.eof and not self.outstanding:
            self.fin_seq = self.next_seq
            self.fin_phase = True
            self.fin_attempts = 0
            self.next_fin_t = now
        return False


def _udp_schedule_sender(udp_sock: socket.socket, client_addr, session: int, chunk_iter,
                          window: int, timeout: float, max_no_ack_s: float, kind: str, log_tag: str = ""):
    key = (client_addr[0], client_addr[1], session)
    if key in _UDP_OUTGOING_TASKS:
        return
    _UDP_OUTGOING_TASKS[key] = _UDPSenderState(udp_sock, client_addr, session, chunk_iter, window, timeout, max_no_ack_s, kind, log_tag)


def schedule_udp_message(udp_sock: socket.socket, client_addr, session: int, payload: bytes):
    chunks = [payload[i:i + UDP_CHUNK_SIZE] for i in range(0, len(payload), UDP_CHUNK_SIZE)]
    _udp_schedule_sender(
        udp_sock=udp_sock,
        client_addr=client_addr,
        session=session,
        chunk_iter=chunks,
        window=32,
        timeout=0.25,
        max_no_ack_s=5.0,
        kind="message",
    )


def schedule_udp_stream(udp_sock: socket.socket, client_addr, session: int, chunk_iter,
                         window: int = UDP_SEND_WINDOW, timeout: float = UDP_SEND_TIMEOUT, max_no_ack_s: float = UDP_MAX_NO_ACK,
                         log_tag: str = ""):
    _udp_schedule_sender(
        udp_sock=udp_sock,
        client_addr=client_addr,
        session=session,
        chunk_iter=chunk_iter,
        window=window,
        timeout=timeout,
        max_no_ack_s=max_no_ack_s,
        kind="stream",
        log_tag=log_tag,
    )

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

class _TCPClientState:
    __slots__ = (
        "sock",
        "addr",
        "buffer",
        "stage",
        "upload_file",
        "upload_file_name",
        "upload_expected",
        "upload_received",
        "upload_start_t",
        "upload_last_log_t",
        "download_file",
        "download_remaining",
        "send_queue",
    )

    def __init__(self, sock: socket.socket, addr):
        self.sock = sock
        self.addr = addr
        self.buffer = bytearray()
        self.stage = "idle"
        self.upload_file = None
        self.upload_file_name = ""
        self.upload_expected = 0
        self.upload_received = 0
        self.upload_start_t = 0.0
        self.upload_last_log_t = 0.0
        self.download_file = None
        self.download_remaining = 0
        self.send_queue = bytearray()


def _tcp_start_upload(st: _TCPClientState, fname: str, offset: int, total_payload_len: int, initial_data: bytes):
    safe_name = basename(fname)
    st.upload_file_name = safe_name
    full_path = os.path.join(PATH, safe_name)
    mode = "ab" if offset > 0 else "wb"
    st.upload_file = open(full_path, mode)
    if offset > 0:
        st.upload_file.seek(offset)
    if initial_data:
        st.upload_file.write(initial_data)
    st.upload_expected = total_payload_len
    st.upload_received = len(initial_data)
    st.upload_start_t = time.time()
    st.upload_last_log_t = st.upload_start_t
    st.stage = "upload"
    logStr(f"START UPLOAD: {safe_name} ({total_payload_len} bytes)")


def _tcp_start_download(st: _TCPClientState, fname: str, offset: int):
    safe_name = basename(fname)
    full_path = os.path.join(PATH, safe_name)
    if not os.path.isfile(full_path):
        st.send_queue += (b"\x04" + b"\x00" * 14)
        st.stage = "idle"
        return

    file_size = os.path.getsize(full_path)
    data_len = max(0, file_size - offset)
    name_bytes = safe_name.encode("utf-8")
    header = (
        b'\x04' +
        len(name_bytes).to_bytes(2, 'big') +
        name_bytes +
        offset.to_bytes(8, 'big') +
        data_len.to_bytes(4, 'big')
    )
    st.send_queue += header
    st.download_file = open(full_path, "rb")
    if offset > 0:
        st.download_file.seek(offset)
    st.download_remaining = data_len
    st.stage = "download"
    logStr(f"DOWNLOAD: {safe_name} sent from offset {offset}")


def _tcp_try_parse(st: _TCPClientState):
    if st.stage != "idle":
        return
    if st.send_queue:
        return

    while True:
        if st.stage != "idle" or st.send_queue:
            return
        if len(st.buffer) < 3:
            return
        try:
            m_type = st.buffer[0]
            n_len = int.from_bytes(st.buffer[1:3], "big")
            h_size = 15 + n_len
            if len(st.buffer) < h_size:
                return
            fname = st.buffer[3:3 + n_len].decode("utf-8", errors="ignore")
            offset = int.from_bytes(st.buffer[3 + n_len:11 + n_len], "big")
            p_len = int.from_bytes(st.buffer[11 + n_len:15 + n_len], "big")

            if m_type == 0x05:
                del st.buffer[:h_size]
                initial_take = min(len(st.buffer), p_len)
                initial_data = bytes(st.buffer[:initial_take])
                del st.buffer[:initial_take]
                _tcp_start_upload(st, fname, offset, p_len, initial_data)
                if st.upload_received >= st.upload_expected:
                    try:
                        st.upload_file.flush()
                    except Exception:
                        pass
                    try:
                        st.upload_file.close()
                    except Exception:
                        pass
                    st.upload_file = None
                    total_time = time.time() - st.upload_start_t
                    final_speed = (st.upload_received * 8) / (total_time * 1024 * 1024) if total_time > 0 else 0
                    logStr(f"FINISH: {st.upload_file_name} | {st.upload_received} bytes | Avg Speed: {final_speed:.2f} Mbps")
                    st.stage = "idle"
                    continue
                return

            total_msg_size = h_size + p_len
            if len(st.buffer) < total_msg_size:
                return
            payload = bytes(st.buffer[h_size: total_msg_size]) if p_len > 0 else b""
            del st.buffer[:total_msg_size]

            if m_type == 0x00:
                st.send_queue += payload + b"\n"
            elif m_type == 0x01:
                t_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S\n")
                st.send_queue += t_str.encode("utf-8")
            elif m_type == 0x03:
                files_list = "\n".join(os.listdir(PATH)) + "\n"
                st.send_queue += files_list.encode("utf-8")
            elif m_type == 0x06:
                safe_name = basename(fname)
                f_path = os.path.join(PATH, safe_name)
                size = os.path.getsize(f_path) if os.path.exists(f_path) else 0
                st.send_queue += size.to_bytes(8, "big")
            elif m_type == 0x04:
                _tcp_start_download(st, fname, offset)
            elif m_type == 0x02:
                logStr("CMD: EXIT")
                os._exit(0)
            else:
                pass
            return
        except Exception:
            return


def _tcp_close_state(st: _TCPClientState):
    try:
        if st.upload_file:
            st.upload_file.close()
    except Exception:
        pass
    try:
        if st.download_file:
            st.download_file.close()
    except Exception:
        pass
    try:
        st.sock.close()
    except Exception:
        pass


def _tcp_on_readable(st: _TCPClientState):
    if st.stage == "upload":
        remaining = st.upload_expected - st.upload_received
        if remaining <= 0:
            try:
                st.upload_file.close()
            except Exception:
                pass
            st.upload_file = None
            st.stage = "idle"
            return
        try:
            data = st.sock.recv(min(CHUNK_SIZE, remaining))
        except BlockingIOError:
            return
        except Exception:
            data = b""
        if not data:
            try:
                st.upload_file.close()
            except Exception:
                pass
            st.upload_file = None
            st.stage = "idle"
            return
        st.upload_file.write(data)
        st.upload_received += len(data)
        now = time.time()
        if now - st.upload_last_log_t > 2.0:
            speed = (st.upload_received * 8) / ((now - st.upload_start_t) * 1024 * 1024) if now > st.upload_start_t else 0
            logStr(f"PROG: {st.upload_file_name} | {st.upload_received}/{st.upload_expected} | {speed:.2f} Mbps")
            st.upload_last_log_t = now
        if st.upload_received >= st.upload_expected:
            try:
                st.upload_file.flush()
            except Exception:
                pass
            try:
                st.upload_file.close()
            except Exception:
                pass
            st.upload_file = None
            st.stage = "idle"
            total_time = time.time() - st.upload_start_t
            final_speed = (st.upload_received * 8) / (total_time * 1024 * 1024) if total_time > 0 else 0
            logStr(f"FINISH: {st.upload_file_name} | {st.upload_received} bytes | Avg Speed: {final_speed:.2f} Mbps")
            _tcp_try_parse(st)
        return

    if st.stage != "idle":
        return
    if st.send_queue:
        return

    try:
        data = st.sock.recv(65536)
    except BlockingIOError:
        return
    if not data:
        raise ConnectionError("Client disconnected")
    st.buffer.extend(data)
    _tcp_try_parse(st)


def _tcp_on_writable(st: _TCPClientState):
    if st.stage == "upload":
        return
    try:
        if st.send_queue:
            sent = st.sock.send(st.send_queue)
            if sent > 0:
                del st.send_queue[:sent]
    except BlockingIOError:
        return
    except Exception as e:
        raise ConnectionError(str(e))

    if st.stage == "idle":
        if not st.send_queue:
            _tcp_try_parse(st)
        return

    if st.stage == "download":
        if st.send_queue:
            return
        if st.download_remaining > 0:
            to_read = min(CHUNK_SIZE, st.download_remaining)
            data = st.download_file.read(to_read)
            if data:
                st.send_queue += data
                st.download_remaining -= len(data)
            else:
                st.download_remaining = 0
        else:
            try:
                st.download_file.close()
            except Exception:
                pass
            st.download_file = None
            st.stage = "idle"
            _tcp_try_parse(st)


def _multiplex_server_loop():
    tcp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_server_socket.bind(('', TCP_PORT))
    tcp_server_socket.listen(5)
    tcp_server_socket.setblocking(False)

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind(('', UDP_PORT))
    udp_sock.setblocking(False)

    logStr(f"File Transfer Server Started (TCP:{TCP_PORT} UDP:{UDP_PORT})")

    clients: dict[socket.socket, _TCPClientState] = {}
    udp_sessions: dict[tuple[str, int, int], _UDPReceiverState] = {}

    while True:
        now = time.time()

        r_socks = [tcp_server_socket, udp_sock]
        w_socks: list[socket.socket] = []
        for st in list(clients.values()):
            if st.stage == "upload" or (st.stage == "idle" and not st.send_queue):
                r_socks.append(st.sock)
            if st.stage == "download" or st.send_queue:
                w_socks.append(st.sock)

        try:
            readable, writable, _ = select.select(r_socks, w_socks, [], 0.05)
        except Exception:
            readable, writable = [], []

        for s in readable:
            if s is tcp_server_socket:
                while True:
                    try:
                        clientSock, clientAddr = tcp_server_socket.accept()
                    except BlockingIOError:
                        break
                    except Exception:
                        break
                    set_keepalive(clientSock)
                    clientSock.setblocking(False)
                    logStr(f"CONNECT: {clientAddr}")
                    clients[clientSock] = _TCPClientState(clientSock, clientAddr)
            elif s is udp_sock:
                while True:
                    try:
                        data, addr = udp_sock.recvfrom(65535)
                    except BlockingIOError:
                        break
                    except Exception:
                        break
                    parsed = _rudp_unpack(data)
                    if not parsed:
                        continue
                    status, session, ptype, seq, ack, payload = parsed
                    if status != "OK":
                        continue
                    if ptype == PT_ACK:
                        key = (addr[0], addr[1], session)
                        task = _UDP_OUTGOING_TASKS.get(key)
                        if task:
                            try:
                                task.on_ack(ack, now)
                            except Exception:
                                pass
                        continue

                    key = (addr[0], addr[1], session)
                    st = udp_sessions.get(key)
                    if not st:
                        handler = _UDPSessionHandler(udp_sock, addr, session)
                        st = _UDPReceiverState(handler)
                        udp_sessions[key] = st

                    if ptype == PT_DATA and seq < st.expected:
                        udp_sock.sendto(_ack_packet(session, st.expected - 1), addr)
                        continue

                    if ptype in (PT_DATA, PT_FIN):
                        st.feed(ptype, seq, payload)
                        st.drain_in_order()

                        in_order = st.expected - 1
                        if in_order > 0:
                            need_ack = False
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
                                st.handler.on_complete()
                            except Exception as e:
                                logStr(f"UDP SESSION ERROR: {e}")
                            udp_sessions.pop(key, None)

            else:
                st = clients.get(s)
                if not st:
                    continue
                try:
                    _tcp_on_readable(st)
                except Exception:
                    logStr(f"DISCONNECT: {st.addr}")
                    _tcp_close_state(st)
                    clients.pop(s, None)

        for s in writable:
            st = clients.get(s)
            if not st:
                continue
            try:
                _tcp_on_writable(st)
            except Exception:
                logStr(f"DISCONNECT: {st.addr}")
                _tcp_close_state(st)
                clients.pop(s, None)

        for k in list(udp_sessions.keys()):
            if now - udp_sessions[k].last_seen > 120:
                udp_sessions.pop(k, None)

        for key, task in list(_UDP_OUTGOING_TASKS.items()):
            try:
                if task.step(now):
                    _UDP_OUTGOING_TASKS.pop(key, None)
            except Exception as e:
                _UDP_OUTGOING_TASKS.pop(key, None)
                logStr(f"UDP OUTGOING ERROR: {e}")


try:
    _multiplex_server_loop()
except KeyboardInterrupt:
    logStr("SHUTDOWN")