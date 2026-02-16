import socket
import datetime
import sys
import os
import time
import os
from os.path import basename

buffer = b""
path = "./serverFiles"

if not os.path.exists(path):
    os.makedirs(path)

def logStr(strLog: str):
    timeStr = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timeStr} - {strLog}")

def set_keepalive(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if sys.platform == "win32":
        sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 30000, 2000))
    elif sys.platform == "darwin":
        TCP_KEEPALIVE = getattr(socket, 'TCP_KEEPALIVE', 0x10)
        sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPALIVE, 30)
    elif sys.platform == "linux":
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 10)

def uploadCommand(conn, fileName, offset, payload):
    safe_name = basename(fileName) 
    full_path = os.path.join(path, safe_name)
    
    start_time = time.time()
    mode = "ab" if offset > 0 else "wb"
    try:
        with open(full_path, mode) as f:
            f.seek(offset)
            f.write(payload)
        duration = time.time() - start_time
        bitrate = (len(payload) * 8) / duration if duration > 0.000001 else 0
        logStr(f"UPLOAD: {safe_name}, Size: {len(payload)}, Offset: {offset}, Speed: {bitrate:.2f} bps")
    except Exception as e:
        logStr(f"UPLOAD ERROR: {e}")

def downloadCommand(conn, fileName, offset=0):
    safe_name = basename(fileName)
    full_path = os.path.join(path, safe_name)
    
    if not os.path.isfile(full_path):
        logStr(f"DOWNLOAD ERROR: File {safe_name} not found")
        conn.sendall(b"\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        return

    try:
        file_size = os.path.getsize(full_path)
        data_len = file_size - offset
        if data_len < 0: data_len = 0

        name_bytes = safe_name.encode('utf-8')

        header = (
            b'\x04' + 
            len(name_bytes).to_bytes(2, 'big') + 
            name_bytes + 
            offset.to_bytes(8, 'big') + 
            data_len.to_bytes(4, 'big')
        )
        conn.sendall(header)

        with open(full_path, "rb") as f:
            f.seek(offset)
            while True:
                chunk = f.read(65536) 
                if not chunk: 
                    break
                conn.sendall(chunk)
        
        logStr(f"DOWNLOAD: {safe_name} sent completely from offset {offset}")
    except Exception as e:
        logStr(f"DOWNLOAD STREAM ERROR: {e}")

def processCommand(conn, m_type, filename, offset, payload):
    try:
        fname_str = filename.tobytes().decode("utf-8") if filename else ""
    except:
        fname_str = ""
    if m_type == 0x00:
        logStr(f"CMD: ECHO")
        conn.sendall(payload.tobytes() + b"\n")
    elif m_type == 0x01:
        logStr(f"CMD: TIME")
        t_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S\n")
        conn.sendall(t_str.encode("utf-8"))
    elif m_type == 0x02:
        logStr("CMD: EXIT - Closing connection")
        return False
    elif m_type == 0x03:
        logStr(f"CMD: LS")
        files_list = "\n".join(os.listdir(path)) + "\n"
        conn.sendall(files_list.encode("utf-8"))
    elif m_type == 0x04:
        downloadCommand(conn, fname_str, offset)
    elif m_type == 0x05:
        uploadCommand(conn, fname_str, offset, payload.tobytes())
    return True

def createMessage(conn, data: bytes):
    global buffer
    buffer += data
    while len(buffer) >= 3:
        mv = memoryview(buffer)
        n_len = int.from_bytes(mv[1:3], byteorder='big')
        h_size = 15 + n_len
        if len(buffer) < h_size: break
        p_len = int.from_bytes(mv[11+n_len : 15+n_len], byteorder='big')
        total_size = h_size + p_len
        if len(buffer) < total_size: break
        m_type = mv[0]
        fname = mv[3 : 3+n_len]
        offs = int.from_bytes(mv[3+n_len : 11+n_len], byteorder='big')
        payl = mv[15+n_len : total_size]
        should_continue = processCommand(conn, m_type, fname, offs, payl)
        buffer = buffer[total_size:]
        if not should_continue: return False
    return True

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
serverSocket.bind(('', 3000))
serverSocket.listen(1)

logStr("SERVER STARTED - Waiting for clients on port 3000")

try:
    while True:
        clientSock, clientAddr = serverSocket.accept()
        set_keepalive(clientSock) 
        logStr(f"CONNECT: {clientAddr}")
        buffer = b"" 
        try:
            while True:
                data = clientSock.recv(4096)
                if not data: break
                if not createMessage(clientSock, data): break
        except Exception as e:
            logStr(f"DISCONNECT ERROR: {e}")
        finally:
            clientSock.close()
            logStr(f"DISCONNECT: {clientAddr}")
except KeyboardInterrupt:
    logStr("SERVER SHUTDOWN")
    serverSocket.close()