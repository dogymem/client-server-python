import socket
import datetime
import sys
import os
import time
from os.path import basename

PATH = "./serverFiles"
PORT = 3000
CHUNK_SIZE = 65536

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
                    raise ConnectionError("Connection lost")
                
                f.write(chunk)
                bytes_received += len(chunk)

                now = time.time()
                if now - last_log_time > 2.0:
                    speed = (bytes_received * 8) / ((now - start_time) * 1024 * 1024)
                    logStr(f"PROG: {safe_name} | {bytes_received}/{total_payload_len} | {speed:.2f} Mbps")
                    last_log_time = now

        total_time = time.time() - start_time
        final_speed = (bytes_received * 8) / (total_time * 1024 * 1024) if total_time > 0 else 0
        logStr(f"FINISH: {safe_name} | Avg Speed: {final_speed:.2f} Mbps")
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

        with open(full_path, "rb") as f:
            f.seek(offset)
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk: break
                conn.sendall(chunk)
        logStr(f"DOWNLOAD: {safe_name} sent")
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
                n_len = int.from_bytes(buffer[1:3], byteorder='big')
                h_size = 15 + n_len
                
                if len(buffer) < h_size:
                    break
                
                m_type = buffer[0]
                fname = buffer[3 : 3+n_len].decode('utf-8', errors='ignore')
                offset = int.from_bytes(buffer[3+n_len : 11+n_len], byteorder='big')
                p_len = int.from_bytes(buffer[11+n_len : 15+n_len], byteorder='big')

                if m_type == 0x05:
                    payload_in_buffer = buffer[h_size : h_size + p_len]
                    buffer.clear()
                    logStr(f"START UPLOAD: {fname} ({p_len} bytes)")
                    upload_stream(client_sock, fname, offset, p_len, payload_in_buffer)
                    break 

                elif m_type == 0x02:
                    logStr("CMD: EXIT")
                    return

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

serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
serverSocket.bind(('', PORT))
serverSocket.listen(5)

logStr(f"SERVER STARTED - Port {PORT}")

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