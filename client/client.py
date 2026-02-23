import socket
import os
import time
import datetime
import sys

SERVER_IP = '127.0.0.1'
SERVER_PORT = 3000
FILES_PATH = "./clientFiles"

if not os.path.exists(FILES_PATH):
    os.makedirs(FILES_PATH)

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

def send_and_receive(packet, wait_response=True):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        set_keepalive(sock)
        sock.connect((SERVER_IP, SERVER_PORT))
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

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            set_keepalive(sock)
            sock.connect((SERVER_IP, SERVER_PORT))
            
            bytes_to_send = file_size - remote_offset
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
            
            print(f"\nUpload of {filename} completed.")
            sock.close()
            break 

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

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            set_keepalive(sock)
            sock.connect((SERVER_IP, SERVER_PORT))
            
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
            
            print(f"\nDownload finished.")
            sock.close()
            break

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
  echo <msg>, time, ls, upload <file>, download <file>, exit_server, quit
    """)

print("TCP Binary Client Started.")
while True:
    try:
        user_input = input("\nclient> ").strip().split()
        if not user_input: continue
        cmd = user_input[0].lower()
        args = user_input[1:]

        if cmd == "help": show_help()
        elif cmd == "echo":
            res = send_and_receive(create_packet(0x00, payload=" ".join(args).encode()))
            if res: print("Server:", res.decode(errors='ignore'))
        elif cmd == "time":
            res = send_and_receive(create_packet(0x01))
            if res: print("Time:", res.decode())
        elif cmd == "ls":
            res = send_and_receive(create_packet(0x03))
            if res: print("Files:\n", res.decode())
        elif cmd == "upload": do_upload(args)
        elif cmd == "download": do_download(args)
        elif cmd == "exit_server":
            send_and_receive(create_packet(0x02), False)
        elif cmd in ["quit", "exit"]: break
        else: print(f"Unknown command '{cmd}'")
    except KeyboardInterrupt: break