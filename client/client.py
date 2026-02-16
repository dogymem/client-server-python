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
        sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 30000, 2000))
    elif sys.platform == "darwin":
        TCP_KEEPALIVE = getattr(socket, 'TCP_KEEPALIVE', 0x10)
        sock.setsockopt(socket.IPPROTO_TCP, TCP_KEEPALIVE, 30)
    else:
        sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, 'TCP_KEEPIDLE', 4), 30)
        sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, 'TCP_KEEPINTVL', 5), 2)
        sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, 'TCP_KEEPCNT', 6), 10)

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
    sent_bytes = 0 
    max_retry_time = 180
    start_recovery_t = None

    log_msg(f"Starting upload: {filename}")

    while sent_bytes < file_size:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            set_keepalive(sock)
            sock.connect((SERVER_IP, SERVER_PORT))
            
            if start_recovery_t:
                log_msg("\nConnection restored! Resuming...")
                start_recovery_t = None

            # Фиксируем время начала передачи текущей сессии
            session_start_t = time.time()
            # Запоминаем, сколько было передано до начала этой сессии для честного расчета
            bytes_at_session_start = sent_bytes

            with open(local_path, "rb") as f:
                f.seek(sent_bytes)
                while sent_bytes < file_size:
                    chunk = f.read(65536)
                    if not chunk: break
                    
                    packet = create_packet(0x05, filename, sent_bytes, chunk)
                    sock.sendall(packet)
                    
                    sent_bytes += len(chunk)
                    
                    # Расчет битрейта
                    duration = time.time() - session_start_t
                    # (Байты в этой сессии * 8) / (1024 * 1024) = Мегабиты
                    if duration > 0:
                        mbits = ((sent_bytes - bytes_at_session_start) * 8) / (1024 * 1024)
                        bitrate = mbits / duration
                    else:
                        bitrate = 0
                        
                    print(f"\rProgress: {sent_bytes}/{file_size} bytes | Speed: {bitrate:.2f} Mbit/s", end="")
            
            log_msg(f"\nUpload of {filename} completed.")
            break 

        except (socket.error, BrokenPipeError) as e:
            if not start_recovery_t:
                start_recovery_t = time.time()
                print(f"\n[!] Connection lost: {e}")
            
            elapsed = time.time() - start_recovery_t
            if elapsed > max_retry_time:
                log_msg("Recovery timeout. Upload failed.")
                break
            time.sleep(5)
        finally:
            sock.close()

def do_download(args):
    if not args:
        print("Usage: download <filename>")
        return
    filename = args[0]
    local_path = os.path.join(FILES_PATH, filename)
    
    max_retry_time = 180
    start_recovery_t = None

    while True:
        current_offset = os.path.getsize(local_path) if os.path.exists(local_path) else 0
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            set_keepalive(sock)
            sock.connect((SERVER_IP, SERVER_PORT))
            
            if start_recovery_t:
                log_msg("\nConnection restored! Resuming download...")
                start_recovery_t = None

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

            # Время старта именно этой сессии докачки
            session_start_t = time.time()

            with open(local_path, "ab") as f:
                first_chunk = header_data[header_size:]
                if first_chunk:
                    f.write(first_chunk)
                
                received_in_session = len(first_chunk)
                while received_in_session < payload_total_size:
                    data = sock.recv(65536)
                    if not data: break
                    f.write(data)
                    received_in_session += len(data)
                    
                    # Расчет битрейта в Мбит/с
                    duration = time.time() - session_start_t
                    if duration > 0:
                        bitrate = (received_in_session * 8) / (1024 * 1024) / duration
                    else:
                        bitrate = 0
                        
                    total_now = current_offset + received_in_session
                    print(f"\rDownloaded: {total_now} bytes | Speed: {bitrate:.2f} Mbit/s", end="")
            
            print(f"\nDownload finished.")
            break

        except (socket.error, BrokenPipeError) as e:
            if not start_recovery_t:
                start_recovery_t = time.time()
                print(f"\n[!] Connection lost: {e}")
            
            if (time.time() - start_recovery_t) > max_retry_time:
                log_msg("Recovery timeout. Download failed.")
                break
            time.sleep(5)
        finally:
            sock.close()

def show_help():
    print("""
Available commands:
  echo <message>      - Send text to the server
  time                - Get the current server time
  ls                  - List files available on the server
  upload <filename>   - Upload a file from ./clientFiles to the server
  download <filename> - Download a file from the server (supports resume)
  exit_server         - Shut down the server (command 0x02)
  help                - Show this help message
  quit                - Close the client
    """)

print("TCP Binary Client Started. Type 'help' for commands.")
while True:
    try:
        user_input = input("\nclient> ").strip().split()
        if not user_input: continue
        
        cmd = user_input[0].lower()
        args = user_input[1:]

        if cmd == "help":
            show_help()
        elif cmd == "echo":
            res = send_and_receive(create_packet(0x00, payload=" ".join(args).encode()))
            if res: print("Server:", res.decode(errors='ignore'))
        elif cmd == "time":
            res = send_and_receive(create_packet(0x01))
            if res: print("Time:", res.decode())
        elif cmd == "ls":
            res = send_and_receive(create_packet(0x03))
            if res: print("Files:\n", res.decode())
        elif cmd == "upload":
            do_upload(args)
        elif cmd == "exit_server":
            send_and_receive(create_packet(0x02), False)
            print("Signal sent.")
        elif cmd == "download":
            do_download(args)
        elif cmd in ["quit", "exit"]:
            break
        else:
            print(f"Unknown command '{cmd}'. Type 'help' for info.")
    except KeyboardInterrupt:
        break
    except Exception as e:
        print(f"System Error: {e}")
