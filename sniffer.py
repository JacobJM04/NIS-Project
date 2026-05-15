import sqlite3
import time
import signal
import sys
import os
from collections import deque
from threading import Thread, Event, Lock
from scapy.all import sniff, IP, TCP, UDP
import config

stop_event = Event()
packet_queue = deque()
queue_lock = Lock()

def init_db():
    conn = sqlite3.connect(config.DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS packets
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  time TEXT,
                  src TEXT,
                  dst TEXT,
                  protocol TEXT,
                  port INTEGER,
                  size INTEGER,
                  epoch REAL)''')
    c.execute("PRAGMA journal_mode=WAL")
    conn.commit()
    conn.close()
    if os.path.exists(config.DB_PATH):
        try:
            os.chmod(config.DB_PATH, 0o666)
        except OSError:
            pass

def cleanup_old_packets():
    try:
        conn = sqlite3.connect(config.DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM packets WHERE id NOT IN (SELECT id FROM packets ORDER BY id DESC LIMIT ?)", (config.MAX_PACKETS,))
        conn.commit()
        conn.close()
    except sqlite3.Error:
        pass

def write_batch():
    batch = []
    with queue_lock:
        if not packet_queue:
            return
        while packet_queue:
            batch.append(packet_queue.popleft())

    if not batch:
        return

    try:
        conn = sqlite3.connect(config.DB_PATH)
        c = conn.cursor()
        data_tuples = [(p['time'], p['src'], p['dst'], p['protocol'], p['port'], p['size'], p['epoch']) for p in batch]
        c.executemany("INSERT INTO packets (time, src, dst, protocol, port, size, epoch) VALUES (?,?,?,?,?,?,?)", data_tuples)
        conn.commit()
        conn.close()
        cleanup_old_packets()
    except sqlite3.Error:
        pass

def packet_handler(pkt):
    if IP not in pkt:
        return
    
    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = "Other"
    port = 0
    
    if TCP in pkt:
        proto = "TCP"
        port = pkt[TCP].dport
    elif UDP in pkt:
        proto = "UDP"
        port = pkt[UDP].dport
        
    packet_data = {
        "time": time.strftime("%H:%M:%S"),
        "src": src,
        "dst": dst,
        "protocol": proto,
        "port": port,
        "size": len(pkt),
        "epoch": time.time()
    }
    
    with queue_lock:
        packet_queue.append(packet_data)
        current_len = len(packet_queue)
    
    if current_len >= config.BATCH_SIZE:
        write_batch()

def batch_writer_loop():
    while not stop_event.is_set():
        time.sleep(config.BATCH_INTERVAL)
        write_batch()

def signal_handler(sig, frame):
    stop_event.set()
    write_batch()
    sys.exit(0)

def start_sniffing(interface=None):
    init_db()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    writer = Thread(target=batch_writer_loop, daemon=True)
    writer.start()
    
    sniff(iface=interface, prn=packet_handler, store=0, stop_filter=lambda x: stop_event.is_set())

if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else None
    start_sniffing(iface)