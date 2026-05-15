import sqlite3
import time
import random
import netifaces
import config

def get_local_ips():
    ips = set()
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for addr in addrs:
                ips.add(addr['addr'])
    except ValueError:
        pass
    return ips

def random_ip(prefixes=None):
    if prefixes:
        prefix = random.choice(prefixes)
        return f"{prefix}{random.randint(1,254)}"
    else:
        return ".".join(str(random.randint(1,254)) for _ in range(4))

def inject_attack_packets(count=500):
    local_ips = get_local_ips()
    internal_prefixes = [
        "192.168.0.", "192.168.1.", "192.168.2.", "192.168.3.",
        "10.0.0.", "10.0.1.", "10.0.2.", "10.0.3.",
        "172.16.0.", "172.16.1.", "172.17.0.", "172.18.0."
    ]
    ports = [22, 23, 80, 443, 445, 3389, 8080, 8443, 53, 123]
    protocols = ["TCP", "UDP"]

    conn = sqlite3.connect(config.DB_PATH)
    c = conn.cursor()
    now = time.time()
    
    data_tuples = []

    for i in range(count):
        src_ip = random_ip(internal_prefixes)
        while src_ip in local_ips:
            src_ip = random_ip(internal_prefixes)

        if random.random() < 0.5:
            dst_ip = random_ip(internal_prefixes)
        else:
            dst_ip = random_ip()

        protocol = random.choice(protocols)
        port = random.choice(ports)
        size = random.randint(40, 1500)
        ts_epoch = now + i * 0.001
        ts_str = time.strftime("%H:%M:%S", time.localtime(ts_epoch))

        data_tuples.append((ts_str, src_ip, dst_ip, protocol, port, size, ts_epoch))

    c.executemany("INSERT INTO packets (time, src, dst, protocol, port, size, epoch) VALUES (?,?,?,?,?,?,?)", data_tuples)
    conn.commit()
    conn.close()
    print(f"Injected {count} random attack packets")

if __name__ == "__main__":
    inject_attack_packets()