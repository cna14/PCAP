from scapy.all import rdpcap, IP, TCP, UDP, DNSQR, ICMP, ARP
from collections import defaultdict, Counter
import math


def calculate_entropy(text):
    """Tính độ hỗn loạn của chuỗi để phát hiện mã hóa/tunneling"""
    if not text: return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def analyze_pcap(file_path):
    print(f"[*] Đang đọc file PCAP: {file_path}...")
    try:
        packets = rdpcap(file_path)
    except FileNotFoundError:
        print("[-] Không tìm thấy file.")
        return

    # Các bộ lưu trữ thống kê
    syn_flood_tracker = Counter()  # Đếm gói SYN
    port_scan_tracker = defaultdict(set)  # IP -> Set các Port đích
    dns_queries = defaultdict(list)  # IP -> Các tên miền đã hỏi
    icmp_flood_tracker = Counter()  # Đếm gói ICMP
    arp_mapping = {}  # IP -> MAC (Dùng để phát hiện ARP Spoofing)
    arp_spoof_warnings = []  # Danh sách cảnh báo ARP

    print(f"[*] Đã tải {len(packets)} gói tin. Đang phân tích...")

    for pkt in packets:
        # 4. Phân tích ARP (Phát hiện ARP Spoofing - Logic từ bài mẫu của bạn)
        if ARP in pkt and pkt[ARP].op == 2:  # ARP Reply (is-at)
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc

            if src_ip in arp_mapping:
                if arp_mapping[src_ip] != src_mac:
                    # Phát hiện xung đột: Cùng 1 IP nhưng MAC thay đổi -> Dấu hiệu tấn công
                    warning = f"IP {src_ip} thay đổi MAC từ {arp_mapping[src_ip]} sang {src_mac}"
                    if warning not in arp_spoof_warnings:
                        arp_spoof_warnings.append(warning)
            else:
                arp_mapping[src_ip] = src_mac

        if IP not in pkt:
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # 1. Phân tích TCP (Phát hiện SYN Flood & Port Scan)
        if TCP in pkt:
            dport = pkt[TCP].dport
            # Cờ SYN được bật và ACK tắt (Bắt đầu kết nối)
            if pkt[TCP].flags & 0x02 and not pkt[TCP].flags & 0x10:
                syn_flood_tracker[src_ip] += 1
                port_scan_tracker[src_ip].add(dport)

        # 2. Phân tích UDP/DNS (Phát hiện DNS Tunneling/DGA)
        if pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').strip('.')
            dns_queries[src_ip].append(qname)

        # 3. Phân tích ICMP (Ping Flood)
        if ICMP in pkt and pkt[ICMP].type == 8:  # Echo Request
            icmp_flood_tracker[src_ip] += 1

    print("\n" + "=" * 50)
    print("BÁO CÁO PHÂN TÍCH TẤN CÔNG MẠNG (PCAP)")
    print("=" * 50)

    # --- BÁO CÁO 1: ARP SPOOFING (Mới bổ sung) ---
    if arp_spoof_warnings:
        print("\n[!!!] CẢNH BÁO: ARP SPOOFING / MAN-IN-THE-MIDDLE")
        for w in arp_spoof_warnings:
            print(f"-> {w}")
    else:
        print("\n[+] ARP Check: Không phát hiện xung đột địa chỉ MAC.")

    # --- BÁO CÁO 2: TCP SYN FLOOD / BRUTE FORCE ---
    print("\n[+] CẢNH BÁO: TCP SYN FLOOD / BRUTE FORCE")
    print(f"{'Nguồn Tấn Công':<20} | {'Số lượng Request':<15} | {'Đánh giá'}")
    for ip, count in syn_flood_tracker.most_common():
        if count > 50:  # Ngưỡng giả định
            print(f"{ip:<20} | {count:<15} | Nghi vấn tấn công DoS hoặc Brute Force")

    # --- BÁO CÁO 3: PORT SCANNING ---
    print("\n[+] CẢNH BÁO: PORT SCANNING (Dò quét cổng)")
    print(f"{'Nguồn Tấn Công':<20} | {'Số cổng đã quét':<15} | {'Chi tiết'}")
    for ip, ports in port_scan_tracker.items():
        if len(ports) > 10:  # Quét hơn 10 cổng
            print(f"{ip:<20} | {len(ports):<15} | Quét dải rộng (VD: {list(ports)[:5]}...)")

    # --- BÁO CÁO 4: DNS TUNNELING ---
    print("\n[+] CẢNH BÁO: DNS TUNNELING / EXFILTRATION")
    for ip, queries in dns_queries.items():
        high_entropy_queries = [q for q in queries if calculate_entropy(q) > 4.0 or len(q) > 50]
        if high_entropy_queries:
            print(f"-> Nguồn: {ip}")
            print(f"   Giao thức: DNS")
            print(f"   Dấu hiệu: {len(high_entropy_queries)} truy vấn tên miền lạ (Entropy cao/Dài bất thường)")
            print(f"   Mẫu: {high_entropy_queries[0]}")


if __name__ == "__main__":
    # Thay đường dẫn file pcap của bạn vào đây
    # Bạn có thể dùng file tạo ra từ bài colab trước: 'pcaps/portscan.pcap' hoặc 'pcaps/arp_spoof.pcap'
    analyze_pcap('attack_sample.pcap')