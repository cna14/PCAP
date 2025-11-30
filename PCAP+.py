from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNSQR, ICMP, ARP, Raw
from collections import defaultdict, Counter
import math
import sys


def calculate_entropy(text):
    """Tính độ hỗn loạn của chuỗi (Shannon Entropy)"""
    if not text: return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def analyze_pcap(file_path):
    print(f"[*] Đang khởi động bộ phân tích (Streaming Mode): {file_path}")
    print("[*] Chế độ này hỗ trợ file dung lượng lớn (GB) và IPv6.")

    # --- CÁC BỘ ĐẾM VÀ LƯU TRỮ ---
    # Thống kê cơ bản
    stats = {'total': 0, 'ipv4': 0, 'ipv6': 0, 'tcp': 0, 'udp': 0, 'errors': 0}

    # 1. Scanning & Flooding
    syn_flood_tracker = Counter()
    port_scan_tracker = defaultdict(set)
    icmp_flood_tracker = Counter()
    stealth_scan_log = defaultdict(list)

    # 2. Anomalies
    land_attack_log = []
    arp_mapping = {}
    arp_warnings = []

    # 3. Application Layer
    dns_queries = defaultdict(list)
    cred_leaks = []

    try:
        # PcapReader: Đọc tuần tự từng gói (Tiết kiệm RAM tối đa)
        with PcapReader(file_path) as pcap_reader:
            for pkt in pcap_reader:
                stats['total'] += 1
                if stats['total'] % 5000 == 0:
                    print(f"    -> Đã xử lý {stats['total']} gói tin...", end='\r')

                try:
                    # --- LỚP 2: ARP (Chỉ có trên mạng IPv4 cục bộ) ---
                    if ARP in pkt and pkt[ARP].op == 2:
                        src_ip, src_mac = pkt[ARP].psrc, pkt[ARP].hwsrc
                        if src_ip in arp_mapping and arp_mapping[src_ip] != src_mac:
                            w = f"IP {src_ip} đổi MAC: {arp_mapping[src_ip]} -> {src_mac}"
                            if w not in arp_warnings: arp_warnings.append(w)
                        else:
                            arp_mapping[src_ip] = src_mac

                    # --- LỚP 3: IP (Hỗ trợ cả IPv4 và IPv6) ---
                    src_ip = None
                    dst_ip = None

                    if IP in pkt:
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        stats['ipv4'] += 1
                    elif IPv6 in pkt:
                        src_ip = pkt[IPv6].src
                        dst_ip = pkt[IPv6].dst
                        stats['ipv6'] += 1

                    if not src_ip: continue  # Không phải gói IP (có thể là STP, LLC...)

                    # 5. Phát hiện LAND Attack
                    if src_ip == dst_ip:
                        land_attack_log.append(f"{src_ip} tự gửi gói tin cho chính mình")

                    # --- LỚP 4: TCP ---
                    if TCP in pkt:
                        stats['tcp'] += 1
                        dport = pkt[TCP].dport
                        flags = pkt[TCP].flags

                        # 1 & 2. SYN Flood & Connect Scan
                        if flags & 0x02 and not flags & 0x10:  # SYN=1, ACK=0
                            syn_flood_tracker[src_ip] += 1
                            port_scan_tracker[src_ip].add(dport)

                        # 6. Stealth Scans
                        if flags == 0:  # Null Scan
                            stealth_scan_log[src_ip].append(f"Null Scan -> {dst_ip}:{dport}")
                        elif flags & 0x29 == 0x29:  # Xmas Scan (FIN,PSH,URG)
                            stealth_scan_log[src_ip].append(f"Xmas Scan -> {dst_ip}:{dport}")

                        # 8. Plaintext Credentials
                        if pkt.haslayer(Raw):
                            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                            if any(k in payload.upper() for k in ['USER ', 'PASS ', 'AUTHORIZATION: BASIC']):
                                clean_payload = payload.replace('\r', '').replace('\n', ' ')[:100]
                                cred_leaks.append(f"{src_ip}:{pkt[TCP].sport} -> {dst_ip}:{dport} | {clean_payload}")

                    # --- LỚP 4: UDP/DNS ---
                    if UDP in pkt:
                        stats['udp'] += 1

                    if pkt.haslayer(DNSQR):
                        qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').strip('.')
                        dns_queries[src_ip].append(qname)

                    # 7. ICMP Flood
                    if ICMP in pkt and pkt[ICMP].type == 8:
                        icmp_flood_tracker[src_ip] += 1

                except Exception as e:
                    # Bỏ qua gói lỗi để không dừng chương trình
                    stats['errors'] += 1
                    continue

    except FileNotFoundError:
        print("\n[-] Lỗi: Không tìm thấy file pcap.")
        return
    except Exception as e:
        print(f"\n[-] Lỗi nghiêm trọng khi mở file: {e}")
        return

    # ================= BÁO CÁO KẾT QUẢ =================
    print(
        f"\n\n[+] HOÀN TẤT. Tổng: {stats['total']} gói (IPv4: {stats['ipv4']}, IPv6: {stats['ipv6']}, Lỗi: {stats['errors']})")
    print("=" * 60)

    # GROUP 1: SCANNING
    print("\n[1] DÒ QUÉT CỔNG (PORT SCANNING)")
    has_scan = False
    for ip, ports in port_scan_tracker.items():
        if len(ports) > 15:  # Ngưỡng
            print(f" [!] {ip:<20}: Quét {len(ports)} cổng (TCP Connect/SYN)")
            has_scan = True
    for ip, logs in stealth_scan_log.items():
        print(f" [!] {ip:<20}: {len(logs)} lần quét tàng hình (Null/Xmas)")
        has_scan = True
    if not has_scan: print(" [+] Không phát hiện hành vi dò quét rõ ràng.")

    # GROUP 2: DOS / FLOODING
    print("\n[2] TẤN CÔNG TỪ CHỐI DỊCH VỤ (DOS/FLOOD)")
    has_flood = False
    for ip, count in syn_flood_tracker.most_common():
        if count > 200:
            print(f" [!] {ip:<20}: SYN Flood ({count} packets) -> Nghi vấn DoS/BruteForce")
            has_flood = True
    for ip, count in icmp_flood_tracker.items():
        if count > 200:
            print(f" [!] {ip:<20}: ICMP Ping Flood ({count} packets)")
            has_flood = True
    if land_attack_log:
        print(f" [!] LAND Attack: {len(land_attack_log)} gói tin dị hình.")
        has_flood = True
    if not has_flood: print(" [+] Lưu lượng mạng ổn định.")

    # GROUP 3: ANOMALY & SPOOFING
    print("\n[3] GIẢ MẠO & ĐƯỜNG HẦM (SPOOFING/TUNNEL)")
    if arp_warnings:
        for w in arp_warnings: print(f" [!] ARP Spoofing: {w}")
    else:
        print(" [+] ARP: An toàn.")

    tunnel_detected = False
    for ip, queries in dns_queries.items():
        # Lọc nhiễu: chỉ lấy query dài hoặc entropy cực cao
        suspicious = [q for q in queries if calculate_entropy(q) > 4.5 or len(q) > 60]
        if suspicious:
            print(f" [!] {ip:<20}: Nghi ngờ DNS Tunnel ({len(suspicious)} queries)")
            print(f"     Mẫu: {suspicious[0][:60]}...")
            tunnel_detected = True
    if not tunnel_detected: print(" [+] DNS: An toàn.")

    # GROUP 4: DATA LEAKAGE
    print("\n[4] DỮ LIỆU NHẠY CẢM (PLAINTEXT CREDENTIALS)")
    if cred_leaks:
        print(f" [!!!] PHÁT HIỆN {len(cred_leaks)} GÓI TIN CHỨA MẬT KHẨU RÕ:")
        for leak in cred_leaks[:10]:  # Chỉ in 10 cái đầu
            print(f"  -> {leak}")
        if len(cred_leaks) > 10: print(f"  ... và {len(cred_leaks) - 10} gói khác.")
    else:
        print(" [+] Không phát hiện mật khẩu dạng rõ.")


if __name__ == "__main__":
    # Thay đường dẫn file pcap của bạn vào đây
    analyze_pcap('attack_sample.pcap')