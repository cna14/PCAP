from scapy.all import wrpcap, IP, TCP, UDP, DNS, DNSQR, ICMP, ARP, Ether, Raw
import random
import base64
import os


def generate_sample_pcap(filename="attack_sample.pcap"):
    print(f"[*] Đang tạo file mẫu {filename}...")
    packets = []

    # Cấu hình IP
    attacker_ip = "192.168.1.100"
    victim_ip = "192.168.1.50"
    victim_mac = "aa:bb:cc:dd:ee:ff"

    # Địa chỉ MAC giả lập cho Ethernet header
    attacker_mac = "00:0c:29:4f:8e:35"
    gateway_mac = "00:50:56:c0:00:08"

    # 1. TẠO PORT SCANNING (TCP Connect/SYN Scan)
    print(" -> Tạo dữ liệu Port Scan...")
    for port in range(20, 41):
        # Thêm lớp Ether() vào trước IP
        pkt = Ether(src=attacker_mac, dst=victim_mac) / IP(src=attacker_ip, dst=victim_ip) / TCP(dport=port, flags="S")
        packets.append(pkt)

    # 2. TẠO SYN FLOOD (DoS)
    print(" -> Tạo dữ liệu SYN Flood...")
    for _ in range(300):
        # Thêm lớp Ether()
        pkt = Ether(src="00:11:22:33:44:55", dst=victim_mac) / IP(src="10.10.10.10", dst=victim_ip) / TCP(dport=80,
                                                                                                          flags="S")
        packets.append(pkt)

    # 3. TẠO DNS TUNNELING
    print(" -> Tạo dữ liệu DNS Tunneling...")
    tunnel_ip = "172.16.0.5"
    for _ in range(5):
        secret_data = base64.b64encode(os.urandom(20)).decode('utf-8')
        bad_domain = f"{secret_data}.malicious.site"
        # Thêm lớp Ether()
        pkt = Ether(src=attacker_mac, dst=gateway_mac) / IP(src=tunnel_ip, dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1,
                                                                                                                qd=DNSQR(
                                                                                                                    qname=bad_domain))
        packets.append(pkt)

    # 4. TẠO ARP SPOOFING
    print(" -> Tạo dữ liệu ARP Spoofing...")
    # Lần 1: ARP Reply chuẩn (Bọc trong Ether)
    # Lưu ý: Với ARP, Ether src/dst phải khớp với ARP hwsrc/hwdst logic
    packets.append(
        Ether(src="00:11:22:33:44:55", dst=victim_mac) / ARP(op=2, psrc="192.168.1.1", hwsrc="00:11:22:33:44:55",
                                                             pdst=victim_ip, hwdst=victim_mac))

    # Lần 2: ARP Spoof (Giả mạo MAC)
    packets.append(
        Ether(src="de:ad:be:ef:ca:fe", dst=victim_mac) / ARP(op=2, psrc="192.168.1.1", hwsrc="de:ad:be:ef:ca:fe",
                                                             pdst=victim_ip, hwdst=victim_mac))

    # 5. TẠO LAND ATTACK
    print(" -> Tạo dữ liệu LAND Attack...")
    # Nguồn và đích giống nhau (Cả IP và MAC)
    packets.append(Ether(src=victim_mac, dst=victim_mac) / IP(src=victim_ip, dst=victim_ip) / TCP(dport=135, flags="S"))

    # 6. TẠO STEALTH SCAN (Null & Xmas)
    print(" -> Tạo dữ liệu Stealth Scan...")
    # Null Scan
    packets.append(
        Ether(src=attacker_mac, dst=victim_mac) / IP(src=attacker_ip, dst=victim_ip) / TCP(dport=22, flags=0))
    # Xmas Scan
    packets.append(
        Ether(src=attacker_mac, dst=victim_mac) / IP(src=attacker_ip, dst=victim_ip) / TCP(dport=23, flags="FPU"))

    # 7. TẠO ICMP FLOOD
    print(" -> Tạo dữ liệu ICMP Flood...")
    for _ in range(250):
        pkt = Ether(src="00:00:00:00:00:11", dst=victim_mac) / IP(src="10.0.0.99", dst=victim_ip) / ICMP(type=8)
        packets.append(pkt)

    # 8. TẠO PLAINTEXT CREDENTIALS LEAK
    print(" -> Tạo dữ liệu Lộ mật khẩu...")
    payload = "POST /login HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic YWRtaW46MTIzNDU2\r\n\r\n"
    pkt = Ether(src=attacker_mac, dst=victim_mac) / IP(src=attacker_ip, dst=victim_ip) / TCP(dport=80, sport=54321,
                                                                                             flags="PA") / Raw(
        load=payload)
    packets.append(pkt)

    # Ghi ra file
    try:
        wrpcap(filename, packets)
        print(f"[*] Đã tạo xong file '{filename}' với {len(packets)} gói tin. Không có lỗi linktype.")
    except Exception as e:
        print(f"[!] Lỗi khi ghi file: {e}")


if __name__ == "__main__":
    generate_sample_pcap()