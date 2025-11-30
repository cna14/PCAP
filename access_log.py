import re
import urllib.parse
from collections import Counter


def analyze_web_log(file_path):
    print(f"[*] Đang phân tích Web Log: {file_path}...")

    # Regex cơ bản cho Apache/Nginx Log
    # Định dạng: IP - - [Time] "METHOD URI PROTOCOL" Status Bytes "Referer" "User-Agent"
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<time>.*?)\] "(?P<method>\w+) (?P<uri>.*?) HTTP/.*?" (?P<status>\d+) (?P<bytes>\d+)(?: ".*?" "(?P<agent>.*?)")?')

    # Các chữ ký tấn công (Attack Signatures)
    signatures = {
        'SQL Injection': [r'union.*select', r'\'\s*or\s*1=1', r'--', r'sleep\(\d+\)', r'information_schema'],
        'XSS (Cross-Site Scripting)': [r'<script>', r'alert\(', r'onerror=', r'onload='],
        'Path Traversal': [r'\.\./', r'/etc/passwd', r'boot\.ini', r'windows/win.ini'],
        'Command Injection': [r';\s*ls', r'\|\s*whoami', r'\$\(.*\)', r';\s*cat']
    }

    attacks_detected = []
    ip_counter = Counter()
    status_404_counter = Counter()

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                match = log_pattern.search(line)
                if not match: continue

                data = match.groupdict()
                ip = data['ip']
                uri = urllib.parse.unquote(data['uri']).lower()  # Giải mã URL (%20 -> Space)
                status = data['status']
                agent = data['agent'] or "Unknown"

                # Thống kê cơ bản
                ip_counter[ip] += 1
                if status == '404':
                    status_404_counter[ip] += 1

                # Kiểm tra chữ ký tấn công
                for attack_type, patterns in signatures.items():
                    for pattern in patterns:
                        if re.search(pattern, uri):
                            attacks_detected.append({
                                'ip': ip,
                                'time': data['time'],
                                'type': attack_type,
                                'payload': data['uri'],  # URI gốc chưa lower để dễ nhìn
                                'status': status,
                                'agent': agent
                            })
                            break  # Đã khớp 1 mẫu thì dừng kiểm tra loại này
    except FileNotFoundError:
        print("[-] Không tìm thấy file log.")
        return

    print("\n" + "=" * 50)
    print("BÁO CÁO PHÂN TÍCH TẤN CÔNG WEB (LOG)")
    print("=" * 50)

    # 1. Phát hiện tấn công dựa trên Payload (Nội dung gói tin)
    if attacks_detected:
        print(f"\n[+] PHÁT HIỆN {len(attacks_detected)} NỖ LỰC TẤN CÔNG CỤ THỂ:")
        print(f"{'Thời gian':<22} | {'IP Nguồn':<15} | {'Loại Tấn Công':<20} | {'Payload (Trích xuất)'}")
        print("-" * 100)
        for attack in attacks_detected:
            print(f"{attack['time']:<22} | {attack['ip']:<15} | {attack['type']:<20} | {attack['payload'][:40]}...")
    else:
        print("\n[+] Không phát hiện các mẫu tấn công Web phổ biến (SQLi, XSS...).")

    # 2. Phát hiện dò quét (Scanner) dựa trên hành vi
    print("\n[+] PHÁT HIỆN DÒ QUÉT (SCANNER/BOT):")
    for ip, count in status_404_counter.items():
        if count > 20:  # Nếu gặp lỗi 404 quá nhiều -> Đang dò file ẩn
            print(f"-> IP: {ip} gây ra {count} lỗi 404. (Nghi vấn: DirBuster/Nikto/Gobuster)")

    # 3. Top IP truy cập (Dấu hiệu DDoS L7)
    print("\n[+] TOP IP TRUY CẬP NHIỀU NHẤT:")
    for ip, count in ip_counter.most_common(3):
        print(f"-> IP: {ip} - Số requests: {count}")


if __name__ == "__main__":
    analyze_web_log('access.log')