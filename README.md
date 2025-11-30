# 🛡️ Network Intrusion Detection System (NIDS) - PCAP Analyzer

Công cụ phân tích file PCAP (Packet Capture) được xây dựng bằng Python và thư viện Scapy. Hệ thống hoạt động như một IDS (Intrusion Detection System) thu nhỏ, có khả năng đọc luồng dữ liệu mạng, bóc tách các lớp giao thức và phát hiện 8 loại hình tấn công mạng phổ biến dựa trên chữ ký (signature) và hành vi (anomaly detection).

## 🚀 Tính năng nổi bật

1.  **Streaming Analysis:** Sử dụng cơ chế đọc luồng (`PcapReader`) thay vì tải toàn bộ file vào RAM, cho phép phân tích các file PCAP dung lượng lớn (GB) mà không gây tràn bộ nhớ.
2.  **Đa dạng phát hiện:** Nhận diện được từ các cuộc tấn công thô sơ (Ping Flood) đến các kỹ thuật tinh vi (DNS Tunneling, Stealth Scan).
3.  **Hỗ trợ IPv4 & IPv6:** Tương thích với cả hai thế hệ địa chỉ IP.

---

## 🧠 Logic Phân Tích & Truy Vết

Hệ thống hoạt động bằng cách "đọc phong bì" (Headers) và "soi nội dung" (Payload) của từng gói tin theo mô hình OSI.

### 1. Truy vết nguồn tấn công (Source Identification)
* **IP Source (`src_ip`):** Xác định địa chỉ IP nguồn của gói tin độc hại. Tuy nhiên, hệ thống cũng cảnh báo nếu nghi ngờ IP này bị giả mạo (Spoofing).
* **MAC Address (`hwsrc`):** Truy vết địa chỉ vật lý của thiết bị tấn công trong mạng nội bộ (LAN), giúp xác định chính xác thiết bị nào đang bị xâm nhập hoặc thực hiện tấn công ARP.

### 2. Phân tích theo lớp giao thức

#### 🟢 Layer 2: Data Link (ARP)
* **Phát hiện:** ARP Spoofing / Man-in-the-Middle.
* **Logic:** Hệ thống duy trì một bảng ánh xạ `IP <-> MAC`.
    * Nếu phát hiện một IP bất ngờ thay đổi địa chỉ MAC liên kết với nó (Ví dụ: `192.168.1.1` lúc đầu là MAC A, sau đó đổi thành MAC B).
    * -> **Kết luận:** Có kẻ đang giả mạo Gateway để nghe lén.

#### 🔵 Layer 3: Network (IP)
* **Phát hiện:** LAND Attack.
* **Logic:** Kiểm tra địa chỉ Nguồn và Đích.
    * Nếu `src_ip == dst_ip` (Gói tin tự gửi cho chính mình).
    * -> **Kết luận:** Tấn công gây lỗi vòng lặp ngăn xếp TCP/IP.

#### 🟡 Layer 4: Transport (TCP/UDP/ICMP)
Dựa vào phân tích cờ hiệu (Flags) và tần suất gửi gói tin.

* **SYN Flood (DoS):**
    * Logic: Đếm số lượng gói tin có cờ `SYN=1` và `ACK=0`. Nếu tần suất vượt ngưỡng cho phép (Threshold) từ một nguồn.
    * -> **Kết luận:** Tấn công từ chối dịch vụ hoặc Brute Force.
* **Port Scanning (Dò quét):**
    * Logic: Theo dõi danh sách các cổng đích (`dport`) mà một IP kết nối tới. Nếu một IP kết nối tới quá nhiều cổng khác nhau (> 15 cổng).
    * -> **Kết luận:** Kẻ tấn công đang dò tìm lỗ hổng dịch vụ.
* **Stealth Scans (Quét lén lút):**
    * **Null Scan:** Gói tin không bật cờ nào (`flags == 0`).
    * **Xmas Scan:** Gói tin bật tổ hợp cờ phi logic (`FIN + PSH + URG`).
    * -> **Kết luận:** Kỹ thuật quét nhằm qua mặt Firewall cũ.
* **ICMP Flood:**
    * Logic: Đếm số lượng gói tin `Echo Request` (Ping) trong thời gian ngắn.

#### 🔴 Layer 7: Application (Payload)
Phân tích nội dung thực sự của gói tin.

* **DNS Tunneling (Exfiltration):**
    * Logic: Sử dụng thuật toán **Shannon Entropy** để đo độ "hỗn loạn" của tên miền truy vấn.
    * Nếu tên miền có độ entropy cao (Ví dụ: `x8s7f9a...hack.com` thay vì `google.com`) hoặc độ dài bất thường.
    * -> **Kết luận:** Dữ liệu đang bị đánh cắp và giấu trong truy vấn DNS.
* **Plaintext Credentials (Lộ mật khẩu):**
    * Logic: Quét lớp dữ liệu thô (`Raw Layer`) tìm các từ khóa nhạy cảm như `USER`, `PASS`, `Authorization: Basic`.
    * -> **Kết luận:** Người dùng đăng nhập qua giao thức không an toàn (HTTP/FTP/Telnet).

---

## 🛠️ Cài đặt & Sử dụng

### 1. Yêu cầu hệ thống
* Python 3.x
* Thư viện Scapy

```bash
pip install scapy
```
(Trên Windows, cần cài thêm Npcap ở chế độ "WinPcap compatible")

2. Cách chạy
Bước 1: Tạo dữ liệu giả lập (Tùy chọn) Nếu chưa có file PCAP thực tế, chạy script này để tạo file mẫu chứa đủ 8 loại tấn công:

```Bash
python generate_pcap.py
```
Kết quả: Sinh ra file attack_sample.pcap.

Bước 2: Chạy bộ phân tích

```Bash
python pcap_analyzer.py
```
Hệ thống sẽ đọc file pcap và in báo cáo chi tiết ra màn hình.

📂 Cấu trúc dự án
Plaintext

.
├── pcap_analyzer.py    # Core: Mã nguồn phân tích & phát hiện tấn công
├── generate_pcap.py    # Tool: Tạo file pcap mẫu với các kịch bản tấn công
├── attack_sample.pcap  # Data: File dữ liệu mẫu (được sinh ra từ tool)
├── .gitignore          # Config: Cấu hình bỏ qua file rác khi đẩy lên Git
└── README.md           # Doc: Tài liệu hướng dẫn (File này)
⚠️ Lưu ý
Công cụ này được xây dựng cho mục đích giáo dục và nghiên cứu an ninh mạng. Vui lòng chỉ sử dụng trên các hệ thống mạng mà bạn có quyền kiểm soát hoặc được cấp phép.
