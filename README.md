# PCAP Programming Project

## 1. 프로젝트 개요

본 프로젝트는 **libpcap 라이브러리**를 이용하여 실시간으로 TCP 패킷을 캡처하고,
수신한 패킷으로부터 **Ethernet Header, IP Header, TCP Header 및 HTTP Message(Application Data)**를 분석하여 출력하는 프로그램이다.

패킷의 계층별 정보를 직접 분석함으로써 네트워크 프로토콜의 구조와 동작 원리를 이해하는 것을 목적으로 한다.

---

## 2. 개발 환경

| 항목 | 내용 |
|------|------|
| 운영체제 | Ubuntu (WSL2) |
| 개발 언어 | C |
| 컴파일러 | GCC |
| 라이브러리 | libpcap |

---

## 3. 프로젝트 구성

```
PCAP_Project
│
├── sniff_improved.c     // 패킷 캡처 및 분석 프로그램
├── myheader.h           // Ethernet, IP, TCP 등 프로토콜 구조체 정의
└── README.md
```

---

## 4. 프로그램 기능

### ① Ethernet Header 분석

- Source MAC Address 출력
- Destination MAC Address 출력

### ② IP Header 분석

- Source IP Address 출력
- Destination IP Address 출력

### ③ TCP Header 분석

- Source Port 출력
- Destination Port 출력

### ④ HTTP Message 출력

- HTTP Request 출력
- HTTP Response 출력
- Application Data 출력

---

## 5. 프로그램 동작 과정

```
패킷 수신
      │
      ▼
Ethernet Header 분석
      │
      ▼
IP Header 분석
      │
      ▼
TCP Header 분석
      │
      ▼
HTTP Message 출력
```

---

## 6. 컴파일 방법

다음 명령어를 이용하여 프로그램을 컴파일한다.

```bash
gcc sniff_improved.c -o sniff -lpcap
```

---

## 7. 실행 방법

### ① 프로그램 실행

```bash
sudo ./sniff
```

### ② 다른 WSL 터미널에서 HTTP 요청 발생

```bash
curl http://example.com
```

---

## 8. 실행 결과

프로그램 실행 시 다음과 같은 정보를 확인할 수 있다.

```
=============================

Ethernet Header

Source MAC
Destination MAC

IP Header

Source IP
Destination IP

Protocol : TCP

TCP Header

Source Port
Destination Port

HTTP Message

GET / HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
...
```

---

## 9. 구현 과정

프로그램은 다음 순서로 패킷을 분석한다.

1. libpcap을 이용하여 TCP 패킷 캡처
2. Ethernet Header 분석
3. IP Header 분석
4. TCP Header 분석
5. HTTP Message(Application Data) 출력

---

## 10. 주요 함수

| 함수 | 설명 |
|------|------|
| pcap_open_live() | 네트워크 인터페이스를 열어 실시간 패킷 캡처 |
| pcap_compile() | BPF 필터 컴파일 |
| pcap_setfilter() | TCP 패킷 필터 적용 |
| pcap_loop() | 패킷을 반복적으로 수신 |
| got_packet() | 수신된 패킷을 분석하는 콜백 함수 |
| ntohs() | 네트워크 바이트 순서를 Host 바이트 순서로 변환 |

---

## 11. 참고 자료

- libpcap Programming Manual
- TCP/IP Protocol Suite
- HTTP/1.1 Specification