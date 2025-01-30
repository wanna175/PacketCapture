# 패킷 캡쳐 프로그램 (Wireshark 벤치마킹)

이 프로젝트는 Wireshark를 벤치마킹하여 만든 패킷 캡쳐 프로그램입니다. Npcap 라이브러리를 사용하여 `pcaplib`라는 정적 링크 라이브러리를 만들었고, 이를 통해 이더넷, IPv4, IPv6, UDP, TCP, ARP 프로토콜을 캡쳐하고 파싱할 수 있습니다. 또한 `sourceIP`와 `destinationIP`를 키로 사용하여 연관된 패킷을 구분할 수 있도록 했습니다.

<img src="https://raw.githubusercontent.com/wanna175/PacketCapture/main/gif/app.gif" width="800" />


## 주요 기능
- **패킷 캡쳐:** Npcap을 사용하여 실시간 네트워크 트래픽을 캡쳐합니다.
- **프로토콜 파싱:** 이더넷, IPv4, IPv6, UDP, TCP, ARP 프로토콜을 파싱합니다.
- **패킷 필터링:** 향후 특정 조건에 맞는 패킷을 필터링하는 기능을 추가할 예정입니다.
- **패킷 그룹화:** `sourceIP`와 `destinationIP`를 기준으로 패킷을 그룹화하여 더 쉽게 분석할 수 있습니다.
- **프론트엔드:** C++와 wxWidgets를 사용하여 UI를 구성하며, 메인 로직과 UI는 `pcaplib`라는 정적 라이브러리를 통해 분리되었습니다.

## 사용된 주요 기술
- **Npcap:** 패킷 캡쳐를 위한 라이브러리입니다.
- **C++/wxWidgets:** 프론트엔드 UI를 구축하는 데 사용되었습니다.
- **정적 링크:** `pcaplib`는 정적 링크 라이브러리로, 패킷 캡쳐 로직과 UI를 분리하여 모듈화했습니다.

## 미완성 기능 (향후 작업)
- **패킷 덤프:** 캡쳐된 패킷을 파일(PCAP 형식)로 저장하는 기능.
- **패킷 필터링:** 특정 프로토콜이나 조건에 맞는 패킷을 필터링하는 기능을 추가할 예정입니다.
- **패킷 통계 시각화:** 캡쳐된 패킷에 대한 통계를 시각적으로 보여주는 페이지를 추가할 예정입니다.

## 화면 미리보기
![메인 UI](./img/main_ui.png)

*패킷 캡쳐 화면 예시.*

![패킷 상세](./img/packet_details.png)

*캡쳐된 패킷의 상세 보기.*

## 설치 방법
1. 레포지토리 클론:
   ```bash
   git clone https://github.com/yourusername/packet-capture-program.git
