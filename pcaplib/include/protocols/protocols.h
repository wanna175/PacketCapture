#pragma once

#pragma pack(push,1)
//Ethernet header
typedef struct EtherHeader {
	U8 dstMac[6];
	U8 srcMac[6];
	U16 type;
}EtherHeader;

//Ipv4 header
typedef struct IpHeader {
	U8 verIhl;             // 버전(4비트) + 헤더 길이(4비트)
	U8 tos;                // DSCP(6비트) + ECN(2비트)
	U16 length;            // ip 패킷의 바이트 단위 길이 (헤더포함, network order주의)
	U16 id;                // 식별자
	U16 fragOffset;        // 플래그(3비트) + 프래그먼트 오프셋(13비트)
	U8 ttl;                //time to live
	U8 protocol;           //상위 계층의 프로토콜
	U16 checksum;          // 헤더 체크섬
	U8 srcIp[4];           // 소스 IP 주소
	U8 dstIp[4];           // 목적지 IP 주소
}IpHeader;

//Ipv6 header
typedef struct Ipv6Header {
	U32 versionTrafficClassFlow; // 버전(4) + 트래픽 클래스(8) + 플로우 레이블(20)
	U16 payloadLength;           // 페이로드 길이
	U8 nextHeader;               // 다음 헤더
	U8 hopLimit;                 // 홉 제한
	U8 srcAddr[16];              // 소스 IPv6 주소
	U8 dstAddr[16];              // 목적지 IPv6 주소
}Ipv6Header;

//tcp header
typedef struct TcpHeader {
	U16 srcPort;                 // 소스 포트
	U16 dstPort;                 // 목적지 포트
	U32 seq;                     // 시퀀스 번호
	U32 ack;                     // 확인 응답 번호
	U8 data;                     // 데이터 오프셋(상위 4비트)
	U8 flags;                    // 플래그
	U16 windowSize;              // 윈도우 크기
	U16 checksum;                // 체크섬
	U16 urgent;                  // 긴급 포인터
}TcpHeader;

//udp header
typedef struct UdpHeader {
	U16 srcPort;                 // 소스 포트
	U16 dstPort;                 // 목적지 포트
	U16 length;                  // 길이
	U16 checksum;                // 체크섬
}UdpHeader;

//udp pseudo header
typedef struct PseudoHeader {
	U32 srcIp;
	U32 dstIp;
	U8 zero;
	U8 protocol;
	U16 length;
}PseudoHeader;

//icmp header
typedef struct IcmpHeader {
	U8 type;       // 타입
	U8 code;       // 코드
	U16 checksum;  // 체크섬
	U16 id;        // 식별자
	U16 seq;       // 시퀀스 번호
}IcmpHeader;

// IGMP header
typedef struct IgmpHeader {
	U8 type;       // 타입
	U8 maxRespTime; // 최대 응답 시간
	U16 checksum;  // 체크섬
	U32 groupAddr; // 그룹 주소
}IgmpHeader;

// ARP header
typedef struct ArpHeader {
	U16 hardwareType;  // 하드웨어 타입
	U16 protocolType;  // 프로토콜 타입
	U8 hardwareSize;   // 하드웨어 주소 크기
	U8 protocolSize;   // 프로토콜 주소 크기
	U16 opcode;        // 오퍼레이션 코드
	U8 srcMac[6];      // 소스 MAC 주소
	U8 srcIp[4];       // 소스 IP 주소
	U8 dstMac[6];      // 목적지 MAC 주소
	U8 dstIp[4];       // 목적지 IP 주소
}ArpHeader;
#pragma pack(pop)

