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
	U8 verIhl; //ver: ipv4, ihl: ip����� ���� (4byte����)
	U8 tos;
	U16 length; // ip ��Ŷ�� ����Ʈ ���� ���� (�������, network order����)
	U16 id;
	U16 fragOffset;
	U8 ttl; //time to live
	U8 protocol; //���� ������ ��������
	U16 checksum;
	U8 srcIp[4];
	U8 dstIp[4];
}IpHeader;

//tcp header
typedef struct TcpHeader {
	U16 srcPort;
	U16 dstPort;
	U32 seq;
	U32 ack;
	U8 data;
	U8 flags;
	U16 windowSize;
	U16 checksum;
	U16 urgent;
}TcpHeader;

//udp header
typedef struct UdpHeader {
	U16 srcPort;
	U16 dstPort;
	U16 length;
	U16 checksum;
}UdpHeader;

//udp pseudo header
typedef struct PseudoHeader {
	U32 srcIp;
	U32 dstIp;
	U8 zero;
	U8 protocol;
	U16 length;
}PseudoHeader;

//arp header
typedef struct ArpHeader {

}ArpHeader;
#pragma pack(pop)

