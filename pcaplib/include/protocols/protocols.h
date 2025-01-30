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
	U8 verIhl;             // ����(4��Ʈ) + ��� ����(4��Ʈ)
	U8 tos;                // DSCP(6��Ʈ) + ECN(2��Ʈ)
	U16 length;            // ip ��Ŷ�� ����Ʈ ���� ���� (�������, network order����)
	U16 id;                // �ĺ���
	U16 fragOffset;        // �÷���(3��Ʈ) + �����׸�Ʈ ������(13��Ʈ)
	U8 ttl;                //time to live
	U8 protocol;           //���� ������ ��������
	U16 checksum;          // ��� üũ��
	U8 srcIp[4];           // �ҽ� IP �ּ�
	U8 dstIp[4];           // ������ IP �ּ�
}IpHeader;

//Ipv6 header
typedef struct Ipv6Header {
	U32 versionTrafficClassFlow; // ����(4) + Ʈ���� Ŭ����(8) + �÷ο� ���̺�(20)
	U16 payloadLength;           // ���̷ε� ����
	U8 nextHeader;               // ���� ���
	U8 hopLimit;                 // ȩ ����
	U8 srcAddr[16];              // �ҽ� IPv6 �ּ�
	U8 dstAddr[16];              // ������ IPv6 �ּ�
}Ipv6Header;

//tcp header
typedef struct TcpHeader {
	U16 srcPort;                 // �ҽ� ��Ʈ
	U16 dstPort;                 // ������ ��Ʈ
	U32 seq;                     // ������ ��ȣ
	U32 ack;                     // Ȯ�� ���� ��ȣ
	U8 data;                     // ������ ������(���� 4��Ʈ)
	U8 flags;                    // �÷���
	U16 windowSize;              // ������ ũ��
	U16 checksum;                // üũ��
	U16 urgent;                  // ��� ������
}TcpHeader;

//udp header
typedef struct UdpHeader {
	U16 srcPort;                 // �ҽ� ��Ʈ
	U16 dstPort;                 // ������ ��Ʈ
	U16 length;                  // ����
	U16 checksum;                // üũ��
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
	U8 type;       // Ÿ��
	U8 code;       // �ڵ�
	U16 checksum;  // üũ��
	U16 id;        // �ĺ���
	U16 seq;       // ������ ��ȣ
}IcmpHeader;

// IGMP header
typedef struct IgmpHeader {
	U8 type;       // Ÿ��
	U8 maxRespTime; // �ִ� ���� �ð�
	U16 checksum;  // üũ��
	U32 groupAddr; // �׷� �ּ�
}IgmpHeader;

// ARP header
typedef struct ArpHeader {
	U16 hardwareType;  // �ϵ���� Ÿ��
	U16 protocolType;  // �������� Ÿ��
	U8 hardwareSize;   // �ϵ���� �ּ� ũ��
	U8 protocolSize;   // �������� �ּ� ũ��
	U16 opcode;        // ���۷��̼� �ڵ�
	U8 srcMac[6];      // �ҽ� MAC �ּ�
	U8 srcIp[4];       // �ҽ� IP �ּ�
	U8 dstMac[6];      // ������ MAC �ּ�
	U8 dstIp[4];       // ������ IP �ּ�
}ArpHeader;
#pragma pack(pop)

