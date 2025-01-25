#pragma once
#include <sstream>
class Ethernet {
public:
    Ethernet() : eth(nullptr), nextProtocol(0) {}
    Ethernet(const u_char* packet);

    // Ethernet ������ ���
    string printEthernet() const;
	string getSourceMac() const;
	string getDestinationMac() const;
	U16 getNextProtocol() const;
	string getNextProtocolString() const;

private:
    // MAC �ּҸ� ���ڿ��� ��ȯ
	string macToString(const unsigned char* mac) const;
    // EtherType�� ���� ���������� ���ڿ��� ��ȯ
	string protocolToString(uint16_t protocol) const;
private:
    const EtherHeader* eth; // Ethernet ��� ����ü
    string srcMac;
    string dstMac;
    U16 nextProtocol; // ���� �������� (EtherType)

    
};
class IP {
public:
	IP() :iph(nullptr) {}
	IP(const u_char* packet);
	
	//IP������ ���
	string printIP() const;
	string getSourceIP() const;

	string getDestinationIP() const;

	U8 getProtocol() const;
private:
	string ipToString(const U8* ip) const;

	string protocolToString(U8 proto) const;
	string printIPv4() const;
	string printIPv6() const;
	string ipv6ToString(const U8* addr) const;
private:
	const IpHeader* iph;
	const Ipv6Header* ip6h;
	string srcIP;
	string dstIP;
	int ver;
	int headerLen;
	int totalLen;
	U8 protocol;               // Protocol
	U16 headerChecksum;        // Header Checksum
};

class TCP {
public:
	TCP() :tcph(nullptr){}
	TCP(const u_char* packet);

	void printTCP() const;

private:
	TcpHeader* tcph;
	U16 srcPort;
	U16 dstPort;
};

class UDP {
public:
	UDP() :udph(nullptr){}
	UDP(const u_char* packet);

	void printUDP() const;

private:
	UdpHeader* udph;
	U16 srcPort;
	U16 dstPort;
};

/*class ARP {
public:
	ARP() :arph(nullptr){}
	ARP(const u_char* packet);

	void printARP() const;

private:
	ArpHeader* arph;
	U32 srcIp;
	U32 dstIp;
};*/

class HttpAnalyzer {
public:
	void analyzeHttp(const u_char* data, size_t length);
	void printHttp() const;

private:
	string method;
	string url;
	string httpVersion;
};

class TlsAnalyzer {
public:
	void analyzeTLS(const u_char* data, size_t length);
	string getSNI() const;
	string getCiperSite() const;

private:
	string parseSni(const u_char* data, size_t length);
	string parseCipherSuite(const u_char* data, size_t length);

private:
	string sni;
	string cipherSuite;
};

