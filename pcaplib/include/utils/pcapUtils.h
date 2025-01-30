#pragma once
#include <sstream>
#include <bitset>

/********************************
	Ethernet class
*********************************/
class Ethernet {
public:
    Ethernet() : eth(nullptr), nextProtocol(0) {}
    Ethernet(const u_char* packet);

    // Ethernet 정보를 출력
    string printEthernet() const;
	string getSourceMac() const;
	string getDestinationMac() const;
	U16 getNextProtocol() const;
	string getNextProtocolString() const;

private:
    // MAC 주소를 문자열로 변환
	string macToString(const unsigned char* mac) const;
    // EtherType에 따라 프로토콜을 문자열로 변환
	string protocolToString(uint16_t protocol) const;
private:
    const EtherHeader* eth; // Ethernet 헤더 구조체
    string srcMac;
    string dstMac;
    U16 nextProtocol; // 다음 프로토콜 (EtherType)

    
};

/********************************
	IPv4 class
*********************************/
class IP {
public:
	IP() :iph(nullptr) {}
	IP(const u_char* packet);
	
	//IP정보를 출력
	string printIP() const;
	string getSourceIP() const;

	string getDestinationIP() const;

	U8 getProtocol() const;
	string getNextProtocolString() const;
private:
	string ipToString(const U8* ip) const;
	string protocolToString(U8 proto) const;
	string printIPv4() const;
private:
	const IpHeader* iph;
	string srcIP;
	string dstIP;
	int ver;
	int headerLen;
	int totalLen;
	U8 protocol;               // Protocol
	U16 headerChecksum;        // Header Checksum
};

/********************************
	IPv6 class
*********************************/
class IPv6 {
public:
	IPv6() :ip6h(nullptr) {}
	IPv6(const u_char* packet);

	//IP정보를 출력
	string printIP() const;
	string getSourceIP() const;

	string getDestinationIP() const;
	string getNextProtocolString() const;
	U8 getProtocol() const;
	const U8* getHeaderPointer(U8 nextHeader) const;
	int getExtensionHeaderLength(const U8* header) const;
	bool isExtensionHeader(U8 headerType) const;
	U8 getNextHeader() const;
	U8 getNextHeader(U8* header) const;
private:
	string protocolToString(U8 proto) const;
	string printIPv6() const;
	string ipv6ToString(const U8* addr) const;
private:
	const Ipv6Header* ip6h;
	string srcIP;
	string dstIP;
	U8 protocol;               // Protocol
};

/********************************
	TCP class
*********************************/
class TCP {
public:
	TCP() :tcph(nullptr){}
	TCP(const u_char* packet);

	string formatTcpInfo() const;

	string printTCP() const;

private:
	string parseTcpFlags(uint8_t flags) const;
	string parseTcpHeader() const;
	string getTcpFlags() const;
private:
	const TcpHeader* tcph;
	U16 srcPort;
	U16 dstPort;
};

/********************************
	UDP class
*********************************/
class UDP {
public:
	UDP() :udph(nullptr){}
	UDP(const u_char* packet);

	string formatUdpInfo() const;

	string printUDP() const;

private:
	const UdpHeader* udph;
	U16 srcPort;
	U16 dstPort;
};

/********************************
	ARP class
*********************************/
class ARP {
public:
    // ARP Operation Codes
    enum Opcode {
        REQUEST = 1,
        REPLY = 2
    };

    ARP():arph(nullptr){}
	ARP(const u_char* packet);

	string formatArpInfo() const ;

	string printARP() const;

private:
    // MAC 주소를 문자열로 변환
    string macToString(const U8* mac) const;

    // IP 주소를 문자열로 변환
    string ipToString(const U8* ip) const;

private:
	const ArpHeader* arph;
	Opcode op;
};

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

