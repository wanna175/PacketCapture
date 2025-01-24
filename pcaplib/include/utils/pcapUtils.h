#pragma once

class Ethernet {
public:
    Ethernet() : eth(nullptr), nextProtocol(0) {}

    // 생성자: 패킷 데이터를 기반으로 초기화
    Ethernet(const u_char* packet);

    // Ethernet 정보를 출력
    void printEthernet() const;

    // Source MAC 반환
	string getSourceMac() const;

    // Destination MAC 반환
	string getDestinationMac() const;

    // 다음 프로토콜 반환
	U16 getNextProtocol() const;

    // 다음 프로토콜의 문자열 반환
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
    uint16_t nextProtocol; // 다음 프로토콜 (EtherType)

    
};
class IP {
public:
	IP() :iph(nullptr) {}
	IP(const u_char* packet);
	
	void printIP() const;

private:
	IpHeader* iph;
	string srcIp;
	string dstIp;
	U8 protocol;
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

