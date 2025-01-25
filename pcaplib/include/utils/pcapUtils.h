#pragma once
#include <sstream>
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
class IP {
public:
	IP() :iph(nullptr) {}
	IP(const u_char* packet);
	
	//IP정보를 출력
	string printIP() const;
	string getSourceIP() const {
		return srcIP;
	}

	string getDestinationIP() const {
		return dstIP;
	}

	uint8_t getProtocol() const {
		return protocol;
	}
private:
	string ipToString(U32 ip) const {
		stringstream ss;
		ss << ((ip >> 24) & 0xFF) << "."
			<< ((ip >> 16) & 0xFF) << "."
			<< ((ip >> 8) & 0xFF) << "."
			<< (ip & 0xFF);
		return ss.str();
	}

	string protocolToString(U8 proto) const {
		switch (proto) {
		case 1: return "ICMP";
		case 2: return "IGMP";
		case 6: return "TCP";
		case 17: return "UDP";
		default: return "Unknown";
		}
	}
private:
	IpHeader* iph;
	string srcIP;
	string dstIP;
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

