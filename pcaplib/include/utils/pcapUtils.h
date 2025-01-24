#pragma once

class Ethernet {
public:
    Ethernet() : eth(nullptr), nextProtocol(0) {}

    // ������: ��Ŷ �����͸� ������� �ʱ�ȭ
    Ethernet(const u_char* packet);

    // Ethernet ������ ���
    void printEthernet() const;

    // Source MAC ��ȯ
	string getSourceMac() const;

    // Destination MAC ��ȯ
	string getDestinationMac() const;

    // ���� �������� ��ȯ
	U16 getNextProtocol() const;

    // ���� ���������� ���ڿ� ��ȯ
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
    uint16_t nextProtocol; // ���� �������� (EtherType)

    
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

