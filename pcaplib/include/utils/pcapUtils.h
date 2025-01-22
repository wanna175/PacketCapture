#pragma once

class Ethernet {
public:
	Ethernet() {}
	Ethernet(const u_char* packet);

	void printEthernet() const;

private:
	string etherToString(const u_char* mac) const;

private:
	EtherHeader* eth;
	U8 srcMac[6];
	U8 dstMac[6];
};
class IP {
public:
	IP() {}
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
	TCP() {}
	TCP(const u_char* packet);

	void printTCP() const;

private:
	TcpHeader* tcph;
	U16 srcPort;
	U16 dstPort;
};

class UDP {
public:
	UDP() {}
	UDP(const u_char* packet);

	void printUDP() const;

private:
	UdpHeader* udph;
	U16 srcPort;
	U16 dstPort;
};

class ARP {
public:
	ARP() {}
	ARP(const u_char* packet);

	void printARP() const;

private:
	ArpHeader* arph;
	U32 srcIp;
	U32 dstIp;
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

