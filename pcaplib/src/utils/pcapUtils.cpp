#include "pch.h"
#include "../Include/utils/pcapUtils.h"

/********************************
	protocol Utils class
*********************************/

/********************************
	Ethernet class
*********************************/

Ethernet::Ethernet(const u_char* packet) {
	eth = reinterpret_cast<const EtherHeader*>(packet);

	// MAC 주소 파싱
	srcMac = macToString(eth->srcMac);
	dstMac = macToString(eth->dstMac);

	// 다음 프로토콜
	nextProtocol = ntohs(eth->type);
}
string Ethernet::printEthernet() const
{
	stringstream ss;
	ss << "Ethernet II:" << endl;
	ss << "\tSource MAC: " << srcMac << endl;
	ss << "\tDestination MAC: " << dstMac << endl;
	ss << "\tType: " << protocolToString(nextProtocol) << " (" << hex << "0x" << nextProtocol << dec << ")" << endl;
	return ss.str();
}

// Source MAC 반환
string Ethernet::getSourceMac() const {
	return srcMac;
}

// Destination MAC 반환
string Ethernet::getDestinationMac() const {
	return dstMac;
}

// 다음 프로토콜 반환
U16 Ethernet::getNextProtocol() const {
	return nextProtocol;
}

// 다음 프로토콜의 문자열 반환
string Ethernet::getNextProtocolString() const {
	return protocolToString(nextProtocol);
}
// MAC 주소를 문자열로 변환
string Ethernet::macToString(const unsigned char* mac) const {
	stringstream ss;
	for (int i = 0; i < 6; ++i) {
		ss << hex << setw(2) << setfill('0') << static_cast<int>(mac[i]);
		if (i != 5)	ss << ":";
	}
	return ss.str();
}

// EtherType에 따라 프로토콜을 문자열로 변환
string Ethernet::protocolToString(uint16_t protocol) const {
	switch (protocol) {
	case 0x0800:
		return "IPv4";
	case 0x0806:
		return "ARP";
	case 0x86DD:
		return "IPv6";
	default:
		return "Unknown";
	}
}
/********************************
	IP class
*********************************/
IP::IP(const u_char* packet)
{
	iph = reinterpret_cast<const IpHeader*>(packet);
	ver = static_cast<int>((iph->verIhl & 0xF0) >> 4);
	if (ver == 4) {
		srcIP = ipToString(iph->srcIp);
		dstIP = ipToString(iph->dstIp);
		protocol = iph->protocol;
		headerLen = static_cast<int>((iph->verIhl & 0x0F) * 4);
		headerChecksum = iph->checksum;
	}
	else if (ver == 6) {
		ip6h = reinterpret_cast<const Ipv6Header*>(packet);
		protocol = ip6h->nextHeader;
		srcIP = ipv6ToString(ip6h->srcAddr);
		dstIP = ipv6ToString(ip6h->dstAddr);
	}
}

string IP::printIP() const
{
	if (ver == 4)
		return printIPv4();
	else
		return printIPv6();
}

string IP::getSourceIP() const {
	return srcIP;
}

string IP::getDestinationIP() const {
	return dstIP;
}

U8 IP::getProtocol() const {
	return protocol;
}

inline string IP::ipToString(const U8* ip) const {
	//ver에 따라 파싱이 달라져야 한다.
	stringstream ss;
	for (int i = 0;i < 4;++i) {
		ss << static_cast<int>(ip[i]);
		if (i != 3) ss << ".";
	}
	return ss.str();
}

inline string IP::protocolToString(U8 proto) const {
	switch (proto) {
	case 1: return "ICMP";
	case 2: return "IGMP";
	case 6: return "TCP";
	case 17: return "UDP";
	default: return "Unknown";
	}
}

string IP::printIPv4() const
{
	stringstream ss;

	// DSCP 및 ECN
	uint8_t dscp = (iph->tos >> 2) & 0x3F;
	uint8_t ecn = iph->tos & 0x03;

	// 플래그 및 프래그먼트 오프셋
	uint8_t flags = (iph->fragOffset >> 13) & 0x07;
	uint16_t fragmentOffset = iph->fragOffset & 0x1FFF;

	ss << "Internet Protocol Version " << static_cast<int>(ver)
		<< ", Src: " << srcIP << ", Dst: " << dstIP << "\n";
	ss << "\tVersion: " << static_cast<int>(ver) << "\n";
	ss << "\tHeader Length: " << static_cast<int>(headerLen) << " bytes\n";
	ss << "\tDifferentiated Services Field: 0x" << std::hex << std::setw(2)
		<< std::setfill('0') << static_cast<int>(iph->tos)
		<< " (DSCP: " << static_cast<int>(dscp) << ", ECN: " << static_cast<int>(ecn) << ")\n";
	ss << "\tTotal Length: " << std::dec << ntohs(iph->length) << "\n";
	ss << "\tIdentification: 0x" << std::hex << std::setw(4) << std::setfill('0')
		<< ntohs(iph->id) << " (" << std::dec << ntohs(iph->id) << ")\n";
	ss << "\tFlags: 0x" << std::hex << static_cast<int>(flags) << "\n";
	ss << "\t\t0... .... = Reserved bit: " << ((flags & 0x04) ? "Set" : "Not set") << "\n";
	ss << "\t\t.0.. .... = Don't fragment: " << ((flags & 0x02) ? "Set" : "Not set") << "\n";
	ss << "\t\t..0. .... = More fragments: " << ((flags & 0x01) ? "Set" : "Not set") << "\n";
	ss << "\tFragment Offset: " << std::dec << fragmentOffset << "\n";
	ss << "\tTime to Live: " << static_cast<int>(iph->ttl) << "\n";
	ss << "\tProtocol: " << static_cast<int>(protocol) << "\n";
	ss << "\tHeader Checksum: 0x" << std::hex << std::setw(4) << std::setfill('0')
		<< ntohs(headerChecksum) << " [validation disabled]\n";
	ss << "\tSource Address: " << srcIP << "\n";
	ss << "\tDestination Address: " << dstIP << "\n";

	return ss.str();
}

string IP::printIPv6() const
{
	std::stringstream ss;
	U32 flowLabel = ip6h->versionTrafficClassFlow & 0xFFFFF;
	U8 trafficClass = (ip6h->versionTrafficClassFlow >> 20) & 0xFF;

	ss << "Internet Protocol Version 6\n";
	ss << "\tVersion: " << ver << "\n";
	ss << "\tTraffic Class: 0x" << std::hex << trafficClass << "\n";
	ss << "\tFlow Label: 0x" << std::hex << flowLabel << "\n";
	ss << "\tPayload Length: " << std::dec << ntohs(ip6h->payloadLength) << "\n";
	ss << "\tNext Header: " << static_cast<int>(ip6h->nextHeader) << "\n";
	ss << "\tHop Limit: " << static_cast<int>(ip6h->hopLimit) << "\n";
	ss << "\tSource Address: " << ipv6ToString(ip6h->srcAddr) << "\n";
	ss << "\tDestination Address: " << ipv6ToString(ip6h->dstAddr) << "\n";
	return ss.str();
}
// IPv6 주소 문자열 변환
string IP::ipv6ToString(const U8* addr) const{
	std::stringstream ss;
	for (int i = 0; i < 16; i += 2) {
		if (i > 0) ss << ":";
		ss << std::hex << std::setw(2) << std::setfill('0') << (addr[i] << 8 | addr[i + 1]);
	}
	return ss.str();
}
/*
	TCP class
*/
TCP::TCP(const u_char* packet)
{
		

	tcph = (TcpHeader*)(packet + sizeof(EtherHeader) + sizeof(IpHeader));
	srcPort = ntohs(tcph->srcPort);
	dstPort = ntohs(tcph->dstPort);
}

void TCP::printTCP() const
{
	cout << "TCP Header:\n";
	cout << "Source Port: " << srcPort << endl;
	cout << "Destination Port: " << dstPort << endl;
}

/*
	UDP class
*/
UDP::UDP(const u_char* packet)
{
	udph = (UdpHeader*)(packet + sizeof(EtherHeader));
	srcPort = ntohs(udph->srcPort);
	dstPort = ntohs(udph->dstPort);
}

void UDP::printUDP() const
{
	cout << "UDP Header:\n";
	cout << "Source Port: " << srcPort << endl;
	cout << "Destination Port: " << dstPort << endl;
}

/*
	ARP class
*/
/*ARP::ARP(const u_char* packet)
{
	arph=(UdpHeader*)(packet + sizeof(EtherHeader));
}

void ARP::printARP() const
{
}
*/
/*
	HttpAnalyzer class
*/
void HttpAnalyzer::analyzeHttp(const u_char* data, size_t length)
{
	string payload(reinterpret_cast<const char*>(data), length);
	size_t methodEnd = payload.find(' ');
	method = payload.substr(0, methodEnd);

	size_t urlStart = methodEnd + 1;
	size_t urlEnd = payload.find(' ', urlStart);
	url = payload.substr(urlStart, urlEnd - urlStart);

	size_t versionStart = urlEnd + 1;
	httpVersion = payload.substr(versionStart, payload.find("\r\n", versionStart) - versionStart);
}

void HttpAnalyzer::printHttp() const
{
	cout << "HTTP Request:\n";
	cout << "Method: " << method << "\nURL: " << url << "\nVersion: " << httpVersion << endl;
}

/*
	TlsAnalyzer class
*/
void TlsAnalyzer::analyzeTLS(const u_char* data, size_t length)
{
	if (length < 5) {
		std::cerr << "TLS data too short to analyze." << std::endl;
		return;
	}

	// Check if this is a TLS handshake
	uint8_t contentType = data[0];
	uint8_t tlsVersionMajor = data[1];
	uint8_t tlsVersionMinor = data[2];

	if (contentType != 0x16 || tlsVersionMajor < 3) {
		std::cerr << "Not a TLS handshake." << std::endl;
		return;
	}

	// Parse SNI and Cipher Suite
	sni = parseSni(data, length);
	cipherSuite = parseCipherSuite(data, length);
}

string TlsAnalyzer::getSNI() const
{
	return this->sni;
}

string TlsAnalyzer::getCiperSite() const
{
	return this->cipherSuite;
}

string TlsAnalyzer::parseSni(const u_char* data, size_t length)
{
	size_t offset = 5; // Skip record header
	if (length <= offset) return "";

	// ServerHello or ClientHello
	size_t handshakeLength = (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
	offset += 4;

	if (length <= offset + handshakeLength) return "";

	// Find the extension section
	size_t extensionsOffset = offset + handshakeLength - 2;
	while (extensionsOffset < length - 4) {
		uint16_t extensionType = (data[extensionsOffset] << 8) | data[extensionsOffset + 1];
		uint16_t extensionLength = (data[extensionsOffset + 2] << 8) | data[extensionsOffset + 3];

		if (extensionType == 0x00) { // SNI extension
			size_t sniOffset = extensionsOffset + 5;
			if (sniOffset + extensionLength > length) return "";

			size_t serverNameLength = (data[sniOffset + 1] << 8) | data[sniOffset + 2];
			if (sniOffset + 3 + serverNameLength > length) return "";

			return std::string(reinterpret_cast<const char*>(&data[sniOffset + 3]), serverNameLength);
		}
		extensionsOffset += 4 + extensionLength;
	}

	return "";
}

string TlsAnalyzer::parseCipherSuite(const u_char* data, size_t length)
{
	size_t offset = 5; // Skip record header
	if (length <= offset) return "";

	// Parse handshake type
	uint8_t handshakeType = data[offset];
	if (handshakeType != 0x01 && handshakeType != 0x02) { // Only ClientHello or ServerHello
		return "";
	}

	offset += 38; // Fixed offset for cipher suite in TLS ClientHello/ServerHello
	if (offset + 2 > length) return "";

	uint16_t cipher = (data[offset] << 8) | data[offset + 1];
	switch (cipher) {
	case 0x1301: return "TLS_AES_128_GCM_SHA256";
	case 0x1302: return "TLS_AES_256_GCM_SHA384";
	case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
	default: return "Unknown Cipher Suite";
	}
}




