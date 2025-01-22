#pragma once
#include <utils/pcapUtils.h>

class PacketCapture {
public:
    // 생성자와 소멸자
    PacketCapture();
    ~PacketCapture();

    bool initialize();
    // 패킷 캡처 시작
    bool startCapture(const string& deviceName,const string& filterExpr = "",int captureDuration = 0);

    // 패킷 캡처 종료
    void stopCapture();

    //network device 출력
    bool listDevices();

    //pcap file 읽기
    void replayPacket(const string& fileName = "") const;
private:
    // 패킷 핸들러 등록
    static void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void timeoutCapture(int captureDuration);
    //npcap 동적라이브러리 로드
    bool LoadNpcapDlls();

private:
    pcap_if_t* alldevs; //network devices
    pcap_t* handle;   // 캡처 핸들
    string deviceName; // 캡처할 네트워크 장치 이름
    unique_ptr<PacketFilter> filter;
    unique_ptr<PacketSaver> saver;
    unique_ptr<PacketAnalyzer> analyzer;
    unique_ptr<PacketStatistics> stats;
    atomic<bool> captureActive;
};

class PacketFilter {
public:
    PacketFilter(const string& filterExpr = "");
    bool setFilter(pcap_t* handle) const;
private:
    string filterExpression;
};

class PacketAnalyzer {
public:
    PacketAnalyzer();

    void analyzePacket(const u_char* packet, const struct pcap_pkthdr* pkthdr);
    void printPacketData(const u_char* packet, const struct pcap_pkthdr* pkthdr);

private:
    Ethernet ethernet;
    IP ip;
    TCP tcp;
    UDP udp;
    ARP arp;
    bool isEthernet;
    bool isIP;
    bool isTCP;
    bool isUDP;
    bool isARP;
};

class PacketSaver {
public:
    PacketSaver(pcap_t* handle);
    bool saveToFile(pcap_t* handle, const string& filename);
    void dumpPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void closeDumper();
private:
    pcap_dumper_t* dumper;
};

class PacketStatistics {
public:
    void updateStats(const u_char* packet);
    void printStats() const;
    unordered_map<string, int> getStats() const;

private:
    unordered_map<string, int> stats;
};