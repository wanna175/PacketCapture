#pragma once
#include <pcap.h>
#include <string>
#include <unordered_map> // �߰�
#include <memory>
#include <atomic>
#include <functional>
#include <sstream>
class PacketAnalyzerImpl;
using namespace std;


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
    ~PacketAnalyzer();

    void analyzePacket(const u_char* packet, const struct pcap_pkthdr* pkthdr);
    void printPacketData(const u_char* packet, const struct pcap_pkthdr* pkthdr);

private:
    std::unique_ptr<PacketAnalyzerImpl> impl;
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

class PacketCapture {
public:
    // �����ڿ� �Ҹ���
    PacketCapture();
    ~PacketCapture();

    bool initialize();
    // ��Ŷ ĸó ����
    bool startCapture(const string& deviceName,const string& filterExpr = "",int captureDuration = 0);

    // ��Ŷ ĸó ����
    void stopCapture();

    //network device ���
    bool listDevices();
    //pcap file �б�
    void replayPacket(const string& fileName = "") const;

    // ����̽� ��� ��ȯ
    std::vector<std::string> getDeviceNames() const;

    // ��Ŷ ó�� �ݹ�
    bool processPackets(const std::function<void(const std::string&)>& callback);
private:
    // ��Ŷ �ڵ鷯 ���
    static void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void timeoutCapture(int captureDuration);
    //npcap �������̺귯�� �ε�
    bool LoadNpcapDlls();

private:
    pcap_if_t* alldevs; //network devices
    pcap_t* handle;   // ĸó �ڵ�
    unique_ptr<PacketFilter> filter;
    unique_ptr<PacketSaver> saver;
    unique_ptr<PacketAnalyzer> analyzer;
    unique_ptr<PacketStatistics> stats;
    vector<std::string> deviceNames;
    atomic<bool> captureActive;
};

