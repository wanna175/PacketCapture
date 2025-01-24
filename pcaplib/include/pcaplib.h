#pragma once
#include <pcap.h>
#include <string>
#include <unordered_map> // 추가
#include <memory>
#include <atomic>
#include <functional>
#include <sstream>
class PacketAnalyzerImpl;
using namespace std;

/************************************
    data transfer object PacketData
*************************************/
class PacketData {
public:
    PacketData(int num,string time,string src,string dst,string protocol,string len,string info,string data)
        :number(num),time(time),source(src),destination(dst),protocol(protocol),length(len), info(info), rawData(data) { }
    int getNum() const { return number; }
    string getTime() const { return time; }
    string getSrc() const { return source; }
    string getDst() const { return destination; }
    string getProtocol() const { return protocol; }
    string getLength() const { return length; }
    string getInfo() const { return info; }
    string getData() const { return rawData; }
    void setNum(int num) { this->number = num; }
    void setTime(string time) { this->time = time; }
    void setSrc(string src) { this->source = src; }
    void setDst(string dst) { this->destination = dst; }
    void setProtocol(string protocol) { this->protocol = protocol; }
    void setLength(string len) { this->length = len; }
    void setInfo(string info) { this->info = info; }
    void setData(string data) { this->rawData = data; }
private:
    int number;
    string time;
    string source;
    string destination;
    string protocol;
    string length;
    string info;
    string rawData;  // 원본 패킷 데이터
public:

    PacketData() = default;
};
/************************************
    PacketFilter class
*************************************/
class PacketFilter {
public:
    PacketFilter(const string& filterExpr = "");
    bool setFilter(pcap_t* handle) const;
private:
    string filterExpression;
};
/************************************
    PacketAnalyzer class
*************************************/
class PacketAnalyzer {
public:
    PacketAnalyzer();
    ~PacketAnalyzer();

    PacketData analyzePacket(const u_char* packet, const struct pcap_pkthdr* pkthdr);
    void printPacketData(const u_char* packet, const struct pcap_pkthdr* pkthdr);

private:
    std::unique_ptr<PacketAnalyzerImpl> impl;
};
/************************************
    PacketSaver class
*************************************/
class PacketSaver {
public:
    PacketSaver(pcap_t* handle);
    bool saveToFile(pcap_t* handle, const string& filename);
    void dumpPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void closeDumper();
private:
    pcap_dumper_t* dumper;
};
/************************************
    PacketStatistics class
*************************************/
class PacketStatistics {
public:
    void updateStats(const u_char* packet);
    void printStats() const;
    unordered_map<string, int> getStats() const;

private:
    unordered_map<string, int> stats;
};
/************************************
    PacketCapture class
*************************************/
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

    // 디바이스 목록 반환
    unordered_map<string,string> getDeviceNames() const;

    // 패킷 처리 콜백
    bool processPackets(const std::function<void(const PacketData&)>& callback);
private:
    // 패킷 핸들러 등록
    static void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void timeoutCapture(int captureDuration);
    //npcap 동적라이브러리 로드
    bool LoadNpcapDlls();

private:
    pcap_if_t* alldevs; //network devices
    pcap_t* handle;   // 캡처 핸들
    unique_ptr<PacketFilter> filter;
    unique_ptr<PacketSaver> saver;
    unique_ptr<PacketAnalyzer> analyzer;
    unique_ptr<PacketStatistics> stats;
    unordered_map<string,string> deviceNames;
    atomic<bool> captureActive;
};

