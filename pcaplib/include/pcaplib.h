#pragma once

class PacketCapture {
public:
    // 생성자와 소멸자
    PacketCapture();
    ~PacketCapture();

    // 패킷 캡처 시작
    bool startCapture(const string& deviceName);

    // 패킷 핸들러 등록
    static void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

    // 패킷 캡처 종료
    void stopCapture();

    vector<string> getDevs();
private:
    // Npcap 라이브러리 초기화
    bool initialize();

    //npcap 동적라이브러리 로드
    bool LoadNpcapDlls();

private:
    pcap_if_t* alldevs; //network devices
    pcap_t* handle;   // 캡처 핸들
    string deviceName; // 캡처할 네트워크 장치 이름
};

