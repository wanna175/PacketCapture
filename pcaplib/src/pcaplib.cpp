#include "pch.h"
#include "pcaplib.h"

/*
    PacketCapture class 
*/
// 생성자
PacketCapture::PacketCapture() : handle(nullptr) {}

// 소멸자
PacketCapture::~PacketCapture() {
    if (handle) {
        stopCapture();  // 캡처가 진행 중이라면 종료
    }
}

// Npcap 라이브러리 초기화
bool PacketCapture::initialize() {
    // Npcap을 사용할 준비가 되었는지 확인
    char errbuf[PCAP_ERRBUF_SIZE];

#ifdef _WIN32
    if (!LoadNpcapDlls())
    {
        cerr << "Error Loading Npcap dlls: " << errbuf << endl;
        return false;
    }
#endif

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << endl;
        return false;
    }

    // Npcap 초기화가 성공적으로 되었으면 true 반환
    return true;
}

// 패킷 캡처 시작
bool PacketCapture::startCapture(const string& deviceName) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // 장치 이름을 저장
    this->deviceName = deviceName;

    // 장치 열기
    handle = pcap_open_live(deviceName.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "Error opening device: " << errbuf << endl;
        return false;
    }

    // 패킷 캡처 시작
    if (pcap_loop(handle, 0, packetHandler, nullptr) < 0) {
        cerr << "Error capturing packets: " << pcap_geterr(handle) << endl;
        return false;
    }

    return true;
}

// 패킷 핸들러
void PacketCapture::packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    cout << "Captured a packet with length: " << pkthdr->len << endl;

    // 여기서 추가적으로 패킷 처리 로직을 구현할 수 있음
}

// 캡처 종료
void PacketCapture::stopCapture() {
    if (handle) {
        pcap_close(handle);
        handle = nullptr;
        cout << "Capture stopped." << endl;
    }
}

vector<string> PacketCapture::getDevs()
{
    int cnt = 0;
    pcap_if_t* d;
    vector<string> devNames;

    for (d = alldevs; d; d = d->next)
    {
        ++cnt;
        devNames.push_back(d->name);
    }
    if (cnt == 0)
    {
        cerr<<"\nNo interfaces found! Make sure Npcap is installed.\n";
    }
    return devNames;
}

bool PacketCapture::LoadNpcapDlls()
{
    wstring npcapDir(MAX_PATH, L'\0');
    UINT len = GetSystemDirectoryW(&npcapDir[0], static_cast<UINT>(npcapDir.size()));

    if (len == 0) {
        cerr << "Error in GetSystemDirectory: " << GetLastError() << endl;
        return false;
    }

    npcapDir.resize(len);
    npcapDir.append(L"\\Npcap");

    if (!SetDllDirectoryW(npcapDir.c_str())) {
        cerr << "Error in SetDllDirectory: " << GetLastError() << endl;
        return false;
    }

    return true;
}
