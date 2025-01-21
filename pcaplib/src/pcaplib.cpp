#include "pch.h"
#include "pcaplib.h"

/*
    PacketCapture class 
*/
// ������
PacketCapture::PacketCapture() : handle(nullptr) {}

// �Ҹ���
PacketCapture::~PacketCapture() {
    if (handle) {
        stopCapture();  // ĸó�� ���� ���̶�� ����
    }
}

// Npcap ���̺귯�� �ʱ�ȭ
bool PacketCapture::initialize() {
    // Npcap�� ����� �غ� �Ǿ����� Ȯ��
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

    // Npcap �ʱ�ȭ�� ���������� �Ǿ����� true ��ȯ
    return true;
}

// ��Ŷ ĸó ����
bool PacketCapture::startCapture(const string& deviceName) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // ��ġ �̸��� ����
    this->deviceName = deviceName;

    // ��ġ ����
    handle = pcap_open_live(deviceName.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "Error opening device: " << errbuf << endl;
        return false;
    }

    // ��Ŷ ĸó ����
    if (pcap_loop(handle, 0, packetHandler, nullptr) < 0) {
        cerr << "Error capturing packets: " << pcap_geterr(handle) << endl;
        return false;
    }

    return true;
}

// ��Ŷ �ڵ鷯
void PacketCapture::packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    cout << "Captured a packet with length: " << pkthdr->len << endl;

    // ���⼭ �߰������� ��Ŷ ó�� ������ ������ �� ����
}

// ĸó ����
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
