#include "pch.h"
#include "pcaplib.h"
#include "../include/utils/pcapUtils.h"
/*
    PacketCapture class 
*/
// ������
PacketCapture::PacketCapture() 
    : handle(nullptr), alldevs(nullptr), filter(make_unique<PacketFilter>()),
      saver(nullptr), analyzer(make_unique<PacketAnalyzer>()), captureActive(false) {}

// �Ҹ���
PacketCapture::~PacketCapture() {
    if (handle) stopCapture();  // ĸó�� ���� ���̶�� ����
    if (alldevs) pcap_freealldevs(alldevs);
    if (saver) saver->closeDumper();
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
    return true;
}

// ��Ŷ ĸó ����
bool PacketCapture::startCapture(const string& deviceName,const string& filterExpr,int captureDuration) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // ��ġ ����
    handle = pcap_open_live(deviceName.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "Error opening device: " << errbuf << endl;
        return false;
    }

    filter->setFilter(handle);
    //filter�� expr�� �������� �ʾƵ� �Ǵ���??
    saver = make_unique<PacketSaver>(handle);
    stats = make_unique<PacketStatistics>();
    
    //timeout ������ ���� race condition �߻� => ������ ó���� �ʿ�
    //thread timeoutThread(&PacketCapture::timeoutCapture, this, captureDuration);
    //��Ŷ ĸ�� ����
    captureActive.store(true);
    
    //timeoutThread.join();
    return true;
}

// ��Ŷ �ڵ鷯
void PacketCapture::packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // userData���� PacketCapture�� �ݹ� �Լ� ����
    auto* data = reinterpret_cast<std::pair<PacketCapture*, std::function<void(const std::string&)>>*>(userData);
    PacketCapture* capture = data->first;
    auto& callback = data->second;
    /*capture->analyzer->analyzePacket(packet, pkthdr);
    capture->analyzer->printPacketData(packet, pkthdr);
    capture->saver->dumpPacket(pkthdr, packet);
    capture->stats->updateStats(packet);*/
    
    std::ostringstream oss;
    oss << "Packet length: " << pkthdr->len << " bytes";
    (callback)(oss.str());
}

void PacketCapture::timeoutCapture(int captureDuration)
{
    if (captureDuration > 0) {
        this_thread::sleep_for(chrono::seconds(captureDuration));
        stopCapture();
    }
}

// ĸó ����
void PacketCapture::stopCapture() {
    if (handle) {
        captureActive.store(false);
        pcap_close(handle);
        handle = nullptr;
        cout << "Capture stopped." << endl;
        stats->printStats();
    }
}

//��� network ����̽� deviceNames�� ����
bool PacketCapture::listDevices()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << endl;
        return false;
    }
    deviceNames.clear();

    for (pcap_if_t* dev = alldevs; dev; dev = dev->next)
        if (dev->name)  deviceNames[dev->name] = (dev->description?dev->description:"�ĺ����� ���� ��Ʈ��ũ ���");

    return !deviceNames.empty();
}


void PacketCapture::replayPacket(const string& fileName) const
{
    if (fileName.empty()) {
        cerr << "Not select file!" << endl;
        return;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* replayHandle = pcap_open_offline(fileName.c_str(), errbuf);
    if (!replayHandle) throw std::runtime_error("Failed to open file for replaying.");

    struct pcap_pkthdr* header;
    const u_char* data;
    while (pcap_next_ex(replayHandle, &header, &data) >= 0) {
        // Custom replay logic
        std::cout << "Replaying packet of length: " << header->len << std::endl;
    }
    pcap_close(replayHandle);
}

unordered_map<string,string> PacketCapture::getDeviceNames() const
{
    return deviceNames;
}

bool PacketCapture::processPackets(const std::function<void(const std::string&)>& callback)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    std::pair<PacketCapture*, std::function<void(const std::string&)>> pair = { this, callback };
    if (pcap_loop(handle, 0, packetHandler, (u_char*)(&pair)) < 0 && captureActive.load()) {
        cerr << "Error capturing packets: " << pcap_geterr(handle) << endl;
        return false;
    }
    return true;
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

/*
    PacketFilter class
*/
//������
PacketFilter::PacketFilter(const string& filter) : filterExpression(filter){}

bool PacketFilter::setFilter(pcap_t* handle) const
{
    if (filterExpression.empty()) {
        return true;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filterExpression.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        cerr << "Error compiling filter: " << pcap_geterr(handle) << endl;
        return false;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        cerr << "Error setting filter: " << pcap_geterr(handle) << endl;
        return false;
    }
    return true;
}

/*
    PacketAnalyzer class
*/
// ���� ���� Ŭ���� ����
class PacketAnalyzerImpl {
public:
    std::unique_ptr<Ethernet> ethernet;
    std::unique_ptr<IP> ip;
    std::unique_ptr<TCP> tcp;
    std::unique_ptr<UDP> udp;
    bool isEthernet;
    bool isIP;
    bool isTCP;
    bool isUDP;
    bool isARP;

    PacketAnalyzerImpl()
        : ethernet(std::make_unique<Ethernet>()),
        ip(std::make_unique<IP>()),
        tcp(std::make_unique<TCP>()),
        udp(std::make_unique<UDP>()),
        isEthernet(false), isIP(false), isTCP(false), isUDP(false), isARP(false) {
    }
    ~PacketAnalyzerImpl() = default;
};
PacketAnalyzer::PacketAnalyzer()
    : impl(std::make_unique<PacketAnalyzerImpl>()) {
}
PacketAnalyzer::~PacketAnalyzer() = default;

void PacketAnalyzer::analyzePacket(const u_char* packet, const pcap_pkthdr* pkthdr)
{
    impl->ethernet = make_unique<Ethernet>(packet);
    impl->isEthernet = true;

    EtherHeader* eth = (EtherHeader*)packet;
    if (ntohs(eth->type) == 0x0800) {
        impl->ip = make_unique<IP>(packet);
        impl->isIP = true;

        IpHeader* iph = (IpHeader*)(packet + sizeof(EtherHeader));
        if (iph->protocol == 6) {
            impl->tcp = make_unique<TCP>(packet);
            impl->isTCP = true;
        }
        else if (iph->protocol == 1) {}
        else if (iph->protocol == 2) {}
        else if (iph->protocol == 17) {
            impl->udp = make_unique<UDP>(packet);
            impl->isUDP = true;
        }
    }
}

void PacketAnalyzer::printPacketData(const u_char* packet, const pcap_pkthdr* pkthdr)
{
    if (impl->isEthernet) impl->ethernet->printEthernet();
    if (impl->isIP) impl->ip->printIP();
    if (impl->isTCP) impl->tcp->printTCP();
    if (impl->isUDP) impl->udp->printUDP();
}

/*
    PacketSaver class
*/
//������ : dumpfile �ʱ�ȭ
PacketSaver::PacketSaver(pcap_t* handle) : dumper(nullptr)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    dumper = pcap_dump_open(handle, "captured_packet.pcap");
    if (dumper == nullptr)
        cerr << "Error opening dump file: " << pcap_geterr(handle) << endl;
}

bool PacketSaver::saveToFile(pcap_t* handle, const string& filename)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    dumper = pcap_dump_open(handle, filename.c_str());
    if (dumper == nullptr) {
        cerr << "Error opening dump file: " << pcap_geterr(handle) << endl;
        return false;
    }
    return true;
}

void PacketSaver::dumpPacket(const pcap_pkthdr* pkthdr, const u_char* packet)
{
    if (dumper) pcap_dump((u_char*)dumper, pkthdr, packet);
}
void PacketSaver::closeDumper() {
    if (dumper) pcap_dump_close(dumper);
}

/*
    PacketStatistics class
*/
void PacketStatistics::updateStats(const u_char* packet)
{
    ++stats["Ether"];

    EtherHeader* eth = (EtherHeader*)packet;
    if (ntohs(eth->type) == 0x0800) {
        ++stats["IP"];

        IpHeader* iph = (IpHeader*)(packet + sizeof(EtherHeader));
        if (iph->protocol == 6) ++stats["TCP"];
        else if (iph->protocol == 1) ++stats["ICMP"];
        else if (iph->protocol == 2) ++stats["IGMP"];
        else if (iph->protocol == 17) ++stats["UDP"];
        else ++stats["Other"];
    }
}

void PacketStatistics::printStats() const
{
    for (const auto& data : stats)
        cout << data.first << ": " << data.second << endl;
}

unordered_map<string, int> PacketStatistics::getStats() const
{
    return stats;
}
