#include "pch.h"
#include "pcaplib.h"
/*
    PacketCapture class 
*/
// ������
PacketCapture::PacketCapture() 
    : handle(nullptr), alldevs(nullptr), filter(make_unique<PacketFilter>()),
      saver(nullptr), analyzer(make_unique<PacketAnalyzer>()) {}

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

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << endl;
        return false;
    }

    // Npcap �ʱ�ȭ�� ���������� �Ǿ����� true ��ȯ
    return true;
}

// ��Ŷ ĸó ����
bool PacketCapture::startCapture(const string& deviceName,const string& filterExpr = "",int captureDuration = 0) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // ��ġ �̸��� ����
    this->deviceName = deviceName;

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

    //timeout ������ ����
    thread timeoutThread(&timeoutCapture, this, captureDuration);
    //��Ŷ ĸ�� ����
    if (pcap_loop(handle, 0, packetHandler, (u_char*)this) < 0) {
        cerr << "Error capturing packets: " << pcap_geterr(handle) << endl;
        return false;
    }
    
    timeoutThread.join();
    return true;
}

// ��Ŷ �ڵ鷯
void PacketCapture::packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketCapture* capture = reinterpret_cast<PacketCapture*>(userData);
    capture->analyzer->analyzePacket(packet, pkthdr);
    capture->analyzer->printPacketData(packet, pkthdr);
    capture->saver->dumpPacket(pkthdr, packet);
    capture->stats->updateStats(packet);
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
        pcap_close(handle);
        handle = nullptr;
        captureActive.store(false);
        cout << "Capture stopped." << endl;
        stats->printStats();
    }
}

//��� network ����̽� ���
bool PacketCapture::listDevices()
{
    if (alldevs == nullptr) {
        cerr << "No devices found!" << endl;
        return false;
    }

    int cnt = 1;
    for(pcap_if_t* dev = alldevs;dev!=nullptr;dev->next)
        cout<<cnt++<<": "<<dev->name<<" - " << (dev->description ? dev->description : "No description") << std::endl;
    return true;
}

void PacketCapture::replayPacket(const string& fileName="") const
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
PacketAnalyzer::PacketAnalyzer()
{
    this->isARP = false;
    this->isEthernet = false;
    this->isIP = false;
    this->isTCP = false;
    this->isUDP = false;
}


void PacketAnalyzer::analyzePacket(const u_char* packet, const pcap_pkthdr* pkthdr)
{
    ethernet = Ethernet(packet);
    isEthernet = true;

    EtherHeader* eth = (EtherHeader*)packet;
    if (ntohs(eth->type) == 0x0800) {
        ip = IP(packet);
        isIP = true;

        IpHeader* iph = (IpHeader*)(packet + sizeof(EtherHeader));
        if (iph->protocol == 6) {
            tcp = TCP(packet);
            isTCP = true;
        }
        else if (iph->protocol == 1) {}
        else if (iph->protocol == 2) {}
        else if (iph->protocol == 17) {
            udp = UDP(packet);
            isUDP = true;
        }
    }
}

void PacketAnalyzer::printPacketData(const u_char* packet, const pcap_pkthdr* pkthdr)
{
    if (isEthernet) ethernet.printEthernet();
    if (isIP) ip.printIP();
    if (isTCP) tcp.printTCP();
    if (isUDP) udp.printUDP();
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
        std::cout << data.first << ": " << data.second << std::endl;
}

unordered_map<string, int> PacketStatistics::getStats() const
{
    return stats;
}
