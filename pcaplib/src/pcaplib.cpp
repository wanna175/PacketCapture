#include "pch.h"
#include "pcaplib.h"
#include "../include/utils/pcapUtils.h"
/************************************
    PacketCapture class
*************************************/
// 생성자
PacketCapture::PacketCapture() 
    : handle(nullptr), alldevs(nullptr), filter(make_unique<PacketFilter>()),
      saver(nullptr), analyzer(make_unique<PacketAnalyzer>()), captureActive(false) {}

// 소멸자
PacketCapture::~PacketCapture() {
    if (handle) stopCapture();  // 캡처가 진행 중이라면 종료
    if (alldevs) pcap_freealldevs(alldevs);
    if (saver) saver->closeDumper();
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
    return true;
}

// 패킷 캡처 시작
bool PacketCapture::startCapture(const string& deviceName,const string& filterExpr,int captureDuration) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // 장치 열기
    handle = pcap_open_live(deviceName.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "Error opening device: " << errbuf << endl;
        return false;
    }

    filter->setFilter(handle);
    //filter에 expr를 설정하지 않아도 되는지??
    saver = make_unique<PacketSaver>(handle);
    stats = make_unique<PacketStatistics>();
    
    //timeout 쓰레드 시작 race condition 발생 => 적절한 처리가 필요
    //thread timeoutThread(&PacketCapture::timeoutCapture, this, captureDuration);
    //패킷 캡쳐 시작
    captureActive.store(true);
    
    //timeoutThread.join();
    return true;
}

// 패킷 핸들러
void PacketCapture::packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // userData에서 PacketCapture와 콜백 함수 추출
    auto* data = reinterpret_cast<std::pair<PacketCapture*,std::function<void(const PacketData&)>>*>(userData);
    PacketCapture* capture = data->first;
    auto& callback = data->second;
    PacketData pd = capture->analyzer->analyzePacket(packet, pkthdr);
    
    //capture->saver->dumpPacket(pkthdr, packet);
    //capture->stats->updateStats(packet);
    
    callback(pd);
    
}

void PacketCapture::timeoutCapture(int captureDuration)
{
    if (captureDuration > 0) {
        this_thread::sleep_for(chrono::seconds(captureDuration));
        stopCapture();
    }
}

// 캡처 종료
void PacketCapture::stopCapture() {
    if (handle) {
        captureActive.store(false);
        pcap_breakloop(handle);
        pcap_close(handle);
        handle = nullptr;
    }
}

//모든 network 디바이스 deviceNames에 저장
bool PacketCapture::listDevices()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << endl;
        return false;
    }
    deviceNames.clear();

    for (pcap_if_t* dev = alldevs; dev; dev = dev->next)
        if (dev->name)  deviceNames[dev->name] = (dev->description?dev->description:"식별되지 않은 네트워크 장비");

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

bool PacketCapture::processPackets(const std::function<void(const PacketData&)>& callback)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    this->analyzer->init();
    std::pair<PacketCapture*,std::function<void(const PacketData&)>> pair = { this, callback };
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





/************************************
    PacketFilter class
*************************************/
//생성자
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





/************************************
    PacketAnalyzer class
*************************************/
// 내부 구현 클래스 정의
class PacketAnalyzerImpl {
public:
    unique_ptr<Ethernet> ethernet;
    unique_ptr<IP> ip;
    unique_ptr<IPv6> ipv6;
    unique_ptr<ARP> arp;
    unique_ptr<TCP> tcp;
    unique_ptr<UDP> udp;

    PacketAnalyzerImpl()
        : ethernet(std::make_unique<Ethernet>()),
        ip(make_unique<IP>()),
        ipv6(make_unique<IPv6>()),
        arp(make_unique<ARP>()),
        tcp(make_unique<TCP>()),
        udp(make_unique<UDP>()){}

    ~PacketAnalyzerImpl() = default;
    //transport layer 헤더 시작위치 계산
    int getTransportOffset() const {
        int offset = sizeof(EtherHeader);  // L2: Ethernet Header 크기

        // L3: Network Layer
        if (ethernet->getNextProtocolString() == "IPv4") {
            offset += sizeof(IpHeader);  // IPv4 헤더 크기
        }
        else if (ethernet->getNextProtocolString() == "IPv6") {
            offset += sizeof(Ipv6Header);  // IPv6 기본 헤더 크기

            // IPv6 확장 헤더 처리
            U8 nextHeader = ipv6->getProtocol();
            while (ipv6->isExtensionHeader(nextHeader)) {
                offset += ipv6->getExtensionHeaderLength(&nextHeader);  // 확장 헤더 길이 추가
                nextHeader = ipv6->getNextHeader(&nextHeader);  // 다음 헤더 값 갱신
            }
        }

        return offset;
    }
};
PacketAnalyzer::PacketAnalyzer()
    : impl(std::make_unique<PacketAnalyzerImpl>()),seq(0) {
}
PacketAnalyzer::~PacketAnalyzer() = default;

void PacketAnalyzer::init()
{
    this->seq = 0;
}

PacketData PacketAnalyzer::analyzePacket(const u_char* packet, const pcap_pkthdr* pkthdr)
{
    PacketData data;
    stringstream info;
    stringstream details;
    //time stamp 설정
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;

    local_tv_sec = pkthdr->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);


    data.setNum(this->seq++);
    data.setTime(timestr);
    data.setLength(to_string(pkthdr->len));
    //L2 layer : Data link layer***************************************
    
    //일단은 ethernet protocol이라고 가정하고 시작한다.====나중에 수정필요
    
    impl->ethernet = make_unique<Ethernet>(packet);
    details << impl->ethernet->printEthernet();

    data.setProtocol("ethernet");
    data.setSrc(impl->ethernet->getSourceMac());
    data.setDst(impl->ethernet->getDestinationMac());

    string nextProtocol = impl->ethernet->getNextProtocolString();
    
    //L3 Layer : Network layer******************************************
    if (nextProtocol.compare("IPv4")==0) {
        impl->ip = make_unique<IP>(packet + sizeof(EtherHeader));
        details << impl->ip->printIP();

        data.setProtocol("IPv4");
        data.setSrc(impl->ip->getSourceIP());
        data.setDst(impl->ip->getDestinationIP());
        nextProtocol = impl->ip->getNextProtocolString();
    }
    else if (nextProtocol.compare("IPv6")==0) {
        impl->ipv6 = make_unique<IPv6>(packet + sizeof(EtherHeader));
        details << impl->ipv6->printIP();

        data.setProtocol("IPv6");
        data.setSrc(impl->ipv6->getSourceIP());
        data.setDst(impl->ipv6->getDestinationIP());
        nextProtocol = impl->ipv6->getNextProtocolString();
    }
    else if (nextProtocol.compare("ARP")==0) {
        impl->arp = make_unique<ARP>(packet + sizeof(EtherHeader));
        details << impl->arp->printARP();
        data.setInfo(impl->arp->formatArpInfo());

        data.setProtocol("ARP");
        nextProtocol = "none";
    }
    else if (nextProtocol.compare("RARP") == 0) {
        data.setProtocol("RARP");
    }
    else {
        data.setProtocol("Unknown");
    }

    //L3 Layer : Transport layer******************************************

    if (nextProtocol.compare("TCP")==0) {
        impl->tcp = make_unique<TCP>(packet + impl->getTransportOffset());
        details << impl->tcp->printTCP();
        data.setInfo(impl->tcp->formatTcpInfo());
        data.setProtocol("TCP");
    }else if (nextProtocol.compare("UDP")==0) {
        impl->udp = make_unique<UDP>(packet + impl->getTransportOffset());
        details << impl->udp->printUDP();
        data.setInfo(impl->udp->formatUdpInfo());
        data.setProtocol("UDP");
    }
    data.setDetails(details.str());
    return data;
}




/************************************
    PacketSaver class
*************************************/
//생성자 : dumpfile 초기화
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




/************************************
    PacketStatistics class
*************************************/
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
