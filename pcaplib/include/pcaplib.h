#pragma once

class PacketCapture {
public:
    // �����ڿ� �Ҹ���
    PacketCapture();
    ~PacketCapture();

    // ��Ŷ ĸó ����
    bool startCapture(const string& deviceName);

    // ��Ŷ �ڵ鷯 ���
    static void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

    // ��Ŷ ĸó ����
    void stopCapture();

    vector<string> getDevs();
private:
    // Npcap ���̺귯�� �ʱ�ȭ
    bool initialize();

    //npcap �������̺귯�� �ε�
    bool LoadNpcapDlls();

private:
    pcap_if_t* alldevs; //network devices
    pcap_t* handle;   // ĸó �ڵ�
    string deviceName; // ĸó�� ��Ʈ��ũ ��ġ �̸�
};

