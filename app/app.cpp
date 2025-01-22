#ifdef _DEBUG
#pragma comment(lib,"Debug\\pcaplib.lib")//링커에게 lib위치를 알려줘야함.
#else
#pragma comment(lib,"Release\\pcaplib.lib")
#endif
#include "pcaplib.h"
using namespace std;
int main()
{
	PacketCapture pcap;
	pcap.initialize();
	pcap.listDevices();
	pcap.selectDev(5);
	pcap.startCapture("\Device\NPF_{C134B553-6E9B-4F98-B152-AA162C91EA2A}", "", 5);
	
	return 0;
}
