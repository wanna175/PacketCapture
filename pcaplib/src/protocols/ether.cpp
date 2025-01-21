#include "pch.h"
#include "../Include/protocols/ether.h"

void printEtherHeader(EtherHeader* pEther)
{
    cout 
        << "SRC: "
        << hex << uppercase << setfill('0')
        << setw(2) << static_cast<int>(pEther->srcMac[0]) << "-"
        << setw(2) << static_cast<int>(pEther->srcMac[1]) << "-"
        << setw(2) << static_cast<int>(pEther->srcMac[2]) << "-"
        << setw(2) << static_cast<int>(pEther->srcMac[3]) << "-"
        << setw(2) << static_cast<int>(pEther->srcMac[4]) << "-"
        << setw(2) << static_cast<int>(pEther->srcMac[5]) << " -> "
        << "DST: "
        << setw(2) << static_cast<int>(pEther->dstMac[0]) << "-"
        << setw(2) << static_cast<int>(pEther->dstMac[1]) << "-"
        << setw(2) << static_cast<int>(pEther->dstMac[2]) << "-"
        << setw(2) << static_cast<int>(pEther->dstMac[3]) << "-"
        << setw(2) << static_cast<int>(pEther->dstMac[4]) << "-"
        << setw(2) << static_cast<int>(pEther->dstMac[5]) << ", type:"
        << hex << setw(4) << ntohs(pEther->type)
        << dec << endl;

}
