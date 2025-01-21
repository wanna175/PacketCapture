#pragma once

#pragma pack(push,1)
typedef struct EtherHeader {
	U8 dstMac[6];
	U8 srcMac[6];
	U16 type;
}EtherHeader;
#pragma pack(pop)

void printEtherHeader(EtherHeader* pdata);
