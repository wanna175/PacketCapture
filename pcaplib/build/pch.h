#ifndef PCH_H
#define PCH_H

#define WIN32_LEAN_AND_MEAN             // 거의 사용되지 않는 내용을 Windows 헤더에서 제외합니다.
#include <WinSock2.h>
#include <tchar.h>

#include <atomic>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <iomanip>
#include <string>
#include <pcap.h>
#include <time.h>
#include <thread>
#include <chrono>

#pragma comment(lib,"wpcap")
#pragma comment(lib, "ws2_32")

#include "../include/types/Types.h"
#include "../include/protocols/protocols.h"

using namespace std;
#endif //PCH_H ==#pragma once와 같은 기능이다.
