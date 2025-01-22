#ifndef PCH_H
#define PCH_H

#define WIN32_LEAN_AND_MEAN   

#include <cstdint>
#include <iostream>
#include <vector>
#include <iomanip>
#include <time.h>
#include <thread>
#include <chrono>
#include <WinSock2.h>
#include <tchar.h>
#pragma comment(lib,"wpcap")
#pragma comment(lib, "ws2_32")

#include "../include/types/Types.h"
#include "../include/protocols/protocols.h"

using namespace std;
#endif //PCH_H ==#pragma once와 같은 기능이다.
