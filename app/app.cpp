#ifdef _DEBUG
#pragma comment(lib,"Debug\\pcaplib.lib")//링커에게 lib위치를 알려줘야함.
#else
#pragma comment(lib,"Release\\pcaplib.lib")
#endif
#include "pcaplib.h"
#include <iostream>
using namespace std;
int main()
{
	HelloWorld();
	cout<<setNpcapDirectory();
	return 0;
}
