#pragma once
typedef char* ModuleAddr;
/*����PE�ļ�*/
ModuleAddr myLoadLibrary(TCHAR* filePath);
//�Ƚ��ַ����Ƿ����
int compareStr(char* str1,char* str2);
//�������ƻ�ȡ��ַ
DWORD getFuncAddr(char* iBuff, const char* funName);