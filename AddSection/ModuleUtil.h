#pragma once
typedef char* ModuleAddr;
/*加载PE文件*/
ModuleAddr myLoadLibrary(TCHAR* filePath);
//比较字符串是否相等
int compareStr(char* str1,char* str2);
//根据名称获取地址
DWORD getFuncAddr(char* iBuff, const char* funName);