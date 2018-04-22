#include "stdafx.h"
#include "ModuleUtil.h"
ModuleAddr myLoadLibrary(TCHAR * filePath)
{
		char* fBuff=NULL;
		//加载library到内存
		int size = _read_file_to_fbuff(filePath, &fBuff);

		char* _i_buff = NULL;
		int _i_buff_size = _read_fbuff_to_ibuff(fBuff, &_i_buff);

		//修复重定位表
		restoreTable(_i_buff);

		return _i_buff;
}

DWORD getFuncAddr(char* iBuff, const char* funName)
{
		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)iBuff;

		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(iBuff + _dos->e_lfanew);
		DWORD imageBase = _nt->OptionalHeader.ImageBase;

		//导出 导入表数组偏移起始地址 
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		//导出表地址为数组第一个
		_IMAGE_EXPORT_DIRECTORY* exp_table = (_IMAGE_EXPORT_DIRECTORY *)(iBuff +   _data_table->VirtualAddress) ;


		if (NULL != exp_table) {

				//创建函数表地址的指针
				char* _fun_table_rva_addr = iBuff   + exp_table->AddressOfFunctions ;

				//创建名字表地址的指针
				char* _name_table_rva_addr = iBuff +   exp_table->AddressOfNames ;

				//创建序号表地址的指针
				char* _ordinals_table_rva_addr = iBuff +   exp_table->AddressOfNameOrdinals ;

				for (size_t j = 0; j < exp_table->NumberOfNames; j++)
				{
						//获取名字的地址
						DWORD  _name_rva_addr = *((DWORD*)_name_table_rva_addr);
						char* name = iBuff +   _name_rva_addr ;
						int cResult = compareStr(name, (char*)funName);

						if (cResult)
						{

								//找到下标对应的名字表偏移
								WORD  _ordinals = *((WORD*)(_ordinals_table_rva_addr + sizeof(WORD)*j));
								//取出跟序号对应的函数地址
								DWORD  dword = *((DWORD*)(_fun_table_rva_addr + sizeof(DWORD)*_ordinals));
								//返回函数地址
								return dword + (DWORD)iBuff;
						}
						_name_table_rva_addr += 4;
				}
		}
		else {
				printf("\n没有找到导出表\n");
		}
		return 0;
}
/*
DWORD getFuncAddr(ModuleAddr moudle, const char* funName)
{
		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)moudle;

		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(moudle + _dos->e_lfanew);
		DWORD imageBase = _nt->OptionalHeader.ImageBase;

		//导出 导入表数组偏移起始地址 
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		//导出表地址为数组第一个
		_IMAGE_EXPORT_DIRECTORY* exp_table = (_IMAGE_EXPORT_DIRECTORY *)(moudle + _rva_to_foa(moudle, _data_table->VirtualAddress));


		if (NULL != exp_table) {

				//创建函数表地址的指针
				char* _fun_table_rva_addr = moudle + _rva_to_foa(moudle, exp_table->AddressOfFunctions);

				//创建名字表地址的指针
				char* _name_table_rva_addr = moudle + _rva_to_foa(moudle, exp_table->AddressOfNames);

				//创建序号表地址的指针
				char* _ordinals_table_rva_addr = moudle + _rva_to_foa(moudle, exp_table->AddressOfNameOrdinals);

				for (size_t j = 0; j < exp_table->NumberOfNames; j++)
				{
						//获取名字的地址
						DWORD  _name_rva_addr = *((DWORD*)_name_table_rva_addr);
						char* name = moudle + _rva_to_foa(moudle, _name_rva_addr);
						int cResult = compareStr(name, (char*)funName);

						if (cResult)
						{

								//找到下标对应的名字表偏移
								WORD  _ordinals = *((WORD*)(_ordinals_table_rva_addr + sizeof(WORD)*j));
								//取出跟序号对应的函数地址
								DWORD  dword = *((DWORD*)(_fun_table_rva_addr + sizeof(DWORD)*_ordinals));
								//返回函数地址
								return dword + (DWORD)moudle;
						}
						_name_table_rva_addr += 4;
				}
		}
		else {
				printf("\n没有找到导出表\n");
		}
		return 0;
}*/

//比较字符串是否相等
int compareStr(char * str1, char * str2)
{
		char* tempStr1 = str1;
		char* tempStr2 = str2;
		while (*tempStr1 != '\0' && *tempStr2 != '\0') 
		{
				if(*tempStr1==*tempStr2)
				{
						tempStr1++;
						tempStr2++;
						continue;
				}
				return 0;
		}

		return 1;
}
