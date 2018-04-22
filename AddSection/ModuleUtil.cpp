#include "stdafx.h"
#include "ModuleUtil.h"
ModuleAddr myLoadLibrary(TCHAR * filePath)
{
		char* fBuff=NULL;
		//����library���ڴ�
		int size = _read_file_to_fbuff(filePath, &fBuff);

		char* _i_buff = NULL;
		int _i_buff_size = _read_fbuff_to_ibuff(fBuff, &_i_buff);

		//�޸��ض�λ��
		restoreTable(_i_buff);

		return _i_buff;
}

DWORD getFuncAddr(char* iBuff, const char* funName)
{
		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)iBuff;

		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(iBuff + _dos->e_lfanew);
		DWORD imageBase = _nt->OptionalHeader.ImageBase;

		//���� ���������ƫ����ʼ��ַ 
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		//�������ַΪ�����һ��
		_IMAGE_EXPORT_DIRECTORY* exp_table = (_IMAGE_EXPORT_DIRECTORY *)(iBuff +   _data_table->VirtualAddress) ;


		if (NULL != exp_table) {

				//�����������ַ��ָ��
				char* _fun_table_rva_addr = iBuff   + exp_table->AddressOfFunctions ;

				//�������ֱ��ַ��ָ��
				char* _name_table_rva_addr = iBuff +   exp_table->AddressOfNames ;

				//������ű��ַ��ָ��
				char* _ordinals_table_rva_addr = iBuff +   exp_table->AddressOfNameOrdinals ;

				for (size_t j = 0; j < exp_table->NumberOfNames; j++)
				{
						//��ȡ���ֵĵ�ַ
						DWORD  _name_rva_addr = *((DWORD*)_name_table_rva_addr);
						char* name = iBuff +   _name_rva_addr ;
						int cResult = compareStr(name, (char*)funName);

						if (cResult)
						{

								//�ҵ��±��Ӧ�����ֱ�ƫ��
								WORD  _ordinals = *((WORD*)(_ordinals_table_rva_addr + sizeof(WORD)*j));
								//ȡ������Ŷ�Ӧ�ĺ�����ַ
								DWORD  dword = *((DWORD*)(_fun_table_rva_addr + sizeof(DWORD)*_ordinals));
								//���غ�����ַ
								return dword + (DWORD)iBuff;
						}
						_name_table_rva_addr += 4;
				}
		}
		else {
				printf("\nû���ҵ�������\n");
		}
		return 0;
}
/*
DWORD getFuncAddr(ModuleAddr moudle, const char* funName)
{
		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)moudle;

		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(moudle + _dos->e_lfanew);
		DWORD imageBase = _nt->OptionalHeader.ImageBase;

		//���� ���������ƫ����ʼ��ַ 
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		//�������ַΪ�����һ��
		_IMAGE_EXPORT_DIRECTORY* exp_table = (_IMAGE_EXPORT_DIRECTORY *)(moudle + _rva_to_foa(moudle, _data_table->VirtualAddress));


		if (NULL != exp_table) {

				//�����������ַ��ָ��
				char* _fun_table_rva_addr = moudle + _rva_to_foa(moudle, exp_table->AddressOfFunctions);

				//�������ֱ��ַ��ָ��
				char* _name_table_rva_addr = moudle + _rva_to_foa(moudle, exp_table->AddressOfNames);

				//������ű��ַ��ָ��
				char* _ordinals_table_rva_addr = moudle + _rva_to_foa(moudle, exp_table->AddressOfNameOrdinals);

				for (size_t j = 0; j < exp_table->NumberOfNames; j++)
				{
						//��ȡ���ֵĵ�ַ
						DWORD  _name_rva_addr = *((DWORD*)_name_table_rva_addr);
						char* name = moudle + _rva_to_foa(moudle, _name_rva_addr);
						int cResult = compareStr(name, (char*)funName);

						if (cResult)
						{

								//�ҵ��±��Ӧ�����ֱ�ƫ��
								WORD  _ordinals = *((WORD*)(_ordinals_table_rva_addr + sizeof(WORD)*j));
								//ȡ������Ŷ�Ӧ�ĺ�����ַ
								DWORD  dword = *((DWORD*)(_fun_table_rva_addr + sizeof(DWORD)*_ordinals));
								//���غ�����ַ
								return dword + (DWORD)moudle;
						}
						_name_table_rva_addr += 4;
				}
		}
		else {
				printf("\nû���ҵ�������\n");
		}
		return 0;
}*/

//�Ƚ��ַ����Ƿ����
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
