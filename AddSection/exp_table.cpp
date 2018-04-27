#include "stdafx.h"
#include "exp_table.h"
#include <Windows.h>
/*��ӡ������ �����*/
void print_exp_table(char * _file_buff)
{
		_IMAGE_DOS_HEADER* _dos =(_IMAGE_DOS_HEADER*) _file_buff;
		
		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(_file_buff + _dos->e_lfanew);


		IMAGE_DATA_DIRECTORY*  _data_table =	_nt->OptionalHeader.DataDirectory;


		for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
		{
				printf("==========================================\n");
				printf("VirtualAddress:%X\nSize:%X\n", _data_table[i].VirtualAddress, _data_table[i].Size);
				printf("==========================================\n");

		}


}

/*��ӡ������*/
void print_exp_table(char * _file_buff, char * _image_buff)
{
		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)_file_buff;

		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(_file_buff + _dos->e_lfanew);

		//���� ���������ƫ����ʼ��ַ 
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		//�������ַΪ�����һ��
		_IMAGE_EXPORT_DIRECTORY* exp_table = (_IMAGE_EXPORT_DIRECTORY *)((char*)  (_image_buff + _data_table->VirtualAddress));




		printf("\nBase : %d\n", exp_table->Base);
		printf("\nName : %d\n", exp_table->Name);

		if(NULL!=exp_table){

										//�����������ַ��ָ��
								char* _fun_table_rva_addr = (_image_buff + exp_table->AddressOfFunctions);

								printf("���������ĸ���Ϊ:%d\n", exp_table->NumberOfFunctions);
								for (size_t i = 0; i < exp_table->NumberOfFunctions; i++)
								{ 
										//�������ֱ��ַ��ָ��
										char* _name_table_rva_addr = (_image_buff + exp_table->AddressOfNames);
										 
										//������ű��ַ��ָ��
										char* _ordinals_table_rva_addr = (_image_buff + exp_table->AddressOfNameOrdinals);
										 
										DWORD _fun_rva_addr= *((DWORD*)(_fun_table_rva_addr));
										if (!_fun_rva_addr) {
												_fun_table_rva_addr += 4;
												continue;
										}
										for (size_t j = 0; j < exp_table->NumberOfNames; j++)
										{
												//��ȡ��ŵĵ�ַ
												WORD  _ordinals = *((WORD*)_ordinals_table_rva_addr);
												//˵���ǰ����ֵ���
												if (_ordinals == i) {
																_name_table_rva_addr += 4*j;
														//��ȡ���ֵĵ�ַ
														DWORD  _name_rva_addr = *((DWORD*)_name_table_rva_addr);
														char* name = _image_buff + _name_rva_addr;
														//��ӡ��� - ���� -������ַ
														printf("%d - %s - %X \n", i + exp_table->Base, name,_fun_rva_addr);
														goto _next;
												}
												_ordinals_table_rva_addr += 2;
										}
										//˵���ǰ���ŵ����� ��ӡ������ַ - �������
										printf("%d - $ - %X \n", i + exp_table->Base, _fun_rva_addr);
									
										_next:	_fun_table_rva_addr += 4;
								}
								//printf("�����������Ƹ���Ϊ:%d\n", exp_table->NumberOfNames);
								//				for (size_t i = 0; i < exp_table->NumberOfNames; i++)
								//				{
								//						//��ȡ���ֵĵ�ַ
								//						DWORD  _name_rva_addr = *((DWORD*)_name_table_rva_addr);

								//				 	char* name =	_image_buff + _name_rva_addr;

								//						//��ȡ��ŵĵ�ַ
								//						WORD  _ordinals = *((WORD*)_ordinals_table_rva_addr);
								//						//��ӡ��� - ����
								//						printf("%d - %s\n", _ordinals, name);

								//						_ordinals_table_rva_addr += 2;

								//						_name_table_rva_addr += 4;
								//				}
		}
		else {
				printf("\nû���ҵ�������\n");
		}
}


/*����һ����,����Ϊ  _file_buff-�ļ�buffer name-�ڵ����� virtualSize-�ļ��ж���ǰ�Ĵ�С          ����_add_section_file_size�����ں���ļ���С*/
char* add_section(char * _f_buff, int _file_buff_size,const char * name,int virtualSize,int* _add_section_file_size)
{

		_IMAGE_DOS_HEADER* _dos_header = (_IMAGE_DOS_HEADER*)_f_buff;
		//����PE���λ��ƫ��
		DWORD _pe_sign_offset = _dos_header->e_lfanew;

		_IMAGE_NT_HEADERS* _nt_header = (_IMAGE_NT_HEADERS *)(_f_buff + _pe_sign_offset);

		//������
		WORD sectionNum = _nt_header->FileHeader.NumberOfSections;

		//�����ѡPEͷ��С
		WORD SizeOfOpeHead = _nt_header->FileHeader.SizeOfOptionalHeader;


		//�ڴ�����С
		_mem_Alignment = _nt_header->OptionalHeader.SectionAlignment;
		//�����ڴ澵���ַ
		_image_base = _nt_header->OptionalHeader.ImageBase;
		//�����ڴ������ƫ�Ƶ�ַ
		_image_buffer_oep = _nt_header->OptionalHeader.AddressOfEntryPoint;
		//����_image_buffer�����ڴ��С
		_size_image = _nt_header->OptionalHeader.SizeOfImage;
		//��ȡ����ͷ��������Ϣ��С
		_headers = _nt_header->OptionalHeader.SizeOfHeaders;
		_file_Alignment = _nt_header->OptionalHeader.FileAlignment;
 

		//�����׼PEͷ��С
		size_t fSize = sizeof(_nt_header->FileHeader);
		//�������׵�ַ = PE���+��׼PEͷ��С+��ѡPEͷ��С
		char* sHeaderAddr = ((char*)(_nt_header)) + fSize + SizeOfOpeHead + sizeof(_nt_header->Signature);

		//ת��Ϊָ�������� �ṹ��ָ��
		_IMAGE_SECTION_HEADER* _section_header = (_IMAGE_SECTION_HEADER*)sHeaderAddr;

		 
		/*�жϹ���Ҫ�����ڴ���볤��*/
		int _add_section_need_size_ = virtualSize / _file_Alignment;
		_add_section_need_size_ = (_add_section_need_size_ + (virtualSize % _file_Alignment == 0 ? 0 : 1))*_file_Alignment;

		//����һ���µĿռ� ����Ĵ�С
		*_add_section_file_size = _file_buff_size + _add_section_need_size_;

		//����һ���µĿռ�
		char* _file_buff = new char[*_add_section_file_size];
		memset(_file_buff, 0, *_add_section_file_size);


		//�������������ڴ��������С
		int _add_section_need_virtual_size_ = virtualSize / _mem_Alignment;
		_add_section_need_virtual_size_ = (_add_section_need_virtual_size_ + (virtualSize % _mem_Alignment == 0 ? 0 : 1))*_mem_Alignment;
		//�޸�sizeofimage Ϊԭ�ȴ�С+�½ڵĴ�С
 _nt_header->OptionalHeader.SizeOfImage = _size_image+ _add_section_need_virtual_size_;

	if (((char*)(&_section_header[sectionNum]) - _f_buff + sizeof(_IMAGE_SECTION_HEADER)) > _section_header[0].PointerToRawData) 
	{
			printf("û���㹻�Ŀռ�����½ڵ�������Ϣ");
			return NULL;
	}

	IMAGE_SECTION_HEADER  _last_section = _section_header[sectionNum - 1];

	_section_header[sectionNum] = _section_header[0];
	_section_header[sectionNum].Misc.VirtualSize = virtualSize;
	_section_header[sectionNum].PointerToRawData = _file_buff_size;
	_section_header[sectionNum].SizeOfRawData = _add_section_need_size_;
	DWORD _previous_section_mem_size=(_last_section.SizeOfRawData / _mem_Alignment + (_last_section.SizeOfRawData % _mem_Alignment == 0 ? 0 : 1))*_mem_Alignment;

	_section_header[sectionNum].VirtualAddress = _last_section.VirtualAddress +  _previous_section_mem_size;

	_mem_copy((char*)name,(char*)(&_section_header[sectionNum].Name), IMAGE_SIZEOF_SHORT_NAME);
	_nt_header->FileHeader.NumberOfSections = (++sectionNum);
		_mem_copy(_f_buff, _file_buff,_file_buff_size);
		return _file_buff;
}
void move_exp_table(char * _file_buff, int _file_buff_size)
{

		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)_file_buff;

		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(_file_buff + _dos->e_lfanew);

		//���� ���������ƫ����ʼ��ַ 
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		DWORD _virtual_addr = _data_table->VirtualAddress;

		//�������ַΪ�����һ��
		_IMAGE_EXPORT_DIRECTORY* exp_table = (_IMAGE_EXPORT_DIRECTORY *)(_file_buff + _rva_to_foa(_file_buff, _virtual_addr));


		if (NULL != exp_table) {

			
				//���㵼����ĺ������ֽڴ�С
				DWORD sizeOfFun = exp_table->NumberOfFunctions * 4;
				//�������Ʊ�������ֽڴ�С
				DWORD sizeOfNm = exp_table->NumberOfNames * 4;
				//������ű�������ֽڴ�С
				DWORD sizeOfOrdinals = exp_table->NumberOfNames * 2;


				//�����������ַ��ָ��
				char* _fun_table_rva_addr = _file_buff + _rva_to_foa(_file_buff, exp_table->AddressOfFunctions);
				//�������ֱ��ַ��ָ��
				char* _name_table_rva_addr = _file_buff + _rva_to_foa(_file_buff, exp_table->AddressOfNames);
				//������ű��ַ��ָ��
				char* _ordinals_table_rva_addr = (_file_buff + _rva_to_foa(_file_buff, exp_table->AddressOfNameOrdinals));

				DWORD sizeOfNameStr = 0;

				for (size_t j = 0; j < exp_table->NumberOfNames; j++)
				{
						char* _name_point = _file_buff + _rva_to_foa(_file_buff, *((DWORD*)_name_table_rva_addr));
						while (*_name_point != '\0')
						{
								sizeOfNameStr++;
								_name_point++;
						}
						//���Ͻ�β�ַ�'\0'
						sizeOfNameStr++;
						//ָ�����Ʊ���һ����ַ
						_name_table_rva_addr += 4;
				}
				//������ṹ��ռ���ֽ���
				DWORD sizeOfexpTable = sizeof(_IMAGE_EXPORT_DIRECTORY);
				//�ƶ�����������������ֽ����Ĵ�С
				DWORD _add_section_virtual_size = sizeOfFun + sizeOfNm + sizeOfOrdinals + sizeOfNameStr + sizeOfexpTable;

				int size = 0;
				//���ش����½ں���ļ�buffer
				char* _f_buff = add_section(_file_buff, _file_buff_size, ".exptab", _add_section_virtual_size, &size);


				_IMAGE_DOS_HEADER* _add_dos = (_IMAGE_DOS_HEADER*)_f_buff;

				_IMAGE_NT_HEADERS* _add_nt = (_IMAGE_NT_HEADERS*)(_f_buff + _add_dos->e_lfanew);

				//���� ���������ƫ����ʼ��ַ 
				IMAGE_DATA_DIRECTORY*  _add_data_table = _add_nt->OptionalHeader.DataDirectory;
			//ԭ�ȵĵ������ַ
				_IMAGE_EXPORT_DIRECTORY*  _original_exp_table = (_IMAGE_EXPORT_DIRECTORY*)(_f_buff + _rva_to_foa(_f_buff, _add_data_table->VirtualAddress));
	

				//�����ڵ��ļ�ƫ��
				char* _add_section_addr = _f_buff + _file_buff_size;
				//������������������   ���ص������ں��filebuffer + ԭfilebuffer�Ĵ�С ���������ڵ��ļ�ƫ��
				_mem_copy((char*)exp_table, _add_section_addr, sizeOfexpTable);
				//���ƶ���ĵ�����ṹ��rva��ַ ���� PEͷ��������Ϣ
				_add_data_table->VirtualAddress = _foa_to_rva(_f_buff, (DWORD)_file_buff_size);
				//��ʼ���������������е�����
				_mem_copy(_fun_table_rva_addr, _add_section_addr + sizeOfexpTable, sizeOfFun);
				//�����ڿ������ֱ���ļ�ƫ��
				char* _add_sec_name_addr = _add_section_addr + sizeOfexpTable + sizeOfFun;
				//��ʼ�������������ֱ��е�����
				_mem_copy(_name_table_rva_addr, _add_sec_name_addr, sizeOfNm);

				//��ʼ������������ű��е�����
				_mem_copy(_ordinals_table_rva_addr, _add_sec_name_addr + sizeOfNm, sizeOfOrdinals);
				//�����꺯��+������ṹ��+���ƺ����ļ��е�ƫ��
				char* _offset_copy_addr_end = _add_section_addr + sizeOfexpTable + sizeOfFun + sizeOfNm + sizeOfOrdinals;
				//������������ �ƶ���ĵ������ַ��ָ��
				_IMAGE_EXPORT_DIRECTORY* _add_sec_exp = (_IMAGE_EXPORT_DIRECTORY*)_add_section_addr;
				//�޸��������к������ַ
				_add_sec_exp->AddressOfFunctions = _foa_to_rva(_f_buff, (_add_section_addr-_f_buff + sizeOfexpTable));
				//�޸������������ֱ��ַ
				_add_sec_exp->AddressOfNames = _foa_to_rva(_f_buff, (_add_section_addr - _f_buff + sizeOfexpTable + sizeOfFun));
				//�޸�����������ű��ַ
				_add_sec_exp->AddressOfNameOrdinals = _foa_to_rva(_f_buff, (_add_section_addr - _f_buff + sizeOfexpTable + sizeOfFun + sizeOfNm));

				//�������ֱ��ַ��ָ��
				char* _add_name_table_rva_addr = _f_buff + _rva_to_foa(_f_buff, _original_exp_table->AddressOfNames);

				//ѭ���޸����������ֱ��еĵ�ַ���
				DWORD* _add_sec_name_addr_point = (DWORD*)_add_sec_name_addr;
				for (size_t j = 0; j < exp_table->NumberOfNames; j++)
				{
						//����ָ��ԭ�����Ʊ����ַ�����ַ��foaָ��
						char* _name_point = _f_buff + _rva_to_foa(_f_buff, *((DWORD*)_add_name_table_rva_addr));
						//���ַ��������ĵ��ĵ�ַת��Ϊrva ��ӵ����ֱ���
						*_add_sec_name_addr_point = _foa_to_rva(_f_buff,_offset_copy_addr_end - _f_buff);
						while (*_name_point != '\0')
						{
								//��ֵ�ַ������ֵ� filebuffer�� ��������
								*_offset_copy_addr_end = *_name_point;
								_offset_copy_addr_end++;
								_name_point++;
						}
						//���Ͻ�β�ַ�'\0'
						*_offset_copy_addr_end = '\0';
						_offset_copy_addr_end++;
						//ָ��ԭ�ȵ����������Ʊ���һ����ַ
						_add_name_table_rva_addr += 4;
						_add_sec_name_addr_point++;
				}
				
				_write_restore_to_file(size, _f_buff);
		}
		else {
				printf("\nû���ҵ�������\n");
		}
		return;
}











/*��ӡ�ض�λ��*/
void print_relocation(char * _f_buff)
{
		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)_f_buff;
		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(_f_buff + _dos->e_lfanew);
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		//�����ض�λ���ָ��,Ҳ���ض�λ��������׸����ַ
		IMAGE_BASE_RELOCATION* _first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(_f_buff + _rva_to_foa(_f_buff,_data_table[5].VirtualAddress));
		//�����ض�λ��Ŀ�����
		int _lump_count = 0;
		while (_first_relocation_table_addr->SizeOfBlock && _first_relocation_table_addr->VirtualAddress)
		{
				printf("�ض�λ���%d�鿪ʼ========================\n", ++_lump_count);
				DWORD block = _first_relocation_table_addr->SizeOfBlock;
				DWORD _virtual_addr = _first_relocation_table_addr->VirtualAddress;
				//����ÿ���ض�λ���е�ÿ�������������ĵ�ַ����
				size_t _addr_count = (block - sizeof(block) - sizeof(_virtual_addr)) / sizeof(WORD);
				printf("�����й� %d����ַ\n", _addr_count);
				//����һ����ʱָ�����ÿ�����еĵ�ַ
				WORD* _temp_relocation = (WORD*)_first_relocation_table_addr;
				_temp_relocation += 4;
				for (size_t i = 0; i < _addr_count; i++)
				{
						WORD _relocation_addr_ = *_temp_relocation;
						//ȡ������λ��ֵ���������λ��������������Ч�ĵ�ַ
						int _valid_flag = _relocation_addr_ >> 12;
						if (_valid_flag == 3)
						{
								DWORD valid_relocation_addr = _virtual_addr + (_relocation_addr_ & 0x0fff);
								printf("��Ч��ַ%2d: %XH Base��ֵΪ:%XH\n", i + 1, valid_relocation_addr, _virtual_addr);
						}
						else {
								printf("��Ч��ַ%2d: -  \t\t - \n", i + 1);
						}
						_temp_relocation += 1;
				}
				//ָ����һ���ض�λ��ṹ
				_first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(((char*)_first_relocation_table_addr) + block);

				printf("�ض�λ���%d�����========================\n", _lump_count);
		}
		printf("�ض�λ����%d��", _lump_count);
}



/*�ƶ�������*/
char* move_relocation_table(char * _file_buff,int _file_buff_size)
{

		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)_file_buff;
		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(_file_buff + _dos->e_lfanew);
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		//�����ض�λ���ָ��,Ҳ���ض�λ��������׸����ַ
		IMAGE_BASE_RELOCATION* _first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(_file_buff + _rva_to_foa(_file_buff,_data_table[5].VirtualAddress));
		//�����ض�λ��������ֽڴ�С,��ʼֵ8 ����� IMAGE_BASE_RELOCATION�������0
		int _byte_count = 8;
		while (_first_relocation_table_addr->SizeOfBlock && _first_relocation_table_addr->VirtualAddress)
		{
			
				DWORD block = _first_relocation_table_addr->SizeOfBlock;
				//�����ض�λ��������ֽڴ�С
				_byte_count += block;
				//ָ����һ���ض�λ��ṹ
				_first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(((char*)_first_relocation_table_addr) + block);

			
		}
	

		int _add_relocation_after_file_size = 0;
		char* _relocation_f_buff = add_section(_file_buff, _file_buff_size, "rloction", _byte_count,&_add_relocation_after_file_size);
		delete _file_buff;
		_IMAGE_DOS_HEADER* _relocation_dos = (_IMAGE_DOS_HEADER*)_relocation_f_buff;
		_IMAGE_NT_HEADERS* _relocation_nt = (_IMAGE_NT_HEADERS*)(_relocation_f_buff + _dos->e_lfanew);
		IMAGE_DATA_DIRECTORY*  _relocation_data_table = _relocation_nt->OptionalHeader.DataDirectory;
		//ԭ�ȵ��ض�λ���ļ�ƫ�Ƶ�ַ
		char* relocationFileOffset =_relocation_f_buff + _rva_to_foa(_relocation_f_buff, _relocation_data_table[5].VirtualAddress);
		//�����ض�λ���ָ��,Ҳ���ض�λ��������׸����ַ
		IMAGE_BASE_RELOCATION* _original_first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)relocationFileOffset;
		//��ȡ�����ڵ��ļ�ƫ�� ��ΪŲ���µ��ض�λ���ƫ�Ƶ�ַ
		char* addSectionFileOffset =_relocation_f_buff + _file_buff_size;
		//����һ����ʱָ�� ���������ڵ�ƫ�Ƶ�ַ
		char* tempAddSecionFileOffset = addSectionFileOffset;


		//�����ض�λ��Ŀ�����
		int _lump_count = 0;

		while (_original_first_relocation_table_addr->SizeOfBlock && _original_first_relocation_table_addr->VirtualAddress)
		{
				printf("�ض�λ���%d�鿪ʼ========================\n", ++_lump_count);
				DWORD block = _original_first_relocation_table_addr->SizeOfBlock;
				//��ԭ�ȵ��ض�λ�����Ϣ��������������
				_mem_copy(relocationFileOffset, addSectionFileOffset, block);
				


				//��ԭ���ض�λ��ĵ�ַ���Ͽ������Ĵ�С��ָ��Ҫ��������һ���ض�λ��Ŀ�ͷ��λ��
				relocationFileOffset += block;
				//�������ڵ�ƫ�Ƶ�ַ���Ͽ������Ĵ�С��ָ����һ��Ҫ������λ��
				addSectionFileOffset += block;
				
				//ָ����һ���ض�λ��ṹ
				_original_first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)relocationFileOffset;

				printf("�ض�λ���%d�����========================\n", _lump_count);
		}
		//����ָ�������� �ض�λ��ĩβ ������������0
		IMAGE_BASE_RELOCATION* addSectionRelocationEnd= (IMAGE_BASE_RELOCATION*)addSectionFileOffset;
		addSectionRelocationEnd->SizeOfBlock = 0;
		addSectionRelocationEnd->VirtualAddress = 0;


		//�޸�ԭ���ض�λ�����ض�λ��ĵ�ַָ���������п���������ض�λ���ַ
		_relocation_data_table[5].VirtualAddress =  _foa_to_rva(_relocation_f_buff, (DWORD)(tempAddSecionFileOffset - _relocation_f_buff));
		
		printf("�ض�λ����%d��", _lump_count);
		_write_restore_to_file(_add_relocation_after_file_size, _relocation_f_buff);
		return _relocation_f_buff;
}
/*�޸�ImageBase�� �޸��ض�λ��*/
void changeImageBase(char * _f_buff, int _file_buff_size)
{ 
		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)_f_buff;
		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(_f_buff + _dos->e_lfanew);
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		//�����ض�λ���ָ��,Ҳ���ض�λ��������׸����ַ
		IMAGE_BASE_RELOCATION* _first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(_f_buff + _rva_to_foa(_f_buff, _data_table[5].VirtualAddress));


		DWORD  _image_base = _nt->OptionalHeader.ImageBase;
		_nt->OptionalHeader.ImageBase = _image_base + 0x100000;

		//�����ض�λ��Ŀ�����
		int _lump_count = 0;
		while (_first_relocation_table_addr->SizeOfBlock && _first_relocation_table_addr->VirtualAddress)
		{
				printf("�ض�λ���%d�鿪ʼ========================\n", ++_lump_count);
				DWORD block = _first_relocation_table_addr->SizeOfBlock;
				DWORD _virtual_addr = _first_relocation_table_addr->VirtualAddress;
				//����ÿ���ض�λ���е�ÿ�������������ĵ�ַ����
				size_t _addr_count = (block - sizeof(block) - sizeof(_virtual_addr)) / sizeof(WORD);
				printf("�����й� %d����ַ\n", _addr_count);
				//����һ����ʱָ�����ÿ�����еĵ�ַ
				WORD* _temp_relocation = (WORD*)_first_relocation_table_addr;
				_temp_relocation += 4;
				for (size_t i = 0; i < _addr_count; i++)
				{
						WORD _relocation_addr_ = *_temp_relocation;
						//ȡ������λ��ֵ���������λ��������������Ч�ĵ�ַ
						int _valid_flag = _relocation_addr_ >> 12;
						if (_valid_flag == 3)
						{
								DWORD valid_relocation_addr = _virtual_addr + (_relocation_addr_ & 0x0fff);
								char* _changeAddr = _f_buff+_rva_to_foa(_f_buff,valid_relocation_addr );
								DWORD _changeAddrNum = *((DWORD*)_changeAddr);
								*((DWORD*)_changeAddr) = _changeAddrNum + 0X100000;

								printf("��Ч��ַ%2d: %XH Base��ֵΪ:%XH \n", i + 1, valid_relocation_addr, _virtual_addr);
						}
						else {
								printf("��Ч��ַ%2d: -  \t\t - \n", i + 1);
						}
						_temp_relocation += 1;
				}
				//ָ����һ���ض�λ��ṹ
				_first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(((char*)_first_relocation_table_addr) + block);

				printf("�ض�λ���%d�����========================\n", _lump_count);
		}
		printf("�ض�λ����%d��", _lump_count);
		_write_restore_to_file(_file_buff_size, _f_buff);

}

/* �޸��ض�λ��*/
void restoreTable(char * _f_buff)
{
		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)_f_buff;
		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(_f_buff + _dos->e_lfanew);
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		//�����ض�λ���ָ��,Ҳ���ض�λ��������׸����ַ
		IMAGE_BASE_RELOCATION* _first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(_f_buff + _rva_to_foa(_f_buff, _data_table[5].VirtualAddress));


		DWORD  _image_base = _nt->OptionalHeader.ImageBase;
		//ImageBase ��ƫ����
		DWORD   _image_base_offset = ((DWORD)_f_buff - _image_base);
		//�����ض�λ��Ŀ�����
		int _lump_count = 0;
		while (_first_relocation_table_addr->SizeOfBlock && _first_relocation_table_addr->VirtualAddress)
		{
				printf("�ض�λ���%d�鿪ʼ========================\n", ++_lump_count);
				DWORD block = _first_relocation_table_addr->SizeOfBlock;
				DWORD _virtual_addr = _first_relocation_table_addr->VirtualAddress;
				//����ÿ���ض�λ���е�ÿ�������������ĵ�ַ����
				size_t _addr_count = (block - sizeof(block) - sizeof(_virtual_addr)) / sizeof(WORD);
				printf("�����й� %d����ַ\n", _addr_count);
				//����һ����ʱָ�����ÿ�����еĵ�ַ
				WORD* _temp_relocation = (WORD*)_first_relocation_table_addr;
				_temp_relocation += 4;
				for (size_t i = 0; i < _addr_count; i++)
				{
						WORD _relocation_addr_ = *_temp_relocation;
						//ȡ������λ��ֵ���������λ��������������Ч�ĵ�ַ
						int _valid_flag = _relocation_addr_ >> 12;
						if (_valid_flag == 3)
						{
								DWORD valid_relocation_addr = _virtual_addr + (_relocation_addr_ & 0x0fff);
								char* _changeAddr = _f_buff + _rva_to_foa(_f_buff, valid_relocation_addr);
								DWORD _changeAddrNum = *((DWORD*)_changeAddr);
								*((DWORD*)_changeAddr) = _changeAddrNum + _image_base_offset;

								printf("��Ч��ַ%2d: %XH Base��ֵΪ:%XH \n", i + 1, valid_relocation_addr, _virtual_addr);
						}
						else {
								printf("��Ч��ַ%2d: -  \t\t - \n", i + 1);
						}
						_temp_relocation += 1;
				}
				//ָ����һ���ض�λ��ṹ
				_first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(((char*)_first_relocation_table_addr) + block);

				printf("�ض�λ���%d�����========================\n", _lump_count);
		}
		printf("�ض�λ����%d��", _lump_count);

}

/* �޸��ض�λ�� ������״̬*/
void restoreTableIbuff(char * _i_buff)
{

		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)_i_buff;
		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(_i_buff + _dos->e_lfanew);
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		//�����ض�λ���ָ��,Ҳ���ض�λ��������׸����ַ
		IMAGE_BASE_RELOCATION* _first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(_i_buff +   _data_table[5].VirtualAddress );


		DWORD  _image_base = _nt->OptionalHeader.ImageBase;
		//ImageBase ��ƫ����
		DWORD   _image_base_offset = ((DWORD)_i_buff - _image_base);
		//�����ض�λ��Ŀ�����
		int _lump_count = 0;
		while (_first_relocation_table_addr->SizeOfBlock && _first_relocation_table_addr->VirtualAddress)
		{
				printf("�ض�λ���%d�鿪ʼ========================\n", ++_lump_count);
				DWORD block = _first_relocation_table_addr->SizeOfBlock;
				DWORD _virtual_addr = _first_relocation_table_addr->VirtualAddress;
				//����ÿ���ض�λ���е�ÿ�������������ĵ�ַ����
				size_t _addr_count = (block - sizeof(block) - sizeof(_virtual_addr)) / sizeof(WORD);
				printf("�����й� %d����ַ\n", _addr_count);
				//����һ����ʱָ�����ÿ�����еĵ�ַ
				WORD* _temp_relocation = (WORD*)_first_relocation_table_addr;
				_temp_relocation += 4;
				for (size_t i = 0; i < _addr_count; i++)
				{
						WORD _relocation_addr_ = *_temp_relocation;
						//ȡ������λ��ֵ���������λ��������������Ч�ĵ�ַ
						int _valid_flag = _relocation_addr_ >> 12;
						if (_valid_flag == 3)
						{
								DWORD valid_relocation_addr = _virtual_addr + (_relocation_addr_ & 0x0fff);
								char* _changeAddr = _i_buff +  valid_relocation_addr ;
								DWORD _changeAddrNum = *((DWORD*)_changeAddr);
								*((DWORD*)_changeAddr) = _changeAddrNum + _image_base_offset;

								printf("��Ч��ַ%2d: %XH Base��ֵΪ:%XH \n", i + 1, valid_relocation_addr, _virtual_addr);
						}
						else {
								printf("��Ч��ַ%2d: -  \t\t - \n", i + 1);
						}
						_temp_relocation += 1;
				}
				//ָ����һ���ض�λ��ṹ
				_first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(((char*)_first_relocation_table_addr) + block);

				printf("�ض�λ���%d�����========================\n", _lump_count);
		}
		printf("�ض�λ����%d��", _lump_count);
}
//��ӡ�����
void printImpTab(char * fBuff, int buffSize)
{
		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)fBuff;
		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(fBuff + _dos->e_lfanew);
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		//��ȡ�����ṹָ��  ��Ŀ¼������ĵڶ���λ��
		_IMAGE_IMPORT_DESCRIPTOR*  impTable =(_IMAGE_IMPORT_DESCRIPTOR*)(fBuff + _rva_to_foa(fBuff, _data_table[1].VirtualAddress));
		//DLL�ĺ�����ַδ�󶨺�
		if(impTable->TimeDateStamp==0)
		{
				if (impTable->OriginalFirstThunk == 0)
				{
						printf("û�е����\n");
						return;
				}
				//ѭ��������ṹ�壬������Ҫ���õ�����PEģ�� �жϽṹ���
				while (impTable->OriginalFirstThunk != 0)
				{
						char* moduleName = fBuff + _rva_to_foa(fBuff, impTable->Name);
						printf("=========��ǰģ������ [%s]======TimeDateStamp:%X\n", moduleName, impTable->TimeDateStamp);

						//��ȡ����� INT��ĵ�ַ
						IMAGE_THUNK_DATA* IntThunkData = ((IMAGE_THUNK_DATA*)(fBuff + _rva_to_foa(fBuff, impTable->OriginalFirstThunk)));
						//��ȡ����� IAT��ĵ�ַ
						IMAGE_THUNK_DATA* IatThunkData = ((IMAGE_THUNK_DATA*)(fBuff + _rva_to_foa(fBuff, impTable->FirstThunk)));

						//�ж�INT��������
						while (IntThunkData->u1.Ordinal != 0)
						{
								//��ȡ����������
								DWORD numOrName = IntThunkData->u1.Ordinal;
								//ȡ����� �ж�Ϊ��ŵ��뻹�����ֵ���
								DWORD flag = numOrName & 0x80000000;

								DWORD iatFunNameAddr = IatThunkData->u1.Ordinal;
								if (flag == 0x80000000)
								{
										DWORD number = numOrName & 0x7FFFFFFF;
										//��ŵ���
										printf("OriginalFirstThunk - �������Ϊ:%d(%XH)   FirstThunk - %X  \n", number, number, iatFunNameAddr);
								}
								else {
										CHAR*  namefoaAddr = fBuff + _rva_to_foa(fBuff, numOrName);
										IMAGE_IMPORT_BY_NAME* impByName = (IMAGE_IMPORT_BY_NAME*)namefoaAddr;

										//Ϊ���ֵ���
										printf("OriginalFirstThunk - ��������Ϊ%s FirstThunk - %X Hint[%X] \n", impByName->Name, iatFunNameAddr, impByName->Hint);
								}
								//ָ����һ��INT��
								IntThunkData++;
								//ָ����һ��IAT��
								IatThunkData++;
						}

						//ָ����һ������� �ṹ��
						impTable++;
				}
				printf("================�����ģ���������========\n");
		}
		//�Ѿ��󶨺� ,���󶨵����
		else if(impTable->TimeDateStamp == -1)
		{
				printf("��ӡ�󶨵���� impTable->TimeDateStamp:%X \n", impTable->TimeDateStamp);
				//����󶨵����foa
				DWORD boundTabFoa = _rva_to_foa(fBuff, _data_table[11].VirtualAddress);
				if (!boundTabFoa) 
				{
						printf("��ӡ�󶨵����  ת��FOA��ַ��Ч");
						return;
				}
				//��ȡ�����ṹָ��  ��Ŀ¼������ĵ�ʮ����λ��
				_IMAGE_BOUND_IMPORT_DESCRIPTOR*  boundImpTable = (_IMAGE_BOUND_IMPORT_DESCRIPTOR*)(fBuff + boundTabFoa);
				
				char*  tempBoundImpTable =(char*) boundImpTable;
				while(boundImpTable->TimeDateStamp|| boundImpTable->OffsetModuleName)
				{
						WORD numModule =boundImpTable->NumberOfModuleForwarderRefs;
				
						printf("TimeDateStamp:%X - OffsetModuleName:%s - NumberOfModule: %d\n", boundImpTable-> TimeDateStamp, tempBoundImpTable +boundImpTable->OffsetModuleName, boundImpTable->NumberOfModuleForwarderRefs);
						//ָ����һ���ṹ��
						_IMAGE_BOUND_FORWARDER_REF* boundForward =		(_IMAGE_BOUND_FORWARDER_REF*)(boundImpTable++);
						for (size_t i = 0; i < numModule; i++)
						{
								printf("TimeDateStamp:%X - OffsetModuleName:%s\n", boundForward->TimeDateStamp, tempBoundImpTable + boundForward->OffsetModuleName);
								boundForward++;
						}

						boundImpTable = boundImpTable + numModule;
				}
				printf("=================��ӡ�󶨵�������==========\n");

		}
		//û�е����
		else
		{
				printf("û�е����");
		}

}

/*�ƶ������ ����Զ����dll ���������PE�ṹ��buffer��ַ
1.���轫�Զ����Dll ����EXEĿ¼
2.�ƶ�exe����� ���Զ����Dll��Ϣ ��ӵ������
*/void moveImpTab(char * fBuff, int fBuffSize,const char* dllName)
{
		const char* funcName = "_div";
		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)fBuff;
		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(fBuff + _dos->e_lfanew);
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;

		char* impTableFoa =  fBuff + _rva_to_foa(fBuff, _data_table[1].VirtualAddress) ;
		//��ȡ�����ṹָ��  ��Ŀ¼������ĵڶ���λ��
		_IMAGE_IMPORT_DESCRIPTOR*  impTable = (_IMAGE_IMPORT_DESCRIPTOR*)impTableFoa;
		//DLL�ĺ�����ַδ�󶨺�
		if (impTable->TimeDateStamp == 0)
		{
				if (impTable->OriginalFirstThunk == 0)
				{
						printf("û�е����\n");
						return;
				}
				//��¼INT���IAT��������ֽڴ�С
				int iatSize =16;
				//��¼������ṹ�ĸ��� ��ʼ��Ϊ1,�Ƕ���Ľ������
				int impTableCount = 2;
				//ѭ��������ṹ�壬������Ҫ���õ�����PEģ�� �жϽṹ���
				while (impTable->OriginalFirstThunk != 0)
				{
						char* moduleName = fBuff + _rva_to_foa(fBuff, impTable->Name);
						printf("=========��ǰģ������ [%s]======TimeDateStamp:%X\n", moduleName, impTable->TimeDateStamp);

						impTableCount ++;
						//ָ����һ������� �ṹ��
						impTable++;
				}
				//���㵼����ṹ����ռ�ֽڵĴ�Сsizeof(_IMAGE_IMPORT_DESCRIPTOR)*impTableCount
				int impTableSize = sizeof(_IMAGE_IMPORT_DESCRIPTOR)*impTableCount;
				//������������ڴ��С = �����ṹ����*��С + IAT��INT����������� + _IMAGE_BOUND_FORWARDER_REF�ṹ��Ĵ�С���������ֵĳ��ȣ�
				int vSize = impTableSize + iatSize+ strlen(funcName)+strlen(dllName)+4;
				printf("================�����ģ���������========\n");

				int addBufferSize = 0;
				//������ӽں���µ�buffer
				char* addBuffer = add_section(fBuff, fBuffSize, "mDLL", vSize, &addBufferSize);
				_IMAGE_DOS_HEADER* addSectionDosHeader = (_IMAGE_DOS_HEADER*)addBuffer;
				_IMAGE_NT_HEADERS* addSectionNtHeader = (_IMAGE_NT_HEADERS*)(addBuffer + addSectionDosHeader->e_lfanew);
				IMAGE_DATA_DIRECTORY*  addSecDataTable = addSectionNtHeader->OptionalHeader.DataDirectory;
				//��ȡ�����ṹָ��  ��Ŀ¼������ĵڶ���λ�� 
				char* addSecImpTable = addBuffer + _rva_to_foa(addBuffer, addSecDataTable[1].VirtualAddress);
				
				
				//�����ڵ��ļ�ƫ��
				char* addSectionFoaOffset = addBuffer + fBuffSize;

				//��ȡ�����ṹָ���׸� foa��ַ
				_IMAGE_IMPORT_DESCRIPTOR*  impTableDes = (_IMAGE_IMPORT_DESCRIPTOR*)addSectionFoaOffset;

				//���½��п���������
				_mem_copy(addSecImpTable, addSectionFoaOffset, impTableSize - 2*sizeof(_IMAGE_IMPORT_DESCRIPTOR));
				//�����������ļ��е�ƫ��
				DWORD funNameFoaOffset = fBuffSize + impTableSize + 18;
				
				//�ڵ�����ṹĩβ ���IAT���INT�� ����8���ֽ� ����_IMAGE_BOUND_FORWARDER_REF�ṹ��  �������������ַ���
				_mem_copy((char*)funcName, addBuffer+ funNameFoaOffset,strlen(funcName)+1);
				//�������Ƶ�rva��ַ
				DWORD funNameRvaOffset = _foa_to_rva(addBuffer, funNameFoaOffset-2);
				IMAGE_IMPORT_BY_NAME* boundRef = (IMAGE_IMPORT_BY_NAME*)	(addBuffer + fBuffSize + impTableSize + 16);
				
				boundRef->Hint = 0x38F;

				//����DLL���� ������λ���� �����ڵ��ļ�buffer + ԭ�ļ���С+ ���е����ṹ���С + INT���IAT���С����ռ8���ֽڣ� + �ṹ��_IMAGE_BOUND_FORWARDER_REF+�����ӳ���+��β1��'\0'��
				_mem_copy((char*)dllName, addBuffer + funNameFoaOffset +strlen(funcName)+1,strlen(dllName)+1);

				//��INT �� IAT����� �������Ƶĵ�ַ
		  *((DWORD*)(addSectionFoaOffset + impTableSize)) = funNameRvaOffset;
				*((DWORD*)(addSectionFoaOffset + impTableSize+8)) = funNameRvaOffset;
				/*		*((DWORD*)(addSectionFoaOffset + impTableSize)) = 0x8000038f;
				*((DWORD*)(addSectionFoaOffset + impTableSize + 8)) = 0x8000038f;*/


				//ָ��INT���rva��ַ
				impTableDes[impTableCount - 2].OriginalFirstThunk = _foa_to_rva(addBuffer, fBuffSize+ impTableSize);
				//ָ��IAT���rva��ַ
				impTableDes[impTableCount - 2].FirstThunk = _foa_to_rva(addBuffer, fBuffSize + impTableSize+8);

				impTableDes[impTableCount - 2].TimeDateStamp = 0;
				impTableDes[impTableCount - 2].Name = _foa_to_rva(addBuffer, funNameFoaOffset + strlen(funcName) + 1);

				addSecDataTable[1].VirtualAddress = _foa_to_rva(addBuffer, fBuffSize);
				addSecDataTable[1].Size += sizeof(_IMAGE_IMPORT_DESCRIPTOR);
				_write_restore_to_file(addBufferSize, addBuffer);


		}
		//ʹ�õ��ǰ󶨵����
		else {
				printf("ʹ�õİ󶨵����");
		}

}

