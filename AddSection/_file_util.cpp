// ConsoleApplication2.cpp: �������̨Ӧ�ó������ڵ㡣
//
#pragma once
#include "stdafx.h"

wchar_t* _file_path;

//�ڴ�����С
DWORD  _mem_Alignment;
//�����ڴ澵���ַ
DWORD _image_base;
//�����ڴ������ƫ�Ƶ�ַ
DWORD _image_buffer_oep;
//����_image_buffer�����ڴ��С
DWORD _size_image;
//��ȡ����ͷ��������Ϣ��С
DWORD _headers;
DWORD _file_Alignment;
DWORD sectionNum;
char _shell_code[18] = { 0x6A,0x0,0x6A,0x0,0x6A,0x0,0x6A,0x0,0xE8,0x0,0x0,0x0,0x0,0xE9,0x0,0x0,0x0,0x0};

typedef int (*lpFuncDiv)(int, int);

void _run_app()
{
		setlocale(LC_ALL, "Chinese-simplified");
		//��ȡ�ļ�����
		TCHAR * fileName = chooseFile(0);

	char* _f_buff = NULL;

		//��ȡ�ļ����ڴ���
		int fileSize = _read_file_to_fbuff(fileName, &_f_buff);

	moveImpTab(_f_buff, fileSize,"Dll1.dll");
	//	printImpTab(_f_buff, fileSize);
		//�ƶ�������
		//	move_exp_table(_f_buff, fileSize);

		//�ƶ��ض�λ��
	//	char* relocationFileBuff = move_relocation_table(_f_buff, fileSize);
		//char* _i_buff = NULL;

		//int _i_buff_size = _read_fbuff_to_ibuff(_f_buff, &_i_buff);

		//	print_exp_table(_f_buff, _i_buff);
		//

	//print_relocation(relocationFileBuff);
		////_write_restore_to_file(_i_buff_size, _i_buff);
		////addShellCode(_f_buff,fileSize);
		////_add_section(_f_buff, fileSize);

//	changeImageBase(_f_buff, fileSize);

		Sleep(3000);
		exit(0);
		return;
}

/*���ļ�����ӽ�*/
void _add_section_and_shell_code(char * _f_buff, int _f_buffer_size)
{
		_IMAGE_DOS_HEADER* _dos_header = (_IMAGE_DOS_HEADER*)_f_buff;

		//����PE���λ��ƫ��
		DWORD _pe_sign_offset = _dos_header->e_lfanew;

		printf("PESignature-OFFSET : %08X\n", _pe_sign_offset);

		_IMAGE_NT_HEADERS* _nt_header = (_IMAGE_NT_HEADERS *)(_f_buff + _pe_sign_offset);
 
		//����PE���λ��
		printf("PESignature : %s\n", (char*)(&_nt_header->Signature));


		printf("Machine ([0~any cpu][14c-386~cpu]):%X\n", _nt_header->FileHeader.Machine);

		//������
		sectionNum = _nt_header->FileHeader.NumberOfSections;
		printf("NumberOfSections:%X\n", sectionNum);

		//�����ѡPEͷ��С
		WORD SizeOfOpeHead = _nt_header->FileHeader.SizeOfOptionalHeader;


		printf("																						OptionalHeader (FILE) 																					\n");

		//�ڴ�����С
		_mem_Alignment = _nt_header->OptionalHeader.SectionAlignment;
		//�����ڴ澵���ַ
		_image_base = _nt_header->OptionalHeader.ImageBase;
		printf("ImageBase:%X\n", _image_base);
		//�����ڴ������ƫ�Ƶ�ַ
		_image_buffer_oep = _nt_header->OptionalHeader.AddressOfEntryPoint;
		//����_image_buffer�����ڴ��С
		_size_image = _nt_header->OptionalHeader.SizeOfImage;
		//��ȡ����ͷ��������Ϣ��С
		_headers = _nt_header->OptionalHeader.SizeOfHeaders;
		_file_Alignment = _nt_header->OptionalHeader.FileAlignment;
		printf("AddressOfEntryPoint:%X\n", _image_buffer_oep);
		printf("SectionAlignment:%X\n", _mem_Alignment);
		printf("FileAlignment:%X\n", _file_Alignment);

		printf("SizeOfImage:%X\n", _size_image);
		printf("SizeOfHeaders:%X\n", _headers);

		//�����׼PEͷ��С
		size_t fSize = sizeof(_nt_header->FileHeader);
		//�������׵�ַ = PE���+��׼PEͷ��С+��ѡPEͷ��С
		char* sHeaderAddr = ((char*)(_nt_header)) + fSize + SizeOfOpeHead + sizeof(_nt_header->Signature);

		//ת��Ϊָ�������� �ṹ��ָ��
		_IMAGE_SECTION_HEADER* _section_header = (_IMAGE_SECTION_HEADER*)sHeaderAddr;


		sectionTostring(_section_header, sectionNum);

		//ȡ�����һ������������Ϣ
		_IMAGE_SECTION_HEADER _last_section = _section_header[sectionNum - 1];
		// �����ڴ����쳤�� = �ڴ�ƫ��+�ļ����볤�� 
		SIZE_T fileBufferSize = _last_section.VirtualAddress + (_last_section.SizeOfRawData / _mem_Alignment+(_last_section.SizeOfRawData % _mem_Alignment==0?0:1))*_mem_Alignment;


		//ȡ����ѡPEͷ�е� �ڴ澵���С�������ֵ���ڼ�����ģ�����ƫ��+�ڴ���룩��ʹ�ô�ֵ��Ϊ imagebuffer�Ĵ�С
		fileBufferSize = _size_image > fileBufferSize ? _size_image : fileBufferSize;
	char*	_add_sections =	(char*)(&(_section_header[sectionNum]));




	DWORD  _header_surplus = (_add_sections - _f_buff) +sizeof(_IMAGE_SECTION_HEADER);
	//���Ҫ�ӵĽڴ��� ��һ�����ļ���ƫ�ƣ�˵��û�п��в�λ��� �ڵ�������Ϣ
	if (_header_surplus > _section_header[0].PointerToRawData)
	{
			printf("û�п��в�λ������ӽڵ�������Ϣ");
			return;
	}
	//������һ�ڵ�������Ϣ ����������
  _section_header[sectionNum] = _section_header[0];

		_IMAGE_SECTION_HEADER* _add_section_header = &_section_header[sectionNum];


	//��ȡ���һ�������ļ��е�ĩβ��ַ
	DWORD _add_sec_pToRavData = _last_section.PointerToRawData + _last_section.SizeOfRawData;
	//Ҫ���ӵ�shellcode ����Ϊ�ļ�����ǰ�����ǳ���
	DWORD _shell_code_size = sizeof(_shell_code);
	//Ҫ���ӵ�shellcode �Ľڰ��ļ������Ĵ�С
	DWORD _add_section_sizeOfRavData = (_shell_code_size / _file_Alignment + (_shell_code_size % _file_Alignment == 0 ? 0 : 1))*_file_Alignment;
	
	/**��������ڵ�������Ϣ*/
	CONST char* _add_section_name = ".ESET\0\0\0";
	_mem_copy((char*)_add_section_name, (char*)_add_section_header, 8);
	//�������������ڴ�������ĳߴ��С ���ļ����������ڴ���룬��������ڴ�����С�����ڴ����
	DWORD  _add_section_virtual_size=(_add_section_sizeOfRavData / _mem_Alignment + (_add_section_sizeOfRavData % _mem_Alignment== 0 ? 0 : 1))*_mem_Alignment;
	_add_section_header->Misc.VirtualSize = _add_section_virtual_size;
	//�����ڵ��ļ�ƫ�� Ϊ���һ���ڵ�ĩβ��ַ
	_add_section_header->PointerToRawData = _add_sec_pToRavData;
	//�����ڵ��ļ�����
	_add_section_header->SizeOfRawData = _add_section_sizeOfRavData;

	DWORD _last_section_virtual_size = (_last_section.SizeOfRawData / _mem_Alignment + (_last_section.SizeOfRawData %_mem_Alignment == 0 ? 0 : 1))*_mem_Alignment;

	//�����ڵ��ڴ�ƫ�� ���� ���һ���ڵ��ڴ�ƫ��+ �ڴ������������ڴ��С
	DWORD _add_section_virtual_addr = _last_section.VirtualAddress + _last_section_virtual_size;

	//���������ڵ��ڴ�ƫ�Ƶ�ַ
	_add_section_header->VirtualAddress = _add_section_virtual_addr;
	//�޸�ԭ�ȵĽ����� + 1
	_nt_header->FileHeader.NumberOfSections = _nt_header->FileHeader.NumberOfSections + 1;
	//�޸ĳ�����ڵ�ַ Ϊ�����ڵ��ڴ�ƫ�Ƶ�ַ - imagebase
	_nt_header->OptionalHeader.AddressOfEntryPoint = _add_section_virtual_addr;
	//�޸��ڴ��ܴ�С �����������ڴ��С ���� ԭ�ȵ��ڴ��ܴ�С
	_nt_header->OptionalHeader.SizeOfImage = _add_section_virtual_size + _nt_header->OptionalHeader.SizeOfImage;

	//���������ں������filebuffer ��С
	DWORD _add_section_file_buffer_size = _add_sec_pToRavData + _add_section_sizeOfRavData;
	//����һ�������Ľ� ����Ĵ�С����ԭ�ļ�buffer ���������У�Ȼ���ٿ��������ڵĴ��뼰������Ϣ
	char* _add_section_file_buffer = new char[_add_section_file_buffer_size];
	memset(_add_section_file_buffer, 0, _add_section_file_buffer_size);
	//�������ڵ���Ϣ�޸���ɣ���ԭfile_buffer������ ���������ں�� file_buffer��
	_mem_copy(_f_buff, _add_section_file_buffer, _f_buffer_size);


	HMODULE  hmodule =LoadLibraryA("USER32.DLL");
	//��̬��ȡҪ��ת��messagebox�ĵ�ַ
	DWORD _target_message_box_addr = (DWORD)GetProcAddress(hmodule, "MessageBoxA");

	//callָ��Ĵ��� = Ŀ���ַ - ���е�ַ
	DWORD _call_encode = _target_message_box_addr - (_image_base + _add_section_virtual_addr + 13 );
	//jmp ָ��Ĵ��� = Ŀ���ַ - ���е�ַ
	DWORD _jmp_encode =  _image_buffer_oep - (_add_section_virtual_addr + 18);

	*((DWORD*)(_shell_code + 9)) = _call_encode;
	*((DWORD*)(_shell_code + 14)) = _jmp_encode;
	//����shellcode�������ڵĴ��뵽��file buffer�У�
	_mem_copy(_shell_code,_add_section_file_buffer+ _add_sec_pToRavData,_shell_code_size);






		/*����ͷ����Ϣ�� �������ַ�ʽ������
		1.ȡ����ѡPEͷ�е� header��С���� _nt_header->OptionalHeader.SizeOfHeaders
		2.�жϵ�һ���ڵ��ļ�ƫ��λ�� _section_header[0].PointerToRawData
		*/



	_write_restore_to_file(_add_section_file_buffer_size, _add_section_file_buffer);
		return;
}





/*��ȡ�ļ����ڴ���*/
int  _read_file_to_fbuff(TCHAR* _file_path,char** _f_buffer)
{
		//��ʼ���ļ�ָ�룬��ȡexe·��
		FILE *fileRead;
		int readAble = _wfopen_s(&fileRead, _file_path, L"rb");

		if (readAble) {
				printf(" - file stream not open !");
				return 0;
		}
		wprintf(L"_file_name: - %s\n", _file_path);
		//��ȡ�ļ���С
		fseek(fileRead, 0, SEEK_END); //��λ���ļ�ĩ

		long fileSize = ftell(fileRead);

		fseek(fileRead, 0, SEEK_SET);

		//�����ļ���С������
		char* _f_buff = new char[fileSize];
		*_f_buffer = _f_buff;
		fread(_f_buff, fileSize, 1,  fileRead);

		//�ر� �����д����
		fclose(fileRead);
		return fileSize;
}
/*���������ڴ�״̬ д��Ӳ��*/
void _write_restore_to_file(int _ibuff_size, char* _i_buff)
{

		//_call_fn(_image_buffer_image_buffer_oep);

		wprintf(L"\n\n%s \n�ļ������ڴ�����,�Ƿ�д��Ӳ��(Y/N):", _file_path);
		delete _file_path;
		//�����û�����
_getInput_:
		int _input_char = _getch();
		if (_input_char == 'n' || _input_char == 'N') {
				printf("\n\n		program will exit					\n");
				Sleep(3000);
				return;
		}
		if (_input_char != 'Y' && _input_char != 'y') {
				printf("\nPlease re-enter ��\n");
				goto _getInput_;
		}
		TCHAR* _save_f_name = chooseFile(1);
		wprintf(L"\nwill save file to: \n-> %s \n", _save_f_name);

		FILE* fileWrite;
		int writeAble = _wfopen_s(&fileWrite, _save_f_name, L"wb+");
		if (writeAble) {
				printf("\n- get write stream fail!");
		}
		fwrite(_i_buff, sizeof(char), _ibuff_size, fileWrite);
		//ˢ�»�����
		fflush(fileWrite);

		fclose(fileWrite);
		printf("\n- save file over program will exit! ");
		Sleep(3000);
}
/*�ڴ��������shell code �޸ĳ�����ڵ�ַ*/
void addShellCode(char * _f_buff,int _f_buffer_size)
{

		_IMAGE_DOS_HEADER* _dos_header = (_IMAGE_DOS_HEADER*)_f_buff;

		//����PE���λ��ƫ��
		DWORD _pe_sign_offset = _dos_header->e_lfanew;

		printf("PESignature-OFFSET : %08X\n", _pe_sign_offset);

		_IMAGE_NT_HEADERS* _nt_header = (_IMAGE_NT_HEADERS *)(_f_buff + _pe_sign_offset);

		//����PE���λ��
		printf("PESignature : %s\n", (char*)(&_nt_header->Signature));


		printf("Machine ([0~any cpu][14c-386~cpu]):%X\n", _nt_header->FileHeader.Machine);

		//������
		 sectionNum = _nt_header->FileHeader.NumberOfSections;
		printf("NumberOfSections:%X\n", sectionNum);

		//�����ѡPEͷ��С
		WORD SizeOfOpeHead = _nt_header->FileHeader.SizeOfOptionalHeader;


		printf("																						OptionalHeader (FILE) 																					\n");

		//�ڴ�����С
		_mem_Alignment = _nt_header->OptionalHeader.SectionAlignment;
		//�����ڴ澵���ַ
		 _image_base = _nt_header->OptionalHeader.ImageBase;
		printf("ImageBase:%X\n", _image_base);
		//�����ڴ������ƫ�Ƶ�ַ
		_image_buffer_oep = _nt_header->OptionalHeader.AddressOfEntryPoint;
		//����_image_buffer�����ڴ��С
		_size_image = _nt_header->OptionalHeader.SizeOfImage;
		//��ȡ����ͷ��������Ϣ��С
		_headers = _nt_header->OptionalHeader.SizeOfHeaders;
		_file_Alignment = _nt_header->OptionalHeader.FileAlignment;
		printf("AddressOfEntryPoint:%X\n", _image_buffer_oep);
		printf("SectionAlignment:%X\n", _mem_Alignment);
		printf("FileAlignment:%X\n", _file_Alignment);

		printf("SizeOfImage:%X\n", _size_image);
		printf("SizeOfHeaders:%X\n", _headers);

		//�����׼PEͷ��С
		size_t fSize = sizeof(_nt_header->FileHeader);
		//�������׵�ַ = PE���+��׼PEͷ��С+��ѡPEͷ��С
		char* sHeaderAddr = ((char*)(_nt_header)) + fSize + SizeOfOpeHead + sizeof(_nt_header->Signature);

		//ת��Ϊָ�������� �ṹ��ָ��
		_IMAGE_SECTION_HEADER* _section_header = (_IMAGE_SECTION_HEADER*)sHeaderAddr;


		sectionTostring(_section_header, sectionNum);

		//ȡ�����һ������������Ϣ
		_IMAGE_SECTION_HEADER _last_section = _section_header[sectionNum - 1];
		// �����ڴ����쳤�� = �ڴ�ƫ��+�ļ����볤�� 
		SIZE_T fileBufferSize = _last_section.VirtualAddress + (_last_section.SizeOfRawData / _mem_Alignment + (_last_section.SizeOfRawData % _mem_Alignment == 0 ? 0 : 1))*_mem_Alignment;

		//ȡ����ѡPEͷ�е� �ڴ澵���С�������ֵ���ڼ�����ģ�����ƫ��+�ڴ���룩��ʹ�ô�ֵ��Ϊ imagebuffer�Ĵ�С
		fileBufferSize = _size_image > fileBufferSize ? _size_image : fileBufferSize;


		DWORD  _rva=0;
		for (size_t i = 0; i < sectionNum; i++)
		{
				//ȡ�������ڴ��е�ƫ��
				DWORD _vAddr = _section_header[i].VirtualAddress;
				//�ļ���ƫ��
				DWORD _point_section = _section_header[i].PointerToRawData;
				//�ļ��ж����Ĵ�С
				DWORD _size_section = _section_header[i].SizeOfRawData;
				//�ļ�����ǰ�Ĵ�С
				DWORD PhysicalAddress = _section_header[i].Misc.PhysicalAddress;

				if (PhysicalAddress > _size_section || ((_size_section - PhysicalAddress) >_file_Alignment))
				{
						printf("������Ч��win32 ����");
						return;
				}
				DWORD _section_margin = _size_section - PhysicalAddress;

				int _shell_code_size = sizeof(_shell_code);

				if (_section_margin < _shell_code_size) {
						printf("%sû�п���λ��.",_section_header[i].Name);
						break;
				}
				//�ļ������_shell_code���� foa ��ַ
				DWORD _current_section_end = _point_section + _size_section-18;
				//�ļ������_shell_code����ת����� rva ��ַ
				 
				_rva =  _foa_to_rva(_f_buff,_current_section_end);

				//��̬��ȡmessagebox��ַ

				HMODULE hmodle = LoadLibraryA("User32.dll");
				DWORD _dynamic_addr =(DWORD) GetProcAddress(hmodle, "MessageBoxA");
				//call �����Ӳ���� =   Ŀ�꺯����ַ -  call ָ����һ��ָ���ַ
				DWORD _call_msgbox_encode = _dynamic_addr - (_rva + 13);

				*((DWORD*)(_shell_code + 9)) = _call_msgbox_encode;



				/*ԭ�ȳ�����ڵ�ַ*/
				DWORD _source_oep = _image_base + _image_buffer_oep;
				/*jmp �����Ӳ���� =   Ŀ���ַ -  jmp ָ�����е�ַ*/
				DWORD _jmp_next_encode = _source_oep - _rva - _shell_code_size;


				*((DWORD*)(_shell_code + 14)) = _jmp_next_encode;
				/*����shell_code��file_buffer��*/
				_mem_copy((char*)_shell_code, _f_buff + _current_section_end, _shell_code_size);

				break;
		}
		/*����ͷ����Ϣ�� �������ַ�ʽ������
		1.ȡ����ѡPEͷ�е� header��С���� _nt_header->OptionalHeader.SizeOfHeaders
		2.�жϵ�һ���ڵ��ļ�ƫ��λ�� _section_header[0].PointerToRawData
		*/

		_nt_header->OptionalHeader.AddressOfEntryPoint = _rva-_image_base;


		wprintf(L"shellcode������,�Ƿ�д��Ӳ��(Y/N):");
		//�����û�����
_getInput_:
		int _input_char = _getch();
		if (_input_char == 'n' || _input_char == 'N') {
				printf("\n\n		program will exit					\n");
				Sleep(3000);
				return;
		}
		if (_input_char != 'Y' && _input_char != 'y') {
				printf("\nPlease re-enter ��\n");
				goto _getInput_;
		}

		TCHAR* _save_f_name = chooseFile(1);
		wprintf(L"\nwill save file to: \n-> %s \n", _save_f_name);

		FILE* fileWrite;
		int writeAble = _wfopen_s(&fileWrite, _save_f_name, L"wb+");
		if (writeAble) {
				printf("\n- get write stream fail!");
		}
		fwrite(_f_buff, sizeof(char), _f_buffer_size, fileWrite);
		//ˢ�»�����
		fflush(fileWrite);

		fclose(fileWrite);
		printf("\n- save file over program will exit! ");
		Sleep(3000);
		return ;

}

/*�ļ�ƫ�Ƶ�ַ ת��Ϊ �ڴ��ַƫ��*/
DWORD _foa_to_rva(char* _f_buff, DWORD _foa)
{
		_IMAGE_DOS_HEADER* _dos_header = (_IMAGE_DOS_HEADER*)_f_buff;

		//����PE���λ��ƫ��
		DWORD _pe_sign_offset = _dos_header->e_lfanew;
		_IMAGE_NT_HEADERS* _nt_header = (_IMAGE_NT_HEADERS *)(_f_buff + _pe_sign_offset);
		//������
		sectionNum = _nt_header->FileHeader.NumberOfSections;

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
		for (size_t i = 0; i < sectionNum; i++)
		{
				//ȡ�������ڴ��е�ƫ��
				DWORD _vAddr = _section_header[i].VirtualAddress;
				//��ǰ���ļ�����ʼƫ�Ƶ�ַ
				DWORD _point_section = _section_header[i].PointerToRawData;
				//�ļ��ж����Ĵ�С
				DWORD _size_section = _section_header[i].SizeOfRawData;
				//�ļ��е�ǰ�ڵĽ�����ַ
				DWORD _foa_end = _point_section + _size_section;
				//����ļ���ַ �����ļ�ƫ�Ʋ���С�� �ļ�ƫ��+�ļ����룬��ô��ַ�ڵ�ǰ����
				if (_foa >= _point_section && _foa < _foa_end)
				{
					return 	_vAddr + (_foa - _point_section);
				}
		}
}
/* �ڴ��ַƫ�� ת��Ϊ �ļ�ƫ�Ƶ�ַ */
DWORD _rva_to_foa(char* _f_buff, DWORD _rva)
{
		_IMAGE_DOS_HEADER* _dos_header = (_IMAGE_DOS_HEADER*)_f_buff;

		//����PE���λ��ƫ��
		DWORD _pe_sign_offset = _dos_header->e_lfanew;
		_IMAGE_NT_HEADERS* _nt_header = (_IMAGE_NT_HEADERS *)(_f_buff + _pe_sign_offset);
		//������
		sectionNum = _nt_header->FileHeader.NumberOfSections;

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



		for (size_t i = 0; i < sectionNum; i++)
		{
				//ȡ�������ڴ��е�ƫ��
				DWORD _vAddr = _section_header[i].VirtualAddress;
				//�ļ���ƫ��
				DWORD _point_section = _section_header[i].PointerToRawData;
				//�ļ��ж����Ĵ�С
				DWORD _size_section = _section_header[i].SizeOfRawData;
				//��ǰ�����ڴ��ж����Ĵ�С
				DWORD _current_section_mem_size = (_size_section / _mem_Alignment + (_size_section % _mem_Alignment == 0 ? 0 : 1))*_mem_Alignment;

			
				//����ļ���ַ �����ļ�ƫ�Ʋ���С�� �ļ�ƫ��+�ļ����룬��ô��ַ�ڵ�ǰ����
				if (_rva >= _vAddr && _rva < _vAddr + _current_section_mem_size)
				{
						return 	_point_section + (_rva - _vAddr);
				}
		}

		if (_rva >0 && _rva<_section_header[0].PointerToRawData)
		{
				return _rva;
		}
		return 0;
}
/*��Ӳ��״̬ת��Ϊ�ڴ�״̬ - �ļ����ڴ�������״̬�����ļ�����   ��Ϊfilebuffer -> imagebuffer*/
int 	_read_fbuff_to_ibuff(char* _f_buff, char** _i_buff)
{

		_IMAGE_DOS_HEADER* _dos_header = (_IMAGE_DOS_HEADER*)_f_buff;

		//����PE���λ��ƫ��
		DWORD _pe_sign_offset = _dos_header->e_lfanew;

		printf("PESignature-OFFSET : %08X\n", _pe_sign_offset);

		_IMAGE_NT_HEADERS* _nt_header = (_IMAGE_NT_HEADERS *)(_f_buff + _pe_sign_offset);

		//����PE���λ��
		printf("PESignature : %s\n", (char*)(&_nt_header->Signature));


		printf("Machine ([0~any cpu][14c-386~cpu]):%X\n", _nt_header->FileHeader.Machine);

		//������
		WORD sectionNum = _nt_header->FileHeader.NumberOfSections;
		printf("NumberOfSections:%X\n", sectionNum);

		//�����ѡPEͷ��С
		WORD SizeOfOpeHead = _nt_header->FileHeader.SizeOfOptionalHeader;


		printf("																						OptionalHeader (FILE) 																					\n");

		//�ڴ�����С
		   _mem_Alignment = _nt_header->OptionalHeader.SectionAlignment;
		//�����ڴ澵���ַ
		  _image_base = _nt_header->OptionalHeader.ImageBase;
		printf("ImageBase:%X\n", _image_base);
		//�����ڴ������ƫ�Ƶ�ַ
		  _image_buffer_oep = _nt_header->OptionalHeader.AddressOfEntryPoint;
		//����_image_buffer�����ڴ��С
		  _size_image = _nt_header->OptionalHeader.SizeOfImage;
		//��ȡ����ͷ��������Ϣ��С
		  _headers = _nt_header->OptionalHeader.SizeOfHeaders;
		  _file_Alignment = _nt_header->OptionalHeader.FileAlignment;
		printf("AddressOfEntryPoint:%X\n", _image_buffer_oep);
		printf("SectionAlignment:%X\n", _mem_Alignment);
		printf("FileAlignment:%X\n", _file_Alignment);

		printf("SizeOfImage:%X\n",_size_image);
		printf("SizeOfHeaders:%X\n", _headers);

		//�����׼PEͷ��С
		size_t fSize = sizeof(_nt_header->FileHeader);
		//�������׵�ַ = PE���+��׼PEͷ��С+��ѡPEͷ��С
		char* sHeaderAddr = ((char*)(_nt_header)) + fSize + SizeOfOpeHead + sizeof(_nt_header->Signature);

		//ת��Ϊָ�������� �ṹ��ָ��
		_IMAGE_SECTION_HEADER* _section_header = (_IMAGE_SECTION_HEADER*)sHeaderAddr;


		sectionTostring(_section_header, sectionNum);

		//ȡ�����һ������������Ϣ
		_IMAGE_SECTION_HEADER _last_section = _section_header[sectionNum - 1];
		/*�жϹ���Ҫ�����ڴ���볤��*/
		int _size_ = _last_section.SizeOfRawData / _mem_Alignment;
		_size_=(_size_ + (_last_section.SizeOfRawData % _mem_Alignment == 0 ? 0 : 1))*_mem_Alignment;


		// �����ڴ����쳤�� = �ڴ�ƫ��+�ļ����볤�� 
		SIZE_T fileBufferSize = _last_section.VirtualAddress + _size_;

		
		//ȡ����ѡPEͷ�е� �ڴ澵���С�������ֵ���ڼ�����ģ�����ƫ��+�ڴ���룩��ʹ�ô�ֵ��Ϊ imagebuffer�Ĵ�С
		fileBufferSize = _size_image > fileBufferSize ? _size_image : fileBufferSize;
		
		//�����ڴ澵�� ����ִ���ļ�
	*_i_buff = new char[fileBufferSize];

	char* _temp_ibuff = *_i_buff;
		//��ʼ��Ϊ0
		memset(_temp_ibuff, 0, fileBufferSize);


		//�޸��ļ�����Ϊ�ڴ����
		_nt_header->OptionalHeader.FileAlignment = _section_header[0].VirtualAddress;
		_nt_header->OptionalHeader.SizeOfHeaders = _section_header[0].VirtualAddress;

		for (size_t i = 0; i < sectionNum; i++)
		{
				//ȡ�������ڴ��е�ƫ��
				DWORD _vAddr = _section_header[i].VirtualAddress;
				DWORD _point_section = _section_header[i].PointerToRawData;
				DWORD _size_section = _section_header[i].SizeOfRawData;

				if (_size_section % _mem_Alignment != 0) {
						//���ڴ���� ��
						_section_header[i].SizeOfRawData = (_size_section / _mem_Alignment + (_size_section % _mem_Alignment==0?0:1))*_mem_Alignment;
				}
				_section_header[i].PointerToRawData = _vAddr;
				//���������� �ļ�ƫ�ƺͶ����Ĵ�С
				_mem_copy(_f_buff + _point_section, _temp_ibuff + _vAddr, _size_section);
				//oep��ڵ�
				if(_image_buffer_oep>_section_header[i].VirtualAddress && _image_buffer_oep < (_section_header[i].VirtualAddress + _section_header[i].SizeOfRawData))
				{
						printf("��ڵ�OEP�ڵ�%d����,����Ϊ[%s],��ַΪ%0X", i + 1, _section_header[i].Name, _image_buffer_oep);
				}
		}
		/*����ͷ����Ϣ�� �������ַ�ʽ������
		1.ȡ����ѡPEͷ�е� header��С���� _nt_header->OptionalHeader.SizeOfHeaders
		2.�жϵ�һ���ڵ��ļ�ƫ��λ�� _section_header[0].PointerToRawData
		*/

		DWORD  _headers_offset = _section_header[0].PointerToRawData;
		_mem_copy(_f_buff,_temp_ibuff, _headers_offset);

		return fileBufferSize;
}




/**
		*�����ַ���,��source������target ,������СΪsize
		*/
void _mem_copy(char* source, char* target,int size) {
		char* temp_source = source;
		char* temp_target = target;

		int i = 0;
		while (i < size) {
				*temp_target = *temp_source;
				temp_target++;
				temp_source++;
				i++;
		}
}
void sectionTostring(_IMAGE_SECTION_HEADER* _section_header, DWORD  sectionNum) {
		//����ÿ������ռ�ֽ���
		size_t  sSize = sizeof(_IMAGE_SECTION_HEADER);
		//�����ֿ������µ������� ��ӽ�����ǡ���������Ҳ���������Ǵ��󣬼��·���whileѭ��
		byte _section_name[9] = { 0 };

		for (size_t i = 0; i < sectionNum; i++)
		{
				int index = 0;
				byte* _t_name = (byte*)(&_section_header[i]);
				//��������Ҳ���������Ǵ���
				while (index < 8) {
						_section_name[index] = *_t_name;
						_t_name++;
						index++;
				}
				printf("���������������������������%d������ ��ʼ�����������������������\n", i + 1);
				printf("name:%s\n", _section_name);
				printf("VirtualSize:%08X\n", _section_header[i].Misc.VirtualSize);
				printf("VirtualAddress:%08X\n", _section_header[i].VirtualAddress);
				printf("SizeOfRawData:%08X\n", _section_header[i].SizeOfRawData);
				printf("PointerToRawData:%08X\n", _section_header[i].PointerToRawData);
				printf("PointerToRelocations:%08X\n", _section_header[i].PointerToRelocations);
				printf("PointerToLineNumbers:%08X\n", _section_header[i].PointerToLinenumbers);

				printf("NumberOfRelocations:%04X\n", _section_header[i].NumberOfRelocations);
				printf("NumberOfLinenumbers:%04X\n", _section_header[i].NumberOfLinenumbers);
				printf("Characteristics:%08X\n", _section_header[i].Characteristics);
				printf("������������������������������������%d������ ����������������������������������\n", i + 1);
				//��ǰ��ָ��+�ڴ�С = ָ����һ���ڵĵ�ַ

		}

}
/*0��ȡ�ļ�,��0Ϊ�����ļ�*/
TCHAR* chooseFile(int operation)
{

loop:
		OPENFILENAME optionFile = { 0 };
		TCHAR filePathBuffer[MAX_PATH] = { 0 };//���ڽ����ļ���                                                            
		optionFile.lStructSize = sizeof(OPENFILENAME);//�ṹ���С                                                           
		optionFile.hwndOwner = NULL;//ӵ���Ŵ��ھ����ΪNULL��ʾ�Ի����Ƿ�ģ̬�ģ�ʵ��Ӧ����һ�㶼Ҫ��������                                            
		optionFile.lpstrFilter = TEXT("ѡ���ļ�*.*\0*.*\0��ִ�г���*.exe\0*.exe\0��̬���ӿ��ļ�*.dll\0*.dll\0\0 ");//���ù���                                
		optionFile.nFilterIndex = 1;//����������                                                                             
		optionFile.lpstrFile = filePathBuffer;//���շ��ص��ļ�����ע���һ���ַ���ҪΪNULL                                                    
		optionFile.nMaxFile = sizeof(filePathBuffer);//����������                                                               
		optionFile.lpstrInitialDir = NULL;//��ʼĿ¼ΪĬ��                                                                     
		optionFile.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;//�ļ���Ŀ¼������ڣ�����ֻ��ѡ��                  

		if (operation) {
				optionFile.lpstrTitle = TEXT("����дһ���ļ�����");//ʹ��ϵͳĬ�ϱ������ռ��� 
				if (!GetSaveFileName(&optionFile))
				{
						MessageBox(NULL, TEXT("����дһ���ļ�����"), NULL, MB_ICONERROR);
						goto loop;
				}
		}
		else {
				optionFile.lpstrTitle = TEXT("��ѡ��һ����ִ�г���");//ʹ��ϵͳĬ�ϱ������ռ���
				if (!GetOpenFileName(&optionFile))
				{
						MessageBox(NULL, TEXT("��ѡ��һ����ִ�г���"), NULL, MB_ICONERROR);
						goto loop;
				}
		}
		wchar_t * filePath = new wchar_t[MAX_PATH];
		_file_path = filePath;
		wchar_t * tempBuffer = filePathBuffer;
		wchar_t * tempfilePath = filePath;

		while (*tempBuffer != '\0\0')
		{
				*tempfilePath++ = *tempBuffer++;
		}
		*tempfilePath = '\0\0';
		return filePath;
}


////���ֽڵ�ַת��Ϊchar
//char* wideCharToChar(TCHAR* wideChar)
//{
//		int length = 0;
//		TCHAR* temp = wideChar;
//		while (*temp != '\0\0') {
//				length++;
//				temp++;
//		}
//		char* _array = new char[length + 1];
//		memset(_array, 0, length + 1);
//		while (*wideChar != '\0\0') {
//				*_array = *((char*)wideChar);
//				wideChar++;
//				_array++;
//		}
//		return _array - length;
//}