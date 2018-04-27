// ConsoleApplication2.cpp: 定义控制台应用程序的入口点。
//
#pragma once
#include "stdafx.h"

wchar_t* _file_path;

//内存对齐大小
DWORD  _mem_Alignment;
//程序内存镜像基址
DWORD _image_base;
//程序内存中入口偏移地址
DWORD _image_buffer_oep;
//计算_image_buffer所需内存大小
DWORD _size_image;
//获取所有头部描述信息大小
DWORD _headers;
DWORD _file_Alignment;
DWORD sectionNum;
char _shell_code[18] = { 0x6A,0x0,0x6A,0x0,0x6A,0x0,0x6A,0x0,0xE8,0x0,0x0,0x0,0x0,0xE9,0x0,0x0,0x0,0x0};

typedef int (*lpFuncDiv)(int, int);

void _run_app()
{
		setlocale(LC_ALL, "Chinese-simplified");
		//获取文件名称
		TCHAR * fileName = chooseFile(0);

	char* _f_buff = NULL;

		//读取文件到内存中
		int fileSize = _read_file_to_fbuff(fileName, &_f_buff);

	moveImpTab(_f_buff, fileSize,"Dll1.dll");
	//	printImpTab(_f_buff, fileSize);
		//移动导出表
		//	move_exp_table(_f_buff, fileSize);

		//移动重定位表
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

/*在文件中添加节*/
void _add_section_and_shell_code(char * _f_buff, int _f_buffer_size)
{
		_IMAGE_DOS_HEADER* _dos_header = (_IMAGE_DOS_HEADER*)_f_buff;

		//读出PE存放位置偏移
		DWORD _pe_sign_offset = _dos_header->e_lfanew;

		printf("PESignature-OFFSET : %08X\n", _pe_sign_offset);

		_IMAGE_NT_HEADERS* _nt_header = (_IMAGE_NT_HEADERS *)(_f_buff + _pe_sign_offset);
 
		//计算PE标记位置
		printf("PESignature : %s\n", (char*)(&_nt_header->Signature));


		printf("Machine ([0~any cpu][14c-386~cpu]):%X\n", _nt_header->FileHeader.Machine);

		//节数量
		sectionNum = _nt_header->FileHeader.NumberOfSections;
		printf("NumberOfSections:%X\n", sectionNum);

		//计算可选PE头大小
		WORD SizeOfOpeHead = _nt_header->FileHeader.SizeOfOptionalHeader;


		printf("																						OptionalHeader (FILE) 																					\n");

		//内存对齐大小
		_mem_Alignment = _nt_header->OptionalHeader.SectionAlignment;
		//程序内存镜像基址
		_image_base = _nt_header->OptionalHeader.ImageBase;
		printf("ImageBase:%X\n", _image_base);
		//程序内存中入口偏移地址
		_image_buffer_oep = _nt_header->OptionalHeader.AddressOfEntryPoint;
		//计算_image_buffer所需内存大小
		_size_image = _nt_header->OptionalHeader.SizeOfImage;
		//获取所有头部描述信息大小
		_headers = _nt_header->OptionalHeader.SizeOfHeaders;
		_file_Alignment = _nt_header->OptionalHeader.FileAlignment;
		printf("AddressOfEntryPoint:%X\n", _image_buffer_oep);
		printf("SectionAlignment:%X\n", _mem_Alignment);
		printf("FileAlignment:%X\n", _file_Alignment);

		printf("SizeOfImage:%X\n", _size_image);
		printf("SizeOfHeaders:%X\n", _headers);

		//计算标准PE头大小
		size_t fSize = sizeof(_nt_header->FileHeader);
		//节数组首地址 = PE标记+标准PE头大小+可选PE头大小
		char* sHeaderAddr = ((char*)(_nt_header)) + fSize + SizeOfOpeHead + sizeof(_nt_header->Signature);

		//转换为指向节数组的 结构体指针
		_IMAGE_SECTION_HEADER* _section_header = (_IMAGE_SECTION_HEADER*)sHeaderAddr;


		sectionTostring(_section_header, sectionNum);

		//取出最后一个节区描述信息
		_IMAGE_SECTION_HEADER _last_section = _section_header[sectionNum - 1];
		// 所需内存拉伸长度 = 内存偏移+文件对齐长度 
		SIZE_T fileBufferSize = _last_section.VirtualAddress + (_last_section.SizeOfRawData / _mem_Alignment+(_last_section.SizeOfRawData % _mem_Alignment==0?0:1))*_mem_Alignment;


		//取出可选PE头中的 内存镜像大小，如果此值大于计算出的（最后节偏移+内存对齐）则使用此值做为 imagebuffer的大小
		fileBufferSize = _size_image > fileBufferSize ? _size_image : fileBufferSize;
	char*	_add_sections =	(char*)(&(_section_header[sectionNum]));




	DWORD  _header_surplus = (_add_sections - _f_buff) +sizeof(_IMAGE_SECTION_HEADER);
	//如果要加的节大于 第一节在文件的偏移，说明没有空闲部位添加 节的描述信息
	if (_header_surplus > _section_header[0].PointerToRawData)
	{
			printf("没有空闲部位可以添加节的描述信息");
			return;
	}
	//拷贝第一节的描述信息 到新增节中
  _section_header[sectionNum] = _section_header[0];

		_IMAGE_SECTION_HEADER* _add_section_header = &_section_header[sectionNum];


	//获取最后一个节在文件中的末尾地址
	DWORD _add_sec_pToRavData = _last_section.PointerToRawData + _last_section.SizeOfRawData;
	//要增加的shellcode 长度为文件对齐前的真是长度
	DWORD _shell_code_size = sizeof(_shell_code);
	//要增加的shellcode 的节按文件对齐后的大小
	DWORD _add_section_sizeOfRavData = (_shell_code_size / _file_Alignment + (_shell_code_size % _file_Alignment == 0 ? 0 : 1))*_file_Alignment;
	
	/**添加新增节的描述信息*/
	CONST char* _add_section_name = ".ESET\0\0\0";
	_mem_copy((char*)_add_section_name, (char*)_add_section_header, 8);
	//计算新增节在内存中所需的尺寸大小 ，文件对齐后除以内存对齐，如果不够内存对齐大小，按内存对齐
	DWORD  _add_section_virtual_size=(_add_section_sizeOfRavData / _mem_Alignment + (_add_section_sizeOfRavData % _mem_Alignment== 0 ? 0 : 1))*_mem_Alignment;
	_add_section_header->Misc.VirtualSize = _add_section_virtual_size;
	//新增节的文件偏移 为最后一个节的末尾地址
	_add_section_header->PointerToRawData = _add_sec_pToRavData;
	//新增节的文件对齐
	_add_section_header->SizeOfRawData = _add_section_sizeOfRavData;

	DWORD _last_section_virtual_size = (_last_section.SizeOfRawData / _mem_Alignment + (_last_section.SizeOfRawData %_mem_Alignment == 0 ? 0 : 1))*_mem_Alignment;

	//新增节的内存偏移 等于 最后一个节的内存偏移+ 内存拉伸后所需的内存大小
	DWORD _add_section_virtual_addr = _last_section.VirtualAddress + _last_section_virtual_size;

	//计算新增节的内存偏移地址
	_add_section_header->VirtualAddress = _add_section_virtual_addr;
	//修改原先的节数量 + 1
	_nt_header->FileHeader.NumberOfSections = _nt_header->FileHeader.NumberOfSections + 1;
	//修改程序入口地址 为新增节的内存偏移地址 - imagebase
	_nt_header->OptionalHeader.AddressOfEntryPoint = _add_section_virtual_addr;
	//修改内存总大小 新增节所需内存大小 加上 原先的内存总大小
	_nt_header->OptionalHeader.SizeOfImage = _add_section_virtual_size + _nt_header->OptionalHeader.SizeOfImage;

	//计算新增节后所需的filebuffer 大小
	DWORD _add_section_file_buffer_size = _add_sec_pToRavData + _add_section_sizeOfRavData;
	//拷贝一份新增的节 所需的大小，将原文件buffer 拷贝到其中，然后再拷贝新增节的代码及描述信息
	char* _add_section_file_buffer = new char[_add_section_file_buffer_size];
	memset(_add_section_file_buffer, 0, _add_section_file_buffer_size);
	//将新增节的信息修改完成，将原file_buffer拷贝到 加上新增节后的 file_buffer中
	_mem_copy(_f_buff, _add_section_file_buffer, _f_buffer_size);


	HMODULE  hmodule =LoadLibraryA("USER32.DLL");
	//动态获取要跳转的messagebox的地址
	DWORD _target_message_box_addr = (DWORD)GetProcAddress(hmodule, "MessageBoxA");

	//call指令的代码 = 目标地址 - 下行地址
	DWORD _call_encode = _target_message_box_addr - (_image_base + _add_section_virtual_addr + 13 );
	//jmp 指令的代码 = 目标地址 - 下行地址
	DWORD _jmp_encode =  _image_buffer_oep - (_add_section_virtual_addr + 18);

	*((DWORD*)(_shell_code + 9)) = _call_encode;
	*((DWORD*)(_shell_code + 14)) = _jmp_encode;
	//拷贝shellcode（新增节的代码到新file buffer中）
	_mem_copy(_shell_code,_add_section_file_buffer+ _add_sec_pToRavData,_shell_code_size);






		/*拷贝头部信息， 后面两种方式都可以
		1.取出可选PE头中的 header大小描述 _nt_header->OptionalHeader.SizeOfHeaders
		2.判断第一个节的文件偏移位置 _section_header[0].PointerToRawData
		*/



	_write_restore_to_file(_add_section_file_buffer_size, _add_section_file_buffer);
		return;
}





/*读取文件到内存中*/
int  _read_file_to_fbuff(TCHAR* _file_path,char** _f_buffer)
{
		//初始化文件指针，读取exe路径
		FILE *fileRead;
		int readAble = _wfopen_s(&fileRead, _file_path, L"rb");

		if (readAble) {
				printf(" - file stream not open !");
				return 0;
		}
		wprintf(L"_file_name: - %s\n", _file_path);
		//获取文件大小
		fseek(fileRead, 0, SEEK_END); //定位到文件末

		long fileSize = ftell(fileRead);

		fseek(fileRead, 0, SEEK_SET);

		//创建文件大小的数组
		char* _f_buff = new char[fileSize];
		*_f_buffer = _f_buff;
		fread(_f_buff, fileSize, 1,  fileRead);

		//关闭 读入和写出流
		fclose(fileRead);
		return fileSize;
}
/*将拉伸后的内存状态 写入硬盘*/
void _write_restore_to_file(int _ibuff_size, char* _i_buff)
{

		//_call_fn(_image_buffer_image_buffer_oep);

		wprintf(L"\n\n%s \n文件已在内存拉伸,是否写入硬盘(Y/N):", _file_path);
		delete _file_path;
		//接收用户输入
_getInput_:
		int _input_char = _getch();
		if (_input_char == 'n' || _input_char == 'N') {
				printf("\n\n		program will exit					\n");
				Sleep(3000);
				return;
		}
		if (_input_char != 'Y' && _input_char != 'y') {
				printf("\nPlease re-enter ：\n");
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
		//刷新缓冲区
		fflush(fileWrite);

		fclose(fileWrite);
		printf("\n- save file over program will exit! ");
		Sleep(3000);
}
/*在代码中添加shell code 修改程序入口地址*/
void addShellCode(char * _f_buff,int _f_buffer_size)
{

		_IMAGE_DOS_HEADER* _dos_header = (_IMAGE_DOS_HEADER*)_f_buff;

		//读出PE存放位置偏移
		DWORD _pe_sign_offset = _dos_header->e_lfanew;

		printf("PESignature-OFFSET : %08X\n", _pe_sign_offset);

		_IMAGE_NT_HEADERS* _nt_header = (_IMAGE_NT_HEADERS *)(_f_buff + _pe_sign_offset);

		//计算PE标记位置
		printf("PESignature : %s\n", (char*)(&_nt_header->Signature));


		printf("Machine ([0~any cpu][14c-386~cpu]):%X\n", _nt_header->FileHeader.Machine);

		//节数量
		 sectionNum = _nt_header->FileHeader.NumberOfSections;
		printf("NumberOfSections:%X\n", sectionNum);

		//计算可选PE头大小
		WORD SizeOfOpeHead = _nt_header->FileHeader.SizeOfOptionalHeader;


		printf("																						OptionalHeader (FILE) 																					\n");

		//内存对齐大小
		_mem_Alignment = _nt_header->OptionalHeader.SectionAlignment;
		//程序内存镜像基址
		 _image_base = _nt_header->OptionalHeader.ImageBase;
		printf("ImageBase:%X\n", _image_base);
		//程序内存中入口偏移地址
		_image_buffer_oep = _nt_header->OptionalHeader.AddressOfEntryPoint;
		//计算_image_buffer所需内存大小
		_size_image = _nt_header->OptionalHeader.SizeOfImage;
		//获取所有头部描述信息大小
		_headers = _nt_header->OptionalHeader.SizeOfHeaders;
		_file_Alignment = _nt_header->OptionalHeader.FileAlignment;
		printf("AddressOfEntryPoint:%X\n", _image_buffer_oep);
		printf("SectionAlignment:%X\n", _mem_Alignment);
		printf("FileAlignment:%X\n", _file_Alignment);

		printf("SizeOfImage:%X\n", _size_image);
		printf("SizeOfHeaders:%X\n", _headers);

		//计算标准PE头大小
		size_t fSize = sizeof(_nt_header->FileHeader);
		//节数组首地址 = PE标记+标准PE头大小+可选PE头大小
		char* sHeaderAddr = ((char*)(_nt_header)) + fSize + SizeOfOpeHead + sizeof(_nt_header->Signature);

		//转换为指向节数组的 结构体指针
		_IMAGE_SECTION_HEADER* _section_header = (_IMAGE_SECTION_HEADER*)sHeaderAddr;


		sectionTostring(_section_header, sectionNum);

		//取出最后一个节区描述信息
		_IMAGE_SECTION_HEADER _last_section = _section_header[sectionNum - 1];
		// 所需内存拉伸长度 = 内存偏移+文件对齐长度 
		SIZE_T fileBufferSize = _last_section.VirtualAddress + (_last_section.SizeOfRawData / _mem_Alignment + (_last_section.SizeOfRawData % _mem_Alignment == 0 ? 0 : 1))*_mem_Alignment;

		//取出可选PE头中的 内存镜像大小，如果此值大于计算出的（最后节偏移+内存对齐）则使用此值做为 imagebuffer的大小
		fileBufferSize = _size_image > fileBufferSize ? _size_image : fileBufferSize;


		DWORD  _rva=0;
		for (size_t i = 0; i < sectionNum; i++)
		{
				//取出节在内存中的偏移
				DWORD _vAddr = _section_header[i].VirtualAddress;
				//文件中偏移
				DWORD _point_section = _section_header[i].PointerToRawData;
				//文件中对齐后的大小
				DWORD _size_section = _section_header[i].SizeOfRawData;
				//文件对齐前的大小
				DWORD PhysicalAddress = _section_header[i].Misc.PhysicalAddress;

				if (PhysicalAddress > _size_section || ((_size_section - PhysicalAddress) >_file_Alignment))
				{
						printf("不是有效的win32 程序");
						return;
				}
				DWORD _section_margin = _size_section - PhysicalAddress;

				int _shell_code_size = sizeof(_shell_code);

				if (_section_margin < _shell_code_size) {
						printf("%s没有空闲位置.",_section_header[i].Name);
						break;
				}
				//文件中添加_shell_code代码 foa 地址
				DWORD _current_section_end = _point_section + _size_section-18;
				//文件中添加_shell_code代码转换后的 rva 地址
				 
				_rva =  _foa_to_rva(_f_buff,_current_section_end);

				//动态获取messagebox地址

				HMODULE hmodle = LoadLibraryA("User32.dll");
				DWORD _dynamic_addr =(DWORD) GetProcAddress(hmodle, "MessageBoxA");
				//call 后面的硬编码 =   目标函数地址 -  call 指令下一行指令地址
				DWORD _call_msgbox_encode = _dynamic_addr - (_rva + 13);

				*((DWORD*)(_shell_code + 9)) = _call_msgbox_encode;



				/*原先程序入口地址*/
				DWORD _source_oep = _image_base + _image_buffer_oep;
				/*jmp 后面的硬编码 =   目标地址 -  jmp 指令下行地址*/
				DWORD _jmp_next_encode = _source_oep - _rva - _shell_code_size;


				*((DWORD*)(_shell_code + 14)) = _jmp_next_encode;
				/*拷贝shell_code到file_buffer中*/
				_mem_copy((char*)_shell_code, _f_buff + _current_section_end, _shell_code_size);

				break;
		}
		/*拷贝头部信息， 后面两种方式都可以
		1.取出可选PE头中的 header大小描述 _nt_header->OptionalHeader.SizeOfHeaders
		2.判断第一个节的文件偏移位置 _section_header[0].PointerToRawData
		*/

		_nt_header->OptionalHeader.AddressOfEntryPoint = _rva-_image_base;


		wprintf(L"shellcode添加完成,是否写入硬盘(Y/N):");
		//接收用户输入
_getInput_:
		int _input_char = _getch();
		if (_input_char == 'n' || _input_char == 'N') {
				printf("\n\n		program will exit					\n");
				Sleep(3000);
				return;
		}
		if (_input_char != 'Y' && _input_char != 'y') {
				printf("\nPlease re-enter ：\n");
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
		//刷新缓冲区
		fflush(fileWrite);

		fclose(fileWrite);
		printf("\n- save file over program will exit! ");
		Sleep(3000);
		return ;

}

/*文件偏移地址 转换为 内存地址偏移*/
DWORD _foa_to_rva(char* _f_buff, DWORD _foa)
{
		_IMAGE_DOS_HEADER* _dos_header = (_IMAGE_DOS_HEADER*)_f_buff;

		//读出PE存放位置偏移
		DWORD _pe_sign_offset = _dos_header->e_lfanew;
		_IMAGE_NT_HEADERS* _nt_header = (_IMAGE_NT_HEADERS *)(_f_buff + _pe_sign_offset);
		//节数量
		sectionNum = _nt_header->FileHeader.NumberOfSections;

		//计算可选PE头大小
		WORD SizeOfOpeHead = _nt_header->FileHeader.SizeOfOptionalHeader;
		//内存对齐大小
		_mem_Alignment = _nt_header->OptionalHeader.SectionAlignment;
		//程序内存镜像基址
		_image_base = _nt_header->OptionalHeader.ImageBase;

		//程序内存中入口偏移地址
		_image_buffer_oep = _nt_header->OptionalHeader.AddressOfEntryPoint;
		//计算_image_buffer所需内存大小
		_size_image = _nt_header->OptionalHeader.SizeOfImage;
		//获取所有头部描述信息大小
		_headers = _nt_header->OptionalHeader.SizeOfHeaders;
		_file_Alignment = _nt_header->OptionalHeader.FileAlignment;

		//计算标准PE头大小
		size_t fSize = sizeof(_nt_header->FileHeader);
		//节数组首地址 = PE标记+标准PE头大小+可选PE头大小
		char* sHeaderAddr = ((char*)(_nt_header)) + fSize + SizeOfOpeHead + sizeof(_nt_header->Signature);

		//转换为指向节数组的 结构体指针
		_IMAGE_SECTION_HEADER* _section_header = (_IMAGE_SECTION_HEADER*)sHeaderAddr;
		for (size_t i = 0; i < sectionNum; i++)
		{
				//取出节在内存中的偏移
				DWORD _vAddr = _section_header[i].VirtualAddress;
				//当前节文件中起始偏移地址
				DWORD _point_section = _section_header[i].PointerToRawData;
				//文件中对齐后的大小
				DWORD _size_section = _section_header[i].SizeOfRawData;
				//文件中当前节的结束地址
				DWORD _foa_end = _point_section + _size_section;
				//如果文件地址 大于文件偏移并且小于 文件偏移+文件对齐，那么地址在当前节中
				if (_foa >= _point_section && _foa < _foa_end)
				{
					return 	_vAddr + (_foa - _point_section);
				}
		}
}
/* 内存地址偏移 转换为 文件偏移地址 */
DWORD _rva_to_foa(char* _f_buff, DWORD _rva)
{
		_IMAGE_DOS_HEADER* _dos_header = (_IMAGE_DOS_HEADER*)_f_buff;

		//读出PE存放位置偏移
		DWORD _pe_sign_offset = _dos_header->e_lfanew;
		_IMAGE_NT_HEADERS* _nt_header = (_IMAGE_NT_HEADERS *)(_f_buff + _pe_sign_offset);
		//节数量
		sectionNum = _nt_header->FileHeader.NumberOfSections;

		//计算可选PE头大小
		WORD SizeOfOpeHead = _nt_header->FileHeader.SizeOfOptionalHeader;
		//内存对齐大小
		_mem_Alignment = _nt_header->OptionalHeader.SectionAlignment;
		//程序内存镜像基址
		_image_base = _nt_header->OptionalHeader.ImageBase;

		//程序内存中入口偏移地址
		_image_buffer_oep = _nt_header->OptionalHeader.AddressOfEntryPoint;
		//计算_image_buffer所需内存大小
		_size_image = _nt_header->OptionalHeader.SizeOfImage;
		//获取所有头部描述信息大小
		_headers = _nt_header->OptionalHeader.SizeOfHeaders;
		_file_Alignment = _nt_header->OptionalHeader.FileAlignment;

		//计算标准PE头大小
		size_t fSize = sizeof(_nt_header->FileHeader);
		//节数组首地址 = PE标记+标准PE头大小+可选PE头大小
		char* sHeaderAddr = ((char*)(_nt_header)) + fSize + SizeOfOpeHead + sizeof(_nt_header->Signature);

		//转换为指向节数组的 结构体指针
		_IMAGE_SECTION_HEADER* _section_header = (_IMAGE_SECTION_HEADER*)sHeaderAddr;



		for (size_t i = 0; i < sectionNum; i++)
		{
				//取出节在内存中的偏移
				DWORD _vAddr = _section_header[i].VirtualAddress;
				//文件中偏移
				DWORD _point_section = _section_header[i].PointerToRawData;
				//文件中对齐后的大小
				DWORD _size_section = _section_header[i].SizeOfRawData;
				//当前节在内存中对齐后的大小
				DWORD _current_section_mem_size = (_size_section / _mem_Alignment + (_size_section % _mem_Alignment == 0 ? 0 : 1))*_mem_Alignment;

			
				//如果文件地址 大于文件偏移并且小于 文件偏移+文件对齐，那么地址在当前节中
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
/*将硬盘状态转换为内存状态 - 文件在内存中拉伸状态，将文件对齐   称为filebuffer -> imagebuffer*/
int 	_read_fbuff_to_ibuff(char* _f_buff, char** _i_buff)
{

		_IMAGE_DOS_HEADER* _dos_header = (_IMAGE_DOS_HEADER*)_f_buff;

		//读出PE存放位置偏移
		DWORD _pe_sign_offset = _dos_header->e_lfanew;

		printf("PESignature-OFFSET : %08X\n", _pe_sign_offset);

		_IMAGE_NT_HEADERS* _nt_header = (_IMAGE_NT_HEADERS *)(_f_buff + _pe_sign_offset);

		//计算PE标记位置
		printf("PESignature : %s\n", (char*)(&_nt_header->Signature));


		printf("Machine ([0~any cpu][14c-386~cpu]):%X\n", _nt_header->FileHeader.Machine);

		//节数量
		WORD sectionNum = _nt_header->FileHeader.NumberOfSections;
		printf("NumberOfSections:%X\n", sectionNum);

		//计算可选PE头大小
		WORD SizeOfOpeHead = _nt_header->FileHeader.SizeOfOptionalHeader;


		printf("																						OptionalHeader (FILE) 																					\n");

		//内存对齐大小
		   _mem_Alignment = _nt_header->OptionalHeader.SectionAlignment;
		//程序内存镜像基址
		  _image_base = _nt_header->OptionalHeader.ImageBase;
		printf("ImageBase:%X\n", _image_base);
		//程序内存中入口偏移地址
		  _image_buffer_oep = _nt_header->OptionalHeader.AddressOfEntryPoint;
		//计算_image_buffer所需内存大小
		  _size_image = _nt_header->OptionalHeader.SizeOfImage;
		//获取所有头部描述信息大小
		  _headers = _nt_header->OptionalHeader.SizeOfHeaders;
		  _file_Alignment = _nt_header->OptionalHeader.FileAlignment;
		printf("AddressOfEntryPoint:%X\n", _image_buffer_oep);
		printf("SectionAlignment:%X\n", _mem_Alignment);
		printf("FileAlignment:%X\n", _file_Alignment);

		printf("SizeOfImage:%X\n",_size_image);
		printf("SizeOfHeaders:%X\n", _headers);

		//计算标准PE头大小
		size_t fSize = sizeof(_nt_header->FileHeader);
		//节数组首地址 = PE标记+标准PE头大小+可选PE头大小
		char* sHeaderAddr = ((char*)(_nt_header)) + fSize + SizeOfOpeHead + sizeof(_nt_header->Signature);

		//转换为指向节数组的 结构体指针
		_IMAGE_SECTION_HEADER* _section_header = (_IMAGE_SECTION_HEADER*)sHeaderAddr;


		sectionTostring(_section_header, sectionNum);

		//取出最后一个节区描述信息
		_IMAGE_SECTION_HEADER _last_section = _section_header[sectionNum - 1];
		/*判断共需要几个内存对齐长度*/
		int _size_ = _last_section.SizeOfRawData / _mem_Alignment;
		_size_=(_size_ + (_last_section.SizeOfRawData % _mem_Alignment == 0 ? 0 : 1))*_mem_Alignment;


		// 所需内存拉伸长度 = 内存偏移+文件对齐长度 
		SIZE_T fileBufferSize = _last_section.VirtualAddress + _size_;

		
		//取出可选PE头中的 内存镜像大小，如果此值大于计算出的（最后节偏移+内存对齐）则使用此值做为 imagebuffer的大小
		fileBufferSize = _size_image > fileBufferSize ? _size_image : fileBufferSize;
		
		//创建内存镜像 填充可执行文件
	*_i_buff = new char[fileBufferSize];

	char* _temp_ibuff = *_i_buff;
		//初始化为0
		memset(_temp_ibuff, 0, fileBufferSize);


		//修改文件对齐为内存对齐
		_nt_header->OptionalHeader.FileAlignment = _section_header[0].VirtualAddress;
		_nt_header->OptionalHeader.SizeOfHeaders = _section_header[0].VirtualAddress;

		for (size_t i = 0; i < sectionNum; i++)
		{
				//取出节在内存中的偏移
				DWORD _vAddr = _section_header[i].VirtualAddress;
				DWORD _point_section = _section_header[i].PointerToRawData;
				DWORD _size_section = _section_header[i].SizeOfRawData;

				if (_size_section % _mem_Alignment != 0) {
						//按内存对齐 ，
						_section_header[i].SizeOfRawData = (_size_section / _mem_Alignment + (_size_section % _mem_Alignment==0?0:1))*_mem_Alignment;
				}
				_section_header[i].PointerToRawData = _vAddr;
				//拷贝节区中 文件偏移和对齐后的大小
				_mem_copy(_f_buff + _point_section, _temp_ibuff + _vAddr, _size_section);
				//oep入口点
				if(_image_buffer_oep>_section_header[i].VirtualAddress && _image_buffer_oep < (_section_header[i].VirtualAddress + _section_header[i].SizeOfRawData))
				{
						printf("入口点OEP在第%d节中,名称为[%s],地址为%0X", i + 1, _section_header[i].Name, _image_buffer_oep);
				}
		}
		/*拷贝头部信息， 后面两种方式都可以
		1.取出可选PE头中的 header大小描述 _nt_header->OptionalHeader.SizeOfHeaders
		2.判断第一个节的文件偏移位置 _section_header[0].PointerToRawData
		*/

		DWORD  _headers_offset = _section_header[0].PointerToRawData;
		_mem_copy(_f_buff,_temp_ibuff, _headers_offset);

		return fileBufferSize;
}




/**
		*拷贝字符串,从source拷贝到target ,拷贝大小为size
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
		//计算每个节所占字节数
		size_t  sSize = sizeof(_IMAGE_SECTION_HEADER);
		//节名字拷贝到新的数组中 添加结束标记。避免遍历找不到结束标记错误，见下方的while循环
		byte _section_name[9] = { 0 };

		for (size_t i = 0; i < sectionNum; i++)
		{
				int index = 0;
				byte* _t_name = (byte*)(&_section_header[i]);
				//避免遍历找不到结束标记错误
				while (index < 8) {
						_section_name[index] = *_t_name;
						_t_name++;
						index++;
				}
				printf("◇※◇※◇※◇※◇※◇※◇※◇※◇第%d个节区 开始◇※◇※◇※◇※◇※◇※◇※◇\n", i + 1);
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
				printf("◆※◆※◆※◆※◆※◆※◆※◆※◆第%d个节区 结束◆※◆※◆※◆※◆※◆※◆※◆\n", i + 1);
				//当前节指针+节大小 = 指向下一个节的地址

		}

}
/*0读取文件,非0为保存文件*/
TCHAR* chooseFile(int operation)
{

loop:
		OPENFILENAME optionFile = { 0 };
		TCHAR filePathBuffer[MAX_PATH] = { 0 };//用于接收文件名                                                            
		optionFile.lStructSize = sizeof(OPENFILENAME);//结构体大小                                                           
		optionFile.hwndOwner = NULL;//拥有着窗口句柄，为NULL表示对话框是非模态的，实际应用中一般都要有这个句柄                                            
		optionFile.lpstrFilter = TEXT("选择文件*.*\0*.*\0可执行程序*.exe\0*.exe\0动态链接库文件*.dll\0*.dll\0\0 ");//设置过滤                                
		optionFile.nFilterIndex = 1;//过滤器索引                                                                             
		optionFile.lpstrFile = filePathBuffer;//接收返回的文件名，注意第一个字符需要为NULL                                                    
		optionFile.nMaxFile = sizeof(filePathBuffer);//缓冲区长度                                                               
		optionFile.lpstrInitialDir = NULL;//初始目录为默认                                                                     
		optionFile.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;//文件、目录必须存在，隐藏只读选项                  

		if (operation) {
				optionFile.lpstrTitle = TEXT("请填写一个文件名称");//使用系统默认标题留空即可 
				if (!GetSaveFileName(&optionFile))
				{
						MessageBox(NULL, TEXT("请填写一个文件名称"), NULL, MB_ICONERROR);
						goto loop;
				}
		}
		else {
				optionFile.lpstrTitle = TEXT("请选择一个可执行程序");//使用系统默认标题留空即可
				if (!GetOpenFileName(&optionFile))
				{
						MessageBox(NULL, TEXT("请选择一个可执行程序"), NULL, MB_ICONERROR);
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


////宽字节地址转换为char
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