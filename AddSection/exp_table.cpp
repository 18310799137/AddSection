#include "stdafx.h"
#include "exp_table.h"
#include <Windows.h>
/*打印导出表 导入表*/
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

/*打印导出表*/
void print_exp_table(char * _file_buff, char * _image_buff)
{
		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)_file_buff;

		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(_file_buff + _dos->e_lfanew);

		//导出 导入表数组偏移起始地址 
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		//导出表地址为数组第一个
		_IMAGE_EXPORT_DIRECTORY* exp_table = (_IMAGE_EXPORT_DIRECTORY *)((char*)  (_image_buff + _data_table->VirtualAddress));




		printf("\nBase : %d\n", exp_table->Base);
		printf("\nName : %d\n", exp_table->Name);

		if(NULL!=exp_table){

										//创建函数表地址的指针
								char* _fun_table_rva_addr = (_image_buff + exp_table->AddressOfFunctions);

								printf("导出表函数的个数为:%d\n", exp_table->NumberOfFunctions);
								for (size_t i = 0; i < exp_table->NumberOfFunctions; i++)
								{ 
										//创建名字表地址的指针
										char* _name_table_rva_addr = (_image_buff + exp_table->AddressOfNames);
										 
										//创建序号表地址的指针
										char* _ordinals_table_rva_addr = (_image_buff + exp_table->AddressOfNameOrdinals);
										 
										DWORD _fun_rva_addr= *((DWORD*)(_fun_table_rva_addr));
										if (!_fun_rva_addr) {
												_fun_table_rva_addr += 4;
												continue;
										}
										for (size_t j = 0; j < exp_table->NumberOfNames; j++)
										{
												//获取序号的地址
												WORD  _ordinals = *((WORD*)_ordinals_table_rva_addr);
												//说明是按名字导出
												if (_ordinals == i) {
																_name_table_rva_addr += 4*j;
														//获取名字的地址
														DWORD  _name_rva_addr = *((DWORD*)_name_table_rva_addr);
														char* name = _image_buff + _name_rva_addr;
														//打印序号 - 名称 -函数地址
														printf("%d - %s - %X \n", i + exp_table->Base, name,_fun_rva_addr);
														goto _next;
												}
												_ordinals_table_rva_addr += 2;
										}
										//说明是按序号导出的 打印函数地址 - 函数序号
										printf("%d - $ - %X \n", i + exp_table->Base, _fun_rva_addr);
									
										_next:	_fun_table_rva_addr += 4;
								}
								//printf("导出表函数名称个数为:%d\n", exp_table->NumberOfNames);
								//				for (size_t i = 0; i < exp_table->NumberOfNames; i++)
								//				{
								//						//获取名字的地址
								//						DWORD  _name_rva_addr = *((DWORD*)_name_table_rva_addr);

								//				 	char* name =	_image_buff + _name_rva_addr;

								//						//获取序号的地址
								//						WORD  _ordinals = *((WORD*)_ordinals_table_rva_addr);
								//						//打印序号 - 名称
								//						printf("%d - %s\n", _ordinals, name);

								//						_ordinals_table_rva_addr += 2;

								//						_name_table_rva_addr += 4;
								//				}
		}
		else {
				printf("\n没有找到导出表\n");
		}
}


/*新增一个节,参数为  _file_buff-文件buffer name-节的名称 virtualSize-文件中对齐前的大小          参数_add_section_file_size新增节后的文件大小*/
char* add_section(char * _f_buff, int _file_buff_size,const char * name,int virtualSize,int* _add_section_file_size)
{

		_IMAGE_DOS_HEADER* _dos_header = (_IMAGE_DOS_HEADER*)_f_buff;
		//读出PE存放位置偏移
		DWORD _pe_sign_offset = _dos_header->e_lfanew;

		_IMAGE_NT_HEADERS* _nt_header = (_IMAGE_NT_HEADERS *)(_f_buff + _pe_sign_offset);

		//节数量
		WORD sectionNum = _nt_header->FileHeader.NumberOfSections;

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

		 
		/*判断共需要几个内存对齐长度*/
		int _add_section_need_size_ = virtualSize / _file_Alignment;
		_add_section_need_size_ = (_add_section_need_size_ + (virtualSize % _file_Alignment == 0 ? 0 : 1))*_file_Alignment;

		//开辟一个新的空间 所需的大小
		*_add_section_file_size = _file_buff_size + _add_section_need_size_;

		//开辟一个新的空间
		char* _file_buff = new char[*_add_section_file_size];
		memset(_file_buff, 0, *_add_section_file_size);


		//计算新增节在内存中所需大小
		int _add_section_need_virtual_size_ = virtualSize / _mem_Alignment;
		_add_section_need_virtual_size_ = (_add_section_need_virtual_size_ + (virtualSize % _mem_Alignment == 0 ? 0 : 1))*_mem_Alignment;
		//修改sizeofimage 为原先大小+新节的大小
 _nt_header->OptionalHeader.SizeOfImage = _size_image+ _add_section_need_virtual_size_;

	if (((char*)(&_section_header[sectionNum]) - _f_buff + sizeof(_IMAGE_SECTION_HEADER)) > _section_header[0].PointerToRawData) 
	{
			printf("没有足够的空间添加新节的描述信息");
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

		//导出 导入表数组偏移起始地址 
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		DWORD _virtual_addr = _data_table->VirtualAddress;

		//导出表地址为数组第一个
		_IMAGE_EXPORT_DIRECTORY* exp_table = (_IMAGE_EXPORT_DIRECTORY *)(_file_buff + _rva_to_foa(_file_buff, _virtual_addr));


		if (NULL != exp_table) {

			
				//计算导出表的函数的字节大小
				DWORD sizeOfFun = exp_table->NumberOfFunctions * 4;
				//计算名称表所需的字节大小
				DWORD sizeOfNm = exp_table->NumberOfNames * 4;
				//计算序号表所需的字节大小
				DWORD sizeOfOrdinals = exp_table->NumberOfNames * 2;


				//创建函数表地址的指针
				char* _fun_table_rva_addr = _file_buff + _rva_to_foa(_file_buff, exp_table->AddressOfFunctions);
				//创建名字表地址的指针
				char* _name_table_rva_addr = _file_buff + _rva_to_foa(_file_buff, exp_table->AddressOfNames);
				//创建序号表地址的指针
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
						//加上结尾字符'\0'
						sizeOfNameStr++;
						//指向名称表下一个地址
						_name_table_rva_addr += 4;
				}
				//导出表结构所占的字节数
				DWORD sizeOfexpTable = sizeof(_IMAGE_EXPORT_DIRECTORY);
				//移动整个导出表所需的字节数的大小
				DWORD _add_section_virtual_size = sizeOfFun + sizeOfNm + sizeOfOrdinals + sizeOfNameStr + sizeOfexpTable;

				int size = 0;
				//返回创建新节后的文件buffer
				char* _f_buff = add_section(_file_buff, _file_buff_size, ".exptab", _add_section_virtual_size, &size);


				_IMAGE_DOS_HEADER* _add_dos = (_IMAGE_DOS_HEADER*)_f_buff;

				_IMAGE_NT_HEADERS* _add_nt = (_IMAGE_NT_HEADERS*)(_f_buff + _add_dos->e_lfanew);

				//导出 导入表数组偏移起始地址 
				IMAGE_DATA_DIRECTORY*  _add_data_table = _add_nt->OptionalHeader.DataDirectory;
			//原先的导出表地址
				_IMAGE_EXPORT_DIRECTORY*  _original_exp_table = (_IMAGE_EXPORT_DIRECTORY*)(_f_buff + _rva_to_foa(_f_buff, _add_data_table->VirtualAddress));
	

				//新增节的文件偏移
				char* _add_section_addr = _f_buff + _file_buff_size;
				//拷贝导出表到新增节中   返回的新增节后的filebuffer + 原filebuffer的大小 就是新增节的文件偏移
				_mem_copy((char*)exp_table, _add_section_addr, sizeOfexpTable);
				//将移动后的导出表结构的rva地址 赋给 PE头部描述信息
				_add_data_table->VirtualAddress = _foa_to_rva(_f_buff, (DWORD)_file_buff_size);
				//开始拷贝导出表函数表中的数据
				_mem_copy(_fun_table_rva_addr, _add_section_addr + sizeOfexpTable, sizeOfFun);
				//新增节拷贝名字表的文件偏移
				char* _add_sec_name_addr = _add_section_addr + sizeOfexpTable + sizeOfFun;
				//开始拷贝导出表名字表中的数据
				_mem_copy(_name_table_rva_addr, _add_sec_name_addr, sizeOfNm);

				//开始拷贝导出表序号表中的数据
				_mem_copy(_ordinals_table_rva_addr, _add_sec_name_addr + sizeOfNm, sizeOfOrdinals);
				//拷贝完函数+导出表结构体+名称后在文件中的偏移
				char* _offset_copy_addr_end = _add_section_addr + sizeOfexpTable + sizeOfFun + sizeOfNm + sizeOfOrdinals;
				//创建新增节中 移动后的导出表地址的指针
				_IMAGE_EXPORT_DIRECTORY* _add_sec_exp = (_IMAGE_EXPORT_DIRECTORY*)_add_section_addr;
				//修复导出表中函数表地址
				_add_sec_exp->AddressOfFunctions = _foa_to_rva(_f_buff, (_add_section_addr-_f_buff + sizeOfexpTable));
				//修复导出表中名字表地址
				_add_sec_exp->AddressOfNames = _foa_to_rva(_f_buff, (_add_section_addr - _f_buff + sizeOfexpTable + sizeOfFun));
				//修复导出表中序号表地址
				_add_sec_exp->AddressOfNameOrdinals = _foa_to_rva(_f_buff, (_add_section_addr - _f_buff + sizeOfexpTable + sizeOfFun + sizeOfNm));

				//创建名字表地址的指针
				char* _add_name_table_rva_addr = _f_buff + _rva_to_foa(_f_buff, _original_exp_table->AddressOfNames);

				//循环修复导出表名字表中的地址编号
				DWORD* _add_sec_name_addr_point = (DWORD*)_add_sec_name_addr;
				for (size_t j = 0; j < exp_table->NumberOfNames; j++)
				{
						//创建指向原先名称表中字符串地址的foa指针
						char* _name_point = _f_buff + _rva_to_foa(_f_buff, *((DWORD*)_add_name_table_rva_addr));
						//将字符串拷贝的到的地址转换为rva 添加到名字表中
						*_add_sec_name_addr_point = _foa_to_rva(_f_buff,_offset_copy_addr_end - _f_buff);
						while (*_name_point != '\0')
						{
								//赋值字符串名字到 filebuffer的 新增节中
								*_offset_copy_addr_end = *_name_point;
								_offset_copy_addr_end++;
								_name_point++;
						}
						//加上结尾字符'\0'
						*_offset_copy_addr_end = '\0';
						_offset_copy_addr_end++;
						//指向原先导出表中名称表下一个地址
						_add_name_table_rva_addr += 4;
						_add_sec_name_addr_point++;
				}
				
				_write_restore_to_file(size, _f_buff);
		}
		else {
				printf("\n没有找到导出表\n");
		}
		return;
}











/*打印重定位表*/
void print_relocation(char * _f_buff)
{
		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)_f_buff;
		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(_f_buff + _dos->e_lfanew);
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		//创建重定位表的指针,也是重定位表数组的首个表地址
		IMAGE_BASE_RELOCATION* _first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(_f_buff + _rva_to_foa(_f_buff,_data_table[5].VirtualAddress));
		//计算重定位表的块数量
		int _lump_count = 0;
		while (_first_relocation_table_addr->SizeOfBlock && _first_relocation_table_addr->VirtualAddress)
		{
				printf("重定位表第%d块开始========================\n", ++_lump_count);
				DWORD block = _first_relocation_table_addr->SizeOfBlock;
				DWORD _virtual_addr = _first_relocation_table_addr->VirtualAddress;
				//计算每个重定位表中的每个块中所包含的地址数量
				size_t _addr_count = (block - sizeof(block) - sizeof(_virtual_addr)) / sizeof(WORD);
				printf("本块中共 %d个地址\n", _addr_count);
				//创建一个临时指针遍历每个块中的地址
				WORD* _temp_relocation = (WORD*)_first_relocation_table_addr;
				_temp_relocation += 4;
				for (size_t i = 0; i < _addr_count; i++)
				{
						WORD _relocation_addr_ = *_temp_relocation;
						//取出高四位的值，如果高四位等于三，则是有效的地址
						int _valid_flag = _relocation_addr_ >> 12;
						if (_valid_flag == 3)
						{
								DWORD valid_relocation_addr = _virtual_addr + (_relocation_addr_ & 0x0fff);
								printf("有效地址%2d: %XH Base的值为:%XH\n", i + 1, valid_relocation_addr, _virtual_addr);
						}
						else {
								printf("无效地址%2d: -  \t\t - \n", i + 1);
						}
						_temp_relocation += 1;
				}
				//指向下一个重定位表结构
				_first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(((char*)_first_relocation_table_addr) + block);

				printf("重定位表第%d块结束========================\n", _lump_count);
		}
		printf("重定位表共有%d块", _lump_count);
}



/*移动导出表*/
char* move_relocation_table(char * _file_buff,int _file_buff_size)
{

		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)_file_buff;
		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(_file_buff + _dos->e_lfanew);
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		//创建重定位表的指针,也是重定位表数组的首个表地址
		IMAGE_BASE_RELOCATION* _first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(_file_buff + _rva_to_foa(_file_buff,_data_table[5].VirtualAddress));
		//计算重定位表所需的字节大小,初始值8 用来填补 IMAGE_BASE_RELOCATION结束标记0
		int _byte_count = 8;
		while (_first_relocation_table_addr->SizeOfBlock && _first_relocation_table_addr->VirtualAddress)
		{
			
				DWORD block = _first_relocation_table_addr->SizeOfBlock;
				//计算重定位表所需的字节大小
				_byte_count += block;
				//指向下一个重定位表结构
				_first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(((char*)_first_relocation_table_addr) + block);

			
		}
	

		int _add_relocation_after_file_size = 0;
		char* _relocation_f_buff = add_section(_file_buff, _file_buff_size, "rloction", _byte_count,&_add_relocation_after_file_size);
		delete _file_buff;
		_IMAGE_DOS_HEADER* _relocation_dos = (_IMAGE_DOS_HEADER*)_relocation_f_buff;
		_IMAGE_NT_HEADERS* _relocation_nt = (_IMAGE_NT_HEADERS*)(_relocation_f_buff + _dos->e_lfanew);
		IMAGE_DATA_DIRECTORY*  _relocation_data_table = _relocation_nt->OptionalHeader.DataDirectory;
		//原先的重定位表文件偏移地址
		char* relocationFileOffset =_relocation_f_buff + _rva_to_foa(_relocation_f_buff, _relocation_data_table[5].VirtualAddress);
		//创建重定位表的指针,也是重定位表数组的首个表地址
		IMAGE_BASE_RELOCATION* _original_first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)relocationFileOffset;
		//获取新增节的文件偏移 做为挪动新的重定位表的偏移地址
		char* addSectionFileOffset =_relocation_f_buff + _file_buff_size;
		//创建一个临时指针 保存新增节的偏移地址
		char* tempAddSecionFileOffset = addSectionFileOffset;


		//计算重定位表的块数量
		int _lump_count = 0;

		while (_original_first_relocation_table_addr->SizeOfBlock && _original_first_relocation_table_addr->VirtualAddress)
		{
				printf("重定位表第%d块开始========================\n", ++_lump_count);
				DWORD block = _original_first_relocation_table_addr->SizeOfBlock;
				//将原先的重定位表的信息拷贝到新增节中
				_mem_copy(relocationFileOffset, addSectionFileOffset, block);
				


				//将原先重定位表的地址加上拷贝过的大小，指向将要拷贝的下一个重定位表的块头部位置
				relocationFileOffset += block;
				//将新增节的偏移地址加上拷贝过的大小，指向下一个要拷贝的位置
				addSectionFileOffset += block;
				
				//指向下一个重定位表结构
				_original_first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)relocationFileOffset;

				printf("重定位表第%d块结束========================\n", _lump_count);
		}
		//创建指向新增节 重定位表末尾 用来填补结束标记0
		IMAGE_BASE_RELOCATION* addSectionRelocationEnd= (IMAGE_BASE_RELOCATION*)addSectionFileOffset;
		addSectionRelocationEnd->SizeOfBlock = 0;
		addSectionRelocationEnd->VirtualAddress = 0;


		//修复原先重定位表，将重定位表的地址指向新增节中拷贝后的新重定位表地址
		_relocation_data_table[5].VirtualAddress =  _foa_to_rva(_relocation_f_buff, (DWORD)(tempAddSecionFileOffset - _relocation_f_buff));
		
		printf("重定位表共有%d块", _lump_count);
		_write_restore_to_file(_add_relocation_after_file_size, _relocation_f_buff);
		return _relocation_f_buff;
}
/*修改ImageBase后 修复重定位表*/
void changeImageBase(char * _f_buff, int _file_buff_size)
{ 
		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)_f_buff;
		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(_f_buff + _dos->e_lfanew);
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		//创建重定位表的指针,也是重定位表数组的首个表地址
		IMAGE_BASE_RELOCATION* _first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(_f_buff + _rva_to_foa(_f_buff, _data_table[5].VirtualAddress));


		DWORD  _image_base = _nt->OptionalHeader.ImageBase;
		_nt->OptionalHeader.ImageBase = _image_base + 0x100000;

		//计算重定位表的块数量
		int _lump_count = 0;
		while (_first_relocation_table_addr->SizeOfBlock && _first_relocation_table_addr->VirtualAddress)
		{
				printf("重定位表第%d块开始========================\n", ++_lump_count);
				DWORD block = _first_relocation_table_addr->SizeOfBlock;
				DWORD _virtual_addr = _first_relocation_table_addr->VirtualAddress;
				//计算每个重定位表中的每个块中所包含的地址数量
				size_t _addr_count = (block - sizeof(block) - sizeof(_virtual_addr)) / sizeof(WORD);
				printf("本块中共 %d个地址\n", _addr_count);
				//创建一个临时指针遍历每个块中的地址
				WORD* _temp_relocation = (WORD*)_first_relocation_table_addr;
				_temp_relocation += 4;
				for (size_t i = 0; i < _addr_count; i++)
				{
						WORD _relocation_addr_ = *_temp_relocation;
						//取出高四位的值，如果高四位等于三，则是有效的地址
						int _valid_flag = _relocation_addr_ >> 12;
						if (_valid_flag == 3)
						{
								DWORD valid_relocation_addr = _virtual_addr + (_relocation_addr_ & 0x0fff);
								char* _changeAddr = _f_buff+_rva_to_foa(_f_buff,valid_relocation_addr );
								DWORD _changeAddrNum = *((DWORD*)_changeAddr);
								*((DWORD*)_changeAddr) = _changeAddrNum + 0X100000;

								printf("有效地址%2d: %XH Base的值为:%XH \n", i + 1, valid_relocation_addr, _virtual_addr);
						}
						else {
								printf("无效地址%2d: -  \t\t - \n", i + 1);
						}
						_temp_relocation += 1;
				}
				//指向下一个重定位表结构
				_first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(((char*)_first_relocation_table_addr) + block);

				printf("重定位表第%d块结束========================\n", _lump_count);
		}
		printf("重定位表共有%d块", _lump_count);
		_write_restore_to_file(_file_buff_size, _f_buff);

}

/* 修复重定位表*/
void restoreTable(char * _f_buff)
{
		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)_f_buff;
		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(_f_buff + _dos->e_lfanew);
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		//创建重定位表的指针,也是重定位表数组的首个表地址
		IMAGE_BASE_RELOCATION* _first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(_f_buff + _rva_to_foa(_f_buff, _data_table[5].VirtualAddress));


		DWORD  _image_base = _nt->OptionalHeader.ImageBase;
		//ImageBase 的偏移量
		DWORD   _image_base_offset = ((DWORD)_f_buff - _image_base);
		//计算重定位表的块数量
		int _lump_count = 0;
		while (_first_relocation_table_addr->SizeOfBlock && _first_relocation_table_addr->VirtualAddress)
		{
				printf("重定位表第%d块开始========================\n", ++_lump_count);
				DWORD block = _first_relocation_table_addr->SizeOfBlock;
				DWORD _virtual_addr = _first_relocation_table_addr->VirtualAddress;
				//计算每个重定位表中的每个块中所包含的地址数量
				size_t _addr_count = (block - sizeof(block) - sizeof(_virtual_addr)) / sizeof(WORD);
				printf("本块中共 %d个地址\n", _addr_count);
				//创建一个临时指针遍历每个块中的地址
				WORD* _temp_relocation = (WORD*)_first_relocation_table_addr;
				_temp_relocation += 4;
				for (size_t i = 0; i < _addr_count; i++)
				{
						WORD _relocation_addr_ = *_temp_relocation;
						//取出高四位的值，如果高四位等于三，则是有效的地址
						int _valid_flag = _relocation_addr_ >> 12;
						if (_valid_flag == 3)
						{
								DWORD valid_relocation_addr = _virtual_addr + (_relocation_addr_ & 0x0fff);
								char* _changeAddr = _f_buff + _rva_to_foa(_f_buff, valid_relocation_addr);
								DWORD _changeAddrNum = *((DWORD*)_changeAddr);
								*((DWORD*)_changeAddr) = _changeAddrNum + _image_base_offset;

								printf("有效地址%2d: %XH Base的值为:%XH \n", i + 1, valid_relocation_addr, _virtual_addr);
						}
						else {
								printf("无效地址%2d: -  \t\t - \n", i + 1);
						}
						_temp_relocation += 1;
				}
				//指向下一个重定位表结构
				_first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(((char*)_first_relocation_table_addr) + block);

				printf("重定位表第%d块结束========================\n", _lump_count);
		}
		printf("重定位表共有%d块", _lump_count);

}

/* 修复重定位表 拉伸后的状态*/
void restoreTableIbuff(char * _i_buff)
{

		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)_i_buff;
		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(_i_buff + _dos->e_lfanew);
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		//创建重定位表的指针,也是重定位表数组的首个表地址
		IMAGE_BASE_RELOCATION* _first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(_i_buff +   _data_table[5].VirtualAddress );


		DWORD  _image_base = _nt->OptionalHeader.ImageBase;
		//ImageBase 的偏移量
		DWORD   _image_base_offset = ((DWORD)_i_buff - _image_base);
		//计算重定位表的块数量
		int _lump_count = 0;
		while (_first_relocation_table_addr->SizeOfBlock && _first_relocation_table_addr->VirtualAddress)
		{
				printf("重定位表第%d块开始========================\n", ++_lump_count);
				DWORD block = _first_relocation_table_addr->SizeOfBlock;
				DWORD _virtual_addr = _first_relocation_table_addr->VirtualAddress;
				//计算每个重定位表中的每个块中所包含的地址数量
				size_t _addr_count = (block - sizeof(block) - sizeof(_virtual_addr)) / sizeof(WORD);
				printf("本块中共 %d个地址\n", _addr_count);
				//创建一个临时指针遍历每个块中的地址
				WORD* _temp_relocation = (WORD*)_first_relocation_table_addr;
				_temp_relocation += 4;
				for (size_t i = 0; i < _addr_count; i++)
				{
						WORD _relocation_addr_ = *_temp_relocation;
						//取出高四位的值，如果高四位等于三，则是有效的地址
						int _valid_flag = _relocation_addr_ >> 12;
						if (_valid_flag == 3)
						{
								DWORD valid_relocation_addr = _virtual_addr + (_relocation_addr_ & 0x0fff);
								char* _changeAddr = _i_buff +  valid_relocation_addr ;
								DWORD _changeAddrNum = *((DWORD*)_changeAddr);
								*((DWORD*)_changeAddr) = _changeAddrNum + _image_base_offset;

								printf("有效地址%2d: %XH Base的值为:%XH \n", i + 1, valid_relocation_addr, _virtual_addr);
						}
						else {
								printf("无效地址%2d: -  \t\t - \n", i + 1);
						}
						_temp_relocation += 1;
				}
				//指向下一个重定位表结构
				_first_relocation_table_addr = (IMAGE_BASE_RELOCATION*)(((char*)_first_relocation_table_addr) + block);

				printf("重定位表第%d块结束========================\n", _lump_count);
		}
		printf("重定位表共有%d块", _lump_count);
}
//打印导入表
void printImpTab(char * fBuff, int buffSize)
{
		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)fBuff;
		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(fBuff + _dos->e_lfanew);
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;
		//获取导入表结构指针  在目录项数组的第二个位置
		_IMAGE_IMPORT_DESCRIPTOR*  impTable =(_IMAGE_IMPORT_DESCRIPTOR*)(fBuff + _rva_to_foa(fBuff, _data_table[1].VirtualAddress));
		//DLL的函数地址未绑定好
		if(impTable->TimeDateStamp==0)
		{
				if (impTable->OriginalFirstThunk == 0)
				{
						printf("没有导入表\n");
						return;
				}
				//循环导出表结构体，遍历所要调用的所有PE模块 判断结构标记
				while (impTable->OriginalFirstThunk != 0)
				{
						char* moduleName = fBuff + _rva_to_foa(fBuff, impTable->Name);
						printf("=========当前模块名称 [%s]======TimeDateStamp:%X\n", moduleName, impTable->TimeDateStamp);

						//获取导入表 INT表的地址
						IMAGE_THUNK_DATA* IntThunkData = ((IMAGE_THUNK_DATA*)(fBuff + _rva_to_foa(fBuff, impTable->OriginalFirstThunk)));
						//获取导入表 IAT表的地址
						IMAGE_THUNK_DATA* IatThunkData = ((IMAGE_THUNK_DATA*)(fBuff + _rva_to_foa(fBuff, impTable->FirstThunk)));

						//判断INT表结束标记
						while (IntThunkData->u1.Ordinal != 0)
						{
								//获取导入表的名字
								DWORD numOrName = IntThunkData->u1.Ordinal;
								//取出标记 判断为序号导入还是名字导入
								DWORD flag = numOrName & 0x80000000;

								DWORD iatFunNameAddr = IatThunkData->u1.Ordinal;
								if (flag == 0x80000000)
								{
										DWORD number = numOrName & 0x7FFFFFFF;
										//序号导入
										printf("OriginalFirstThunk - 导入序号为:%d(%XH)   FirstThunk - %X  \n", number, number, iatFunNameAddr);
								}
								else {
										CHAR*  namefoaAddr = fBuff + _rva_to_foa(fBuff, numOrName);
										IMAGE_IMPORT_BY_NAME* impByName = (IMAGE_IMPORT_BY_NAME*)namefoaAddr;

										//为名字导入
										printf("OriginalFirstThunk - 导入名字为%s FirstThunk - %X Hint[%X] \n", impByName->Name, iatFunNameAddr, impByName->Hint);
								}
								//指向下一个INT表
								IntThunkData++;
								//指向下一个IAT表
								IatThunkData++;
						}

						//指向下一个导入表 结构体
						impTable++;
				}
				printf("================导入表模块遍历结束========\n");
		}
		//已经绑定好 ,检查绑定导入表
		else if(impTable->TimeDateStamp == -1)
		{
				printf("打印绑定导入表 impTable->TimeDateStamp:%X \n", impTable->TimeDateStamp);
				//计算绑定导入表foa
				DWORD boundTabFoa = _rva_to_foa(fBuff, _data_table[11].VirtualAddress);
				if (!boundTabFoa) 
				{
						printf("打印绑定导入表  转换FOA地址无效");
						return;
				}
				//获取导入表结构指针  在目录项数组的第十二个位置
				_IMAGE_BOUND_IMPORT_DESCRIPTOR*  boundImpTable = (_IMAGE_BOUND_IMPORT_DESCRIPTOR*)(fBuff + boundTabFoa);
				
				char*  tempBoundImpTable =(char*) boundImpTable;
				while(boundImpTable->TimeDateStamp|| boundImpTable->OffsetModuleName)
				{
						WORD numModule =boundImpTable->NumberOfModuleForwarderRefs;
				
						printf("TimeDateStamp:%X - OffsetModuleName:%s - NumberOfModule: %d\n", boundImpTable-> TimeDateStamp, tempBoundImpTable +boundImpTable->OffsetModuleName, boundImpTable->NumberOfModuleForwarderRefs);
						//指向下一个结构体
						_IMAGE_BOUND_FORWARDER_REF* boundForward =		(_IMAGE_BOUND_FORWARDER_REF*)(boundImpTable++);
						for (size_t i = 0; i < numModule; i++)
						{
								printf("TimeDateStamp:%X - OffsetModuleName:%s\n", boundForward->TimeDateStamp, tempBoundImpTable + boundForward->OffsetModuleName);
								boundForward++;
						}

						boundImpTable = boundImpTable + numModule;
				}
				printf("=================打印绑定导入表结束==========\n");

		}
		//没有导入表
		else
		{
				printf("没有导入表");
		}

}

/*移动导入表 添加自定义的dll 参数是这个PE结构的buffer地址
1.步骤将自定义的Dll 放入EXE目录
2.移动exe导入表 将自定义的Dll信息 添加到导入表
*/void moveImpTab(char * fBuff, int fBuffSize,const char* dllName)
{
		const char* funcName = "_div";
		_IMAGE_DOS_HEADER* _dos = (_IMAGE_DOS_HEADER*)fBuff;
		_IMAGE_NT_HEADERS* _nt = (_IMAGE_NT_HEADERS*)(fBuff + _dos->e_lfanew);
		IMAGE_DATA_DIRECTORY*  _data_table = _nt->OptionalHeader.DataDirectory;

		char* impTableFoa =  fBuff + _rva_to_foa(fBuff, _data_table[1].VirtualAddress) ;
		//获取导入表结构指针  在目录项数组的第二个位置
		_IMAGE_IMPORT_DESCRIPTOR*  impTable = (_IMAGE_IMPORT_DESCRIPTOR*)impTableFoa;
		//DLL的函数地址未绑定好
		if (impTable->TimeDateStamp == 0)
		{
				if (impTable->OriginalFirstThunk == 0)
				{
						printf("没有导入表\n");
						return;
				}
				//记录INT表和IAT表所需的字节大小
				int iatSize =16;
				//记录导出表结构的个数 起始数为1,是多余的结束标记
				int impTableCount = 2;
				//循环导出表结构体，遍历所要调用的所有PE模块 判断结构标记
				while (impTable->OriginalFirstThunk != 0)
				{
						char* moduleName = fBuff + _rva_to_foa(fBuff, impTable->Name);
						printf("=========当前模块名称 [%s]======TimeDateStamp:%X\n", moduleName, impTable->TimeDateStamp);

						impTableCount ++;
						//指向下一个导入表 结构体
						impTable++;
				}
				//计算导出表结构体所占字节的大小sizeof(_IMAGE_IMPORT_DESCRIPTOR)*impTableCount
				int impTableSize = sizeof(_IMAGE_IMPORT_DESCRIPTOR)*impTableCount;
				//新增节所需的内存大小 = 导入表结构数量*大小 + IAT和INT表所需的数量 + _IMAGE_BOUND_FORWARDER_REF结构体的大小（函数名字的长度）
				int vSize = impTableSize + iatSize+ strlen(funcName)+strlen(dllName)+4;
				printf("================导入表模块遍历结束========\n");

				int addBufferSize = 0;
				//返回添加节后的新的buffer
				char* addBuffer = add_section(fBuff, fBuffSize, "mDLL", vSize, &addBufferSize);
				_IMAGE_DOS_HEADER* addSectionDosHeader = (_IMAGE_DOS_HEADER*)addBuffer;
				_IMAGE_NT_HEADERS* addSectionNtHeader = (_IMAGE_NT_HEADERS*)(addBuffer + addSectionDosHeader->e_lfanew);
				IMAGE_DATA_DIRECTORY*  addSecDataTable = addSectionNtHeader->OptionalHeader.DataDirectory;
				//获取导入表结构指针  在目录项数组的第二个位置 
				char* addSecImpTable = addBuffer + _rva_to_foa(addBuffer, addSecDataTable[1].VirtualAddress);
				
				
				//新增节的文件偏移
				char* addSectionFoaOffset = addBuffer + fBuffSize;

				//获取导入表结构指针首个 foa地址
				_IMAGE_IMPORT_DESCRIPTOR*  impTableDes = (_IMAGE_IMPORT_DESCRIPTOR*)addSectionFoaOffset;

				//在新节中拷贝导出表
				_mem_copy(addSecImpTable, addSectionFoaOffset, impTableSize - 2*sizeof(_IMAGE_IMPORT_DESCRIPTOR));
				//函数名称在文件中的偏移
				DWORD funNameFoaOffset = fBuffSize + impTableSize + 18;
				
				//在导出表结构末尾 添加IAT表和INT表 各空8个字节 拷贝_IMAGE_BOUND_FORWARDER_REF结构体  拷贝函数名称字符串
				_mem_copy((char*)funcName, addBuffer+ funNameFoaOffset,strlen(funcName)+1);
				//函数名称的rva地址
				DWORD funNameRvaOffset = _foa_to_rva(addBuffer, funNameFoaOffset-2);
				IMAGE_IMPORT_BY_NAME* boundRef = (IMAGE_IMPORT_BY_NAME*)	(addBuffer + fBuffSize + impTableSize + 16);
				
				boundRef->Hint = 0x38F;

				//拷贝DLL名称 拷贝的位置是 新增节的文件buffer + 原文件大小+ 所有导入表结构体大小 + INT表和IAT表大小（各占8个字节） + 结构体_IMAGE_BOUND_FORWARDER_REF+名称子长度+结尾1（'\0'）
				_mem_copy((char*)dllName, addBuffer + funNameFoaOffset +strlen(funcName)+1,strlen(dllName)+1);

				//给INT 和 IAT表添加 函数名称的地址
		  *((DWORD*)(addSectionFoaOffset + impTableSize)) = funNameRvaOffset;
				*((DWORD*)(addSectionFoaOffset + impTableSize+8)) = funNameRvaOffset;
				/*		*((DWORD*)(addSectionFoaOffset + impTableSize)) = 0x8000038f;
				*((DWORD*)(addSectionFoaOffset + impTableSize + 8)) = 0x8000038f;*/


				//指定INT表的rva地址
				impTableDes[impTableCount - 2].OriginalFirstThunk = _foa_to_rva(addBuffer, fBuffSize+ impTableSize);
				//指定IAT表的rva地址
				impTableDes[impTableCount - 2].FirstThunk = _foa_to_rva(addBuffer, fBuffSize + impTableSize+8);

				impTableDes[impTableCount - 2].TimeDateStamp = 0;
				impTableDes[impTableCount - 2].Name = _foa_to_rva(addBuffer, funNameFoaOffset + strlen(funcName) + 1);

				addSecDataTable[1].VirtualAddress = _foa_to_rva(addBuffer, fBuffSize);
				addSecDataTable[1].Size += sizeof(_IMAGE_IMPORT_DESCRIPTOR);
				_write_restore_to_file(addBufferSize, addBuffer);


		}
		//使用的是绑定导入表
		else {
				printf("使用的绑定导入表");
		}

}

