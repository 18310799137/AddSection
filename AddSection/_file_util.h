#pragma once
#include "stdafx.h"
#include <stdio.h>
#include<Windows.h>
#include<conio.h>
#include <Locale.h>//_wsetlocale 或 setlocale     _wsetlocale(LC_ALL, L"chs");

//程序内存中入口偏移地址
extern DWORD _image_buffer_oep;

extern wchar_t* _file_path;

//内存对齐大小
extern DWORD  _mem_Alignment;
//程序内存镜像基址
extern DWORD _image_base;

 
//计算_image_buffer所需内存大小
extern DWORD _size_image;
//获取所有头部描述信息大小
extern DWORD _headers;
extern DWORD _file_Alignment;
extern char _shell_code[18];
extern DWORD sectionNum;

/*在文件中添加节*/
void _add_section_and_shell_code(char * _f_buff, int _f_buffer_size);

void _run_app();
/*内存相对地址转换为文件地址*/
DWORD _rva_to_foa(char* _f_buff, DWORD _rva);
/*文件相对地址转换为内存相对地址*/
DWORD _foa_to_rva(char* _f_buff, DWORD _foa);

void sectionTostring(_IMAGE_SECTION_HEADER* _section_header, DWORD sectionNum);
/*内存拷贝 source代表源起始地址，target代表目标地址，size为要拷贝的大小*/
void _mem_copy(char* source, char* target, int size);
/*选择文件返回存放文件名称的地址 0代表打开文件，1代表保存文件*/
TCHAR* chooseFile(int operation);

/*返回内存中创建好的_image_buffer地址*/
int 	_read_fbuff_to_ibuff(char* _f_buff, char** _i_buff);

/*读取文件到内存中，返回内存地址 _f_buff 与文件大小*/
int  _read_file_to_fbuff(TCHAR* _file_path, char** _f_buff);


void _write_restore_to_file(int _ibuff_size, char* _i_buff);

/*在代码中添加shell code 修改程序入口地址*/
void addShellCode(char * _f_buff, int _f_buffer_size);