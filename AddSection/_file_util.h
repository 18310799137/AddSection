#pragma once
#include "stdafx.h"
#include <stdio.h>
#include<Windows.h>
#include<conio.h>
#include <Locale.h>//_wsetlocale �� setlocale     _wsetlocale(LC_ALL, L"chs");

//�����ڴ������ƫ�Ƶ�ַ
extern DWORD _image_buffer_oep;

extern wchar_t* _file_path;

//�ڴ�����С
extern DWORD  _mem_Alignment;
//�����ڴ澵���ַ
extern DWORD _image_base;

 
//����_image_buffer�����ڴ��С
extern DWORD _size_image;
//��ȡ����ͷ��������Ϣ��С
extern DWORD _headers;
extern DWORD _file_Alignment;
extern char _shell_code[18];
extern DWORD sectionNum;

/*���ļ�����ӽ�*/
void _add_section_and_shell_code(char * _f_buff, int _f_buffer_size);

void _run_app();
/*�ڴ���Ե�ַת��Ϊ�ļ���ַ*/
DWORD _rva_to_foa(char* _f_buff, DWORD _rva);
/*�ļ���Ե�ַת��Ϊ�ڴ���Ե�ַ*/
DWORD _foa_to_rva(char* _f_buff, DWORD _foa);

void sectionTostring(_IMAGE_SECTION_HEADER* _section_header, DWORD sectionNum);
/*�ڴ濽�� source����Դ��ʼ��ַ��target����Ŀ���ַ��sizeΪҪ�����Ĵ�С*/
void _mem_copy(char* source, char* target, int size);
/*ѡ���ļ����ش���ļ����Ƶĵ�ַ 0������ļ���1�������ļ�*/
TCHAR* chooseFile(int operation);

/*�����ڴ��д����õ�_image_buffer��ַ*/
int 	_read_fbuff_to_ibuff(char* _f_buff, char** _i_buff);

/*��ȡ�ļ����ڴ��У������ڴ��ַ _f_buff ���ļ���С*/
int  _read_file_to_fbuff(TCHAR* _file_path, char** _f_buff);


void _write_restore_to_file(int _ibuff_size, char* _i_buff);

/*�ڴ��������shell code �޸ĳ�����ڵ�ַ*/
void addShellCode(char * _f_buff, int _f_buffer_size);