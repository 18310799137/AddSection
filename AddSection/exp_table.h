#pragma once 
/*��ӡ������*/
void print_exp_table(char* _file_buff,char* _image_buff);

/*��ӡ�ض�λ��*/
void print_relocation(char * _f_buff);

/*����һ����,����Ϊ  _file_buff-�ļ�buffer name-�ڵ����� virtualSize-�ļ��ж���ǰ�Ĵ�С*/
char* add_section(char * _file_buff,int _file_buff_size, const char * name, int virtualSize, int* _add_section_file_size);

/*�ƶ�������*/
void move_exp_table(char * _file_buff, int _file_buff_size);

/*�ƶ��ض�λ��*/
char* move_relocation_table(char * _file_buff, int _file_buff_size);

/*�޸�ImageBase�� �޸��ض�λ��*/
void changeImageBase(char * _file_buff, int _file_buff_size);

/* �޸��ض�λ��*/
void restoreTable(char * _f_buff);

/* �޸��ض�λ�� ������״̬*/
void restoreTableIbuff(char * _i_buff);

//��ӡ�����
void printImpTab(char* fBuff, int buffSize);

/*�ƶ������ ����Զ����dll ���������PE�ṹ��buffer��ַ   
1.���轫�Զ����Dll ����EXEĿ¼
2.�ƶ�exe����� ���Զ����Dll��Ϣ ��ӵ������
*/
void moveImpTab(char* fBuff,int fBuffSize, const char* dllName);