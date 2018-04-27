#pragma once 
/*打印导出表*/
void print_exp_table(char* _file_buff,char* _image_buff);

/*打印重定位表*/
void print_relocation(char * _f_buff);

/*新增一个节,参数为  _file_buff-文件buffer name-节的名称 virtualSize-文件中对齐前的大小*/
char* add_section(char * _file_buff,int _file_buff_size, const char * name, int virtualSize, int* _add_section_file_size);

/*移动导出表*/
void move_exp_table(char * _file_buff, int _file_buff_size);

/*移动重定位表*/
char* move_relocation_table(char * _file_buff, int _file_buff_size);

/*修改ImageBase后 修复重定位表*/
void changeImageBase(char * _file_buff, int _file_buff_size);

/* 修复重定位表*/
void restoreTable(char * _f_buff);

/* 修复重定位表 拉伸后的状态*/
void restoreTableIbuff(char * _i_buff);

//打印导入表
void printImpTab(char* fBuff, int buffSize);

/*移动导入表 添加自定义的dll 参数是这个PE结构的buffer地址   
1.步骤将自定义的Dll 放入EXE目录
2.移动exe导入表 将自定义的Dll信息 添加到导入表
*/
void moveImpTab(char* fBuff,int fBuffSize, const char* dllName);