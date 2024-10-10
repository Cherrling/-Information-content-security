/*****************************************************************
*文件作用：  哈希头文件,主要是用于对外接口
*author:     xudongliang
*copyright:  www.pact518.hit.edu.cn
*date:       2014.01.02
*
*****************************************************************/
#ifndef _HASH_H_
#define _HASH_H_ 


#define HASH  hash1
#define HASHTABLESIZE 29989//用跟元素个数最接近的质数作为散列表的大小
#define NUMHASH 30 //哈希表的个数

/*
unsigned int SDBMHash(char *str);
unsigned int RSHash(char*str);
unsigned int JSHash(char *str);
unsigned int BKDRHash(char *str);
unsigned int DJBHash(char *str);
unsigned int APHash(char *str);
*/


unsigned int HASH(char *str); 



#endif
