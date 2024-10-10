/*****************************************************************
 *文件作用：  哈希和指纹模块，包含哈希函数和指纹函数
 *author:     xudongliang
 *copyright:  www.pact518.hit.edu.cn
 *date:       2012.05.11
 *
 *****************************************************************/
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include "hash.h"
//static int32_t Hash_Mask[] = {0xffffff, 0x1ffffff, 0x3ffffff};//用来产生哈希值
//static int32_t Hash_Length[] = {6, 7, 8};//块的大小 
//static int32_t HashSize;
static int32_t HashMask;
/****************************************************************
 *函数：int HashFunc(u_int8_t *keyword,int32_t HashLength)
 *目的：用来计算跳跃值的哈希函数
 *参数：keyword => 关键字
	HashLength => 关键字的长度
 *返回值：关键字的哈希值
 * ***************************************************************/

 int HashFunc(u_int8_t *keyword,int32_t HashLength)
 {
	 int32_t i;
	 u_int32_t sum;

	 sum = 0;
	 for(i = 0; i < HashLength; i++)
		 sum = (sum << 8) - (sum << 5) - sum + keyword[i];
	 //sum = (sum >> HashOffset) + (sum & HashMask);
	 return sum & HashMask;
 }

/* ****************************************************************
    函数：static unsigned HASH16(unsigned char *)
	目的：对一串字符进行哈希计算。计算方式为：(((*T)<<8) | *(T+1))，
	参数：
		T => 要哈希计算的字符串
    返回：
	    unsigned - 静态函数，返回对字符串T计算的哈希值
 ****************************************************************/
HASH_TYPE HASH16(unsigned char *T)//如果每个块设为2个字符，可以使用这个哈希函数，但不设为2，不能用这个哈希函数
{
//	printf("T:%c\n",*(T));
//	getchar();
//	printf("T+1:%c\n",*(T+1));
//	getchar();
//	printf("T<<8:%c\n",(int)((*T)<<8));
//	getchar();
//	printf("HASH16:%d\n",((*T)<<8) | *(T+1));
//	getchar();
	HASH_TYPE hash;
	hash =(((*T)<<8)|*(T+1));
	return hash;
//	return (HASH_TYPE) (((*T)<<8) | *(T+1)); //对第一个字符左移8位，然后与第二个字符异或运算
}
/****************************************************************
 *函数：unsigned int FingerPrint1(u_int8_t *keyword)
 *目的：用来计算跳跃值的哈希函数,该方法比下边那个FingerPrint函数效率差很多
 *参数：keyword => 关键字
 *返回值：关键字的哈希值
 * ***************************************************************/
u_int32_t FingerPrint1(unsigned char *keyword,int32_t keylen)
{
	u_int32_t hash=0;
	while((keylen--)!=0)
	{
		hash=(((*keyword)<<keylen)|hash);
	}
	return hash;
//	printf("hash=%u\n",(u_int32_t)(hash & 0x7FFFFFFF));
}
/****************************************************************
 *函数：unsigned int FingerPrint(u_int8_t *keyword)
 *目的：用来计算跳跃值的哈希函数
 *参数：keyword => 关键字
 *返回值：关键字的哈希值
 * ***************************************************************/
u_int32_t FingerPrint(unsigned char *keyword,int32_t keylen)
{
	u_int32_t seed =131;//31 131 1313 13131 131313 etc...
	u_int32_t hash = 0;
	
	while(keylen!=0)
	{
		hash = hash*seed + (*keyword++);
		keylen--;
	}
//	printf("hash=%u\n",(u_int32_t)(hash & 0x7FFFFFFF));
	return(hash & 0x7FFFFFFF);
}
