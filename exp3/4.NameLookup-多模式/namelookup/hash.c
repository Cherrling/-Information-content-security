/*****************************************************************
*文件作用：  哈希和指纹模块，包含哈希函数和指纹函数
*author:     xudongliang
*copyright:  www.pact518.hit.edu.cn
*date:       2014.01.02
*
*****************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"



//哈希函数集

//HASH1
//unsigned int SDBMHash(char *str)
unsigned int hash1(char *str)
{
	unsigned int hash = 0;
	
	while(*str)
	{
		//equivalent to: hash = 65599*hash + (*str++);
		hash = (*str++)+(hash<<6)+(hash<<16)-hash;
	}
	return (hash & 0x7FFFFFFF);
}


//HASH2
//unsigned int RSHash(char*str)
unsigned int hash2(char *str)
{
	unsigned int b = 378551;
	unsigned int a = 63689;
	unsigned int hash = 0;

	while(*str)
	{
		hash = hash*a + (*str++);
		a *= b;
	}
	
	return (hash & 0x7FFFFFFF);
}


//HASH3
//unsigned int JSHash(char *str)
unsigned int hash3(char *str)
{
	unsigned int hash = 1315423911;

	while(*str)
	{
		hash ^= ((hash << 5)+(*str++)+(hash>>2));
	}

	return (hash & 0x7FFFFFFF);
}


//HASH4
//unsigned int BKDRHash(char *str)
unsigned int hash4(char *str)
{
	unsigned int seed = 131;//31 131 1313 13131 131313 etc..
	unsigned int hash = 0;
	
	while(*str)
	{
		hash = hash*seed + (*str++);
	}

	return (hash & 0x7FFFFFFF);
}



//HASH5
//unsigned int DJBHash(char *str)
unsigned int hash5(char *str)
{
	unsigned int hash = 5381;

	while(*str)
	{
		hash += (hash<<5)+(*str++);
	}

	return(hash & 0x7FFFFFFF);
}



//HASH6
//unsigned int APHash(char *str)
unsigned int hash6(char *str)
{
	unsigned int hash = 0;
	int i;

	for(i=0; *str; i++)
	{
		if((i & 1) == 0)
		{
			hash ^= ((hash<<7) ^ (*str++) ^ (hash>>3));
		}
		else
		{
			hash ^= (~((hash<<11) ^ (*str++) ^ (hash>>5)));
		}
	}

	return (hash & 0x7FFFFFFF);
}



//HASH7 网上评价该函数效果较差
//unsigned int ELFHash(char *str)
unsigned int hash7(char *str)
{
	unsigned int hash = 0;
	unsigned int x = 0;

	while(*str)
	{
		hash = (hash<<4) + (*str++);
		if((x = hash&0xF0000000L) != 0)
		{
			hash ^= (x >> 24);
			hash &= ~x;
		}
	}

	return (hash & 0x7FFFFFFF);
}



//HASH8 编程珠玑中给出的一个哈希函数

#define NHASH 29989  //用跟元素个数最接近的质数作为散列表的大小
#define MULT 31

unsigned int hash8(char *str) 
{
	unsigned int hash = 0;

	for(;*str;str++)
	{
		hash = MULT * hash + *str;
	}

	return hash % NHASH;
}










