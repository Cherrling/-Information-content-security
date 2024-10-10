/*****************************************************************
 *author:     xudongliang
 *copyright:  www.pact518.hit.edu.cn
 *date:       2012.05.11
 *
 *****************************************************************/

#ifndef RFPWM_H
#define RFPWM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"

#define HASHTABLESIZE (256*256)//块B为2个字符
#define SHIFTTABLESIZE (256*256)

typedef struct finger_print_struct //每个模式串的每个窗口的指纹冲突结构体
{
	u_int32_t fingerprint;//窗口指纹
	int32_t frequency;//每个窗口指纹在所有模式串中出现的频率
}FINGER_PRINT;

//该结构体在将内容整理到patarray数组中后就释放掉，但其中的pat(存储模式串的数组)不释放，因为patarray中要用到
typedef struct rfpwm_pattern_struct //每个模式串的存储结构
{
	struct rfpwm_pattern_struct *next;//指向下一个模式串
	unsigned char *pat; //存储模式串
	FINGER_PRINT *fparray;//每个模式串的窗口指纹数组
	int32_t index; //模式串唯一指纹起始索引
	u_int32_t len; //length of pattern in bytes
}RFPWM_PATTERN_STRUCT; 

typedef struct rfpwm_patarray_struct //模式串集数组的结构
{
	unsigned char *pat; //存储模式串
	int32_t index;//模式串唯一指纹位置起始索引
	u_int32_t fingerprint;//窗口指纹，此时已经为该模式串的唯一指纹
	u_int32_t len;//length of pattern in bytes
}RFPWM_PATARRAY_STRUCT;

typedef struct rfpwm_struct //模式串集的结构
{
	RFPWM_PATTERN_STRUCT *patlist;//模式串链表存储结构
	RFPWM_PATARRAY_STRUCT *patarray;//模式串数组存储结构
	HASH_TYPE *numarray;//每个哈希组内模式串的个数unsigned short型		
	u_int32_t numpat;//模式串的总数
	HASH_TYPE *hash; //最后两个字符的哈希表
	HASH_TYPE *shift;//坏字符跳跃表
	u_int32_t *fingerprint; //随机指纹表(randomly figureprint),相当于标准WM中的前缀哈希表
	u_int32_t smallest;//最短模式串长度
}RFPWM_STRUCT;

//函数声明
RFPWM_STRUCT *rfpwm_new();
void rfpwmfree(RFPWM_STRUCT*);
int rfpwmaddpat(RFPWM_STRUCT *p, unsigned char *pat,u_int32_t len);
int winfingerprint(RFPWM_STRUCT *p);
int rfpwmprecpat(RFPWM_STRUCT *p);
int rfpwmsearch(RFPWM_STRUCT *p,unsigned char *Tx,int n);
#endif
