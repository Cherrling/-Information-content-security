/*****************************************************************
 *文件作用：  哈希和指纹模块的头文件,主要是用于对外接口
 *author:     xudongliang
 *copyright:  www.pact518.hit.edu.cn
 *date:       2012.05.11
 *
 *****************************************************************/

#ifndef FINGERPRINT_H
#define FINGERPRINT_H
#define HASH_TYPE u_int16_t//如果块B是2个字符，那么设为16位

typedef unsigned char u_int8_t;
typedef int int32_t;
typedef unsigned int u_int32_t;
typedef unsigned short u_int16_t;

int HashFunc(u_int8_t *keyword,int32_t HashLength);
HASH_TYPE HASH16(unsigned char *T);
u_int32_t FingerPrint(unsigned char *keyword,int32_t keylen);



#endif
