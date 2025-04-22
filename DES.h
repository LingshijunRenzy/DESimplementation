#ifndef DES_H
#define DES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "enum.h"

// 64位BYTE类型定义
typedef unsigned long long BYTE;

// DES结构体定义
typedef struct
{
    BYTE key;      // 密钥
    BYTE *subKeys; // 子密钥
    BYTE iv;       // 初始化向量
} DES;

// 创建和销毁DES实例
DES *DES_create();
void DES_destroy(DES *des);

// 设置密钥和初始化向量
void DES_setKey(DES *des, BYTE *key, size_t keySize);
void DES_setIV(DES *des, BYTE *iv, size_t ivSize);

void DES_init(DES *des, BYTE key);

// 加密和解密函数
BYTE DES_encryptBlock(DES *des, BYTE block);
BYTE DES_decryptBlock(DES *des, BYTE block);

// 生成子密钥
BYTE *generate_subkeys(const BYTE key);

// IP置换函数
BYTE IP_transform(const BYTE block);
// IP^-1置换函数
BYTE IP_inv_transform(const BYTE block);
// E-扩展运算
BYTE E_expansion(const BYTE block);
// S-盒运算
BYTE S_box(const BYTE block);
// P-置换
BYTE P_permutation(const BYTE block);

#endif