#ifndef DES_H
#define DES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "enum.h"

// 定义字节类型 - 改为使用64位无符号长整型处理DES块
typedef unsigned long long BYTE;

// DES结构体定义
typedef struct
{
    BYTE *key;      // 密钥
    size_t keySize; // 密钥大小 (以BYTE单位计)
    BYTE *iv;       // 初始化向量
    size_t ivSize;  // 初始化向量大小 (以BYTE单位计)
} DES;

// 创建和销毁DES实例
DES *DES_create();
void DES_destroy(DES *des);

// 设置密钥和初始化向量
void DES_setKey(DES *des, const BYTE *key, size_t keySize);
void DES_setIV(DES *des, const BYTE *iv, size_t ivSize);

// 加密和解密函数
BYTE *DES_encrypt(DES *des, const BYTE *plaintext, size_t plaintextSize,
                  EncryptionMode mode, size_t *ciphertextSize);
BYTE *DES_decrypt(DES *des, const BYTE *ciphertext, size_t ciphertextSize,
                  EncryptionMode mode, size_t *plaintextSize);

// 辅助函数
void generateSubkeys(const BYTE *key, BYTE **subkeys);
void encryptBlock(BYTE *block, const BYTE **subkeys);
void decryptBlock(BYTE *block, const BYTE **subkeys);
void xorBlocks(BYTE *block1, const BYTE *block2, size_t size);
void padding(BYTE **data, size_t *dataSize);
void unpadding(BYTE **data, size_t *dataSize);

#endif