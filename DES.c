#include "DES.h"
#include "DESConstants.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// DES块大小 - 现在1个BYTE即为一个块(64位)
#define BLOCK_SIZE 1

// 创建DES实例
DES *DES_create()
{
    DES *des = (DES *)malloc(sizeof(DES));
    if (des)
    {
        des->key = NULL;
        des->keySize = 0;
        des->iv = NULL;
        des->ivSize = 0;
    }
    return des;
}

// 销毁DES实例
void DES_destroy(DES *des)
{
    if (des)
    {
        if (des->key)
            free(des->key);
        if (des->iv)
            free(des->iv);
        free(des);
    }
}

// 设置密钥
void DES_setKey(DES *des, const BYTE *key, size_t keySize)
{
    if (des->key)
        free(des->key);

    des->key = (BYTE *)malloc(keySize * sizeof(BYTE));
    if (des->key)
    {
        memcpy(des->key, key, keySize * sizeof(BYTE));
        des->keySize = keySize;
    }

    // 生成子密钥 (这里应该调用子密钥生成函数)
    // generateSubkeys(des->key, subkeys);
}

// 设置初始化向量
void DES_setIV(DES *des, const BYTE *iv, size_t ivSize)
{
    if (des->iv)
        free(des->iv);

    des->iv = (BYTE *)malloc(ivSize * sizeof(BYTE));
    if (des->iv)
    {
        memcpy(des->iv, iv, ivSize * sizeof(BYTE));
        des->ivSize = ivSize;
    }
}

// 加密函数
BYTE *DES_encrypt(DES *des, const BYTE *plaintext, size_t plaintextSize,
                  EncryptionMode mode, size_t *ciphertextSize)
{
    // 添加填充
    BYTE *paddedPlaintext = (BYTE *)malloc(plaintextSize * sizeof(BYTE));
    size_t paddedSize = plaintextSize;
    if (paddedPlaintext)
    {
        memcpy(paddedPlaintext, plaintext, plaintextSize * sizeof(BYTE));
        padding(&paddedPlaintext, &paddedSize);
    }
    else
    {
        return NULL;
    }

    // 分配密文空间
    *ciphertextSize = paddedSize;
    BYTE *ciphertext = (BYTE *)malloc(*ciphertextSize * sizeof(BYTE));
    if (!ciphertext)
    {
        free(paddedPlaintext);
        return NULL;
    }

    // 根据不同模式实现加密
    switch (mode)
    {
    case ECB:
        // ECB模式加密
        // 待实现
        break;
    case CBC:
        // CBC模式加密
        // 待实现
        break;
    case CFB:
        // CFB模式加密
        // 待实现
        break;
    case OFB:
        // OFB模式加密
        // 待实现
        break;
    }

    free(paddedPlaintext);
    return ciphertext;
}

// 解密函数
BYTE *DES_decrypt(DES *des, const BYTE *ciphertext, size_t ciphertextSize,
                  EncryptionMode mode, size_t *plaintextSize)
{
    // 分配明文空间
    *plaintextSize = ciphertextSize;
    BYTE *plaintext = (BYTE *)malloc(*plaintextSize * sizeof(BYTE));
    if (!plaintext)
    {
        return NULL;
    }

    // 根据不同模式实现解密
    switch (mode)
    {
    case ECB:
        // ECB模式解密
        // 待实现
        break;
    case CBC:
        // CBC模式解密
        // 待实现
        break;
    case CFB:
        // CFB模式解密
        // 待实现
        break;
    case OFB:
        // OFB模式解密
        // 待实现
        break;
    }

    // 去除填充
    unpadding(&plaintext, plaintextSize);

    return plaintext;
}

// 生成子密钥
void generateSubkeys(const BYTE *key, BYTE **subkeys)
{
    // 实现子密钥生成
    // 待实现
}

// 加密单个块
void encryptBlock(BYTE *block, const BYTE **subkeys)
{
    // 实现DES块加密
    // 待实现
}

// 解密单个块
void decryptBlock(BYTE *block, const BYTE **subkeys)
{
    // 实现DES块解密
    // 待实现
}

// 两个块进行异或操作
void xorBlocks(BYTE *block1, const BYTE *block2, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        block1[i] ^= block2[i];
    }
}

// 填充函数（PKCS#7）- 修改为处理64位块
void padding(BYTE **data, size_t *dataSize)
{
    size_t originalSize = *dataSize;
    size_t paddingSize = BLOCK_SIZE - (originalSize % BLOCK_SIZE);
    if (paddingSize == 0)
    {
        paddingSize = BLOCK_SIZE;
    }

    size_t newSize = originalSize + paddingSize;
    BYTE *newData = (BYTE *)realloc(*data, newSize * sizeof(BYTE));
    if (newData)
    {
        // 添加PKCS#7填充
        for (size_t i = originalSize; i < newSize; i++)
        {
            newData[i] = (BYTE)paddingSize;
        }
        *data = newData;
        *dataSize = newSize;
    }
}

// 去除填充
void unpadding(BYTE **data, size_t *dataSize)
{
    if (*dataSize == 0)
        return;

    size_t size = *dataSize;
    BYTE paddingValue = (*data)[size - 1];

    // 验证填充
    if (paddingValue <= BLOCK_SIZE)
    {
        for (size_t i = size - paddingValue; i < size; i++)
        {
            if ((*data)[i] != paddingValue)
            {
                return; // 无效填充
            }
        }

        // 去除填充
        *dataSize = size - paddingValue;
        // 可选：调整内存大小
        // *data = (BYTE*)realloc(*data, *dataSize * sizeof(BYTE));
    }
}