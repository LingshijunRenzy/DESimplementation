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
    }
    return des;
}

// 销毁DES实例
void DES_destroy(DES *des)
{
    if (des)
    {
        if (des->subKeys)
        {
            free(des->subKeys);
        }
        free(des);
    }
}

void DES_init(DES *des, BYTE key)
{
    des->key = key;
    des->subKeys = generate_subkeys(key);
    if (!des->subKeys)
    {
        printf("Failed to generate subkeys.\n");
        return;
    }
}

// 设置密钥
void DES_setKey(DES *des, BYTE *key, size_t keySize)
{
    if (des && key && keySize == 1)
    { // 期望密钥大小为1个BYTE (64位)
        des->key = *key;
        // 生成子密钥
        des->subKeys = generate_subkeys(des->key);
    }
}

// 设置初始化向量
void DES_setIV(DES *des, BYTE *iv, size_t ivSize)
{
    if (des && iv && ivSize == 1)
    { // 期望IV大小为1个BYTE (64位)
        des->iv = *iv;
    }
}

BYTE DES_encryptBlock(DES *des, BYTE block)
{
    // 初始置换
    block = IP_transform(block);

    // 分为左右两部分
    BYTE left = (block >> 32) & 0xFFFFFFFF;
    BYTE right = block & 0xFFFFFFFF;

    // 16轮迭代
    for (int i = 0; i < 16; i++)
    {
        // 扩展右半部分
        BYTE expandedRight = E_expansion(right);
        // 与子密钥异或
        expandedRight ^= des->subKeys[i];
        // S-盒变换
        BYTE sboxOutput = S_box(expandedRight);
        // P-置换
        BYTE pOutput = P_permutation(sboxOutput);
        // 左右交换并异或
        BYTE temp = left;
        left = right;
        right ^= pOutput;
    }

    // 合并左右部分
    block = ((BYTE)left << 32) | right;

    // 逆初始置换
    block = IP_inv_transform(block);

    return block;
}

BYTE DES_decryptBlock(DES *des, BYTE block)
{
    // 初始置换
    block = IP_transform(block);

    // 分为左右两部分
    BYTE left = (block >> 32) & 0xFFFFFFFF;
    BYTE right = block & 0xFFFFFFFF;

    // 16轮迭代（子密钥顺序反转）
    for (int i = 15; i >= 0; i--)
    {
        // 扩展右半部分
        BYTE expandedRight = E_expansion(right);
        // 与子密钥异或
        expandedRight ^= des->subKeys[i];
        // S-盒变换
        BYTE sboxOutput = S_box(expandedRight);
        // P-置换
        BYTE pOutput = P_permutation(sboxOutput);
        // 左右交换并异或
        BYTE temp = left;
        left = right;
        right ^= pOutput;
    }

    // 合并左右部分
    block = ((BYTE)left << 32) | right;

    // 逆初始置换
    block = IP_inv_transform(block);

    return block;
}

BYTE *generate_subkeys(BYTE key)
{
    BYTE *subkeys = (BYTE *)malloc(16 * sizeof(BYTE));
    if (!subkeys)
    {
        return NULL;
    }

    // 提取56位有效密钥（去除奇偶校验位）
    BYTE key_ = 0;
    int destBit = 0; // 目标位置
    for (int i = 0; i < 64; i++)
    {
        if (i % 8 != 7)
        {
            int bitValue = (key >> i) & 1;
            key_ |= ((BYTE)bitValue << destBit);
            destBit++;
        }
    }

    BYTE keyPC1 = 0;
    for (int i = 0; i < 56; i++)
    {
        int bitPosition = PC1[i] - 1; // PC1表从1开始
        int bitValue = (key_ >> bitPosition) & 1;
        keyPC1 |= (bitValue << i);
    }
    // C0和D0
    BYTE C0 = 0;
    BYTE D0 = 0;
    for (int i = 0; i < 28; i++)
    {
        int bitValue = (keyPC1 >> i) & 1;
        C0 |= (bitValue << i);
        bitValue = (keyPC1 >> (i + 28)) & 1;
        D0 |= (bitValue << i);
    }

    for (int i = 0; i < 16; i++)
    {
        // 从LS表获取左移位数再左移
        int shift = SHIFTS[i];
        C0 = ((C0 << shift) | (C0 >> (28 - shift))) & 0xFFFFFFF; // 左移并循环
        D0 = ((D0 << shift) | (D0 >> (28 - shift))) & 0xFFFFFFF; // 左移并循环

        // PC2置换 subkey = PC2(CiDi)
        BYTE subkey = 0;
        for (int j = 0; j < 48; j++)
        {
            int bitPosition = PC2[j] - 1; // PC2表从1开始
            int bitValue;
            if (bitPosition < 28)
            {
                bitValue = (C0 >> bitPosition) & 1;
            }
            else
            {
                bitValue = (D0 >> (bitPosition - 28)) & 1;
            }
            subkey |= (bitValue << j);
        }
        subkeys[i] = subkey;
    }

    return subkeys;
}

BYTE IP_transform(const BYTE block)
{
    // 输入为64位, 输出为64位
    BYTE output = 0;
    for (int i = 0; i < 64; i++)
    {
        int bitPosition = IP[i] - 1; // IP表从1开始
        int bitValue = (block >> bitPosition) & 1;
        output |= (bitValue << i);
    }
    return output;
}

BYTE IP_inv_transform(const BYTE block)
{
    // 输入为64位, 输出为64位
    BYTE output = 0;
    for (int i = 0; i < 64; i++)
    {
        int bitPosition = IP_INV[i] - 1; // IP^-1表从1开始
        int bitValue = (block >> bitPosition) & 1;
        output |= (bitValue << i);
    }
    return output;
}

BYTE E_expansion(const BYTE block)
{
    // 输入为32位, 输出为48位
    BYTE output = 0;
    for (int i = 0; i < 48; i++)
    {
        // E扩展运算
        int bitPosition = E[i] - 1; // E表从1开始
        int bitValue = (block >> bitPosition) & 1;
        output |= (bitValue << i);
    }
    return output;
}

BYTE S_box(const BYTE block)
{
    // 输入为48位, 输出为32位
    BYTE output = 0;
    for (int i = 0; i < 8; i++)
    {
        // S-盒运算
        int row = ((block >> (i * 6 + 5)) & 1) | (((block >> (i * 6)) & 1) << 1);
        int col = (block >> (i * 6 + 1)) & 0x0F;
        int sboxValue = S_BOXES[i][row][col];
        output |= (sboxValue << (i * 4));
    }
    return output;
}

BYTE P_permutation(const BYTE block)
{
    // 输入为32位, 输出为32位
    BYTE output = 0;
    for (int i = 0; i < 32; i++)
    {
        int bitPosition = P[i] - 1; // P表从1开始
        int bitValue = (block >> bitPosition) & 1;
        output |= (bitValue << i);
    }
    return output;
}