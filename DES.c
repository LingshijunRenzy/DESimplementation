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
        des->key = 0;
        des->subKeys = NULL;
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
        right = temp ^ pOutput;
    }

    // 合并左右部分 - 注意最后一轮后需要交换左右顺序
    block = ((BYTE)right << 32) | left;

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
        right = temp ^ pOutput;
    }

    // 合并左右部分
    block = ((BYTE)right << 32) | left;

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

    // PC1 置换：按 MSB→LSB 提取到 key_, MSB-first 存储
    BYTE key_ = 0;
    for (int i = 0; i < 56; i++)
    {
        int src = PC1[i] - 1; // MSB-based index
        int bit = (key >> (63 - src)) & 1;
        key_ |= (BYTE)bit << (55 - i); // MSB-first 存储, bit pos = 55 - i
    }

    // 分割 C0 和 D0，key_ MSB-first 存储, 高28位是 C0, 低28位是 D0
    BYTE C0 = (key_ >> 28) & 0x0FFFFFFF;
    BYTE D0 = key_ & 0x0FFFFFFF;

    for (int i = 0; i < 16; i++)
    {
        // 从LS表获取左移位数再左移
        int shift = SHIFTS[i];
        C0 = ((C0 << shift) | (C0 >> (28 - shift))) & 0x0FFFFFFF;
        D0 = ((D0 << shift) | (D0 >> (28 - shift))) & 0x0FFFFFFF;

        // PC2 置换：按 MSB→LSB 提取，MSB-first 存储
        unsigned long long CD = ((unsigned long long)C0 << 28) | D0; // 合并时 C0 为高28位, D0 为低28位
        BYTE subkey = 0;
        for (int j = 0; j < 48; j++)
        {
            int src2 = PC2[j] - 1;
            int bit2 = (CD >> (55 - src2)) & 1;
            subkey |= (BYTE)bit2 << (47 - j);
        }
        subkeys[i] = subkey;
    }

    return subkeys;
}

// 初始置换按 MSB→LSB
BYTE IP_transform(const BYTE block)
{
    BYTE output = 0;
    for (int i = 0; i < 64; i++)
    {
        int src = IP[i] - 1;
        int bit = (block >> (63 - src)) & 1;
        output |= (BYTE)bit << (63 - i);
    }
    return output;
}

// 逆初始置换，MSB→LSB
BYTE IP_inv_transform(const BYTE block)
{
    BYTE output = 0;
    for (int i = 0; i < 64; i++)
    {
        int src = IP_INV[i] - 1;
        int bit = (block >> (63 - src)) & 1;
        output |= (BYTE)bit << (63 - i);
    }
    return output;
}

// 扩展置换，MSB→LSB 输入, MSB-first 输出
BYTE E_expansion(const BYTE block)
{
    BYTE output = 0;
    for (int i = 0; i < 48; i++)
    {
        int src = E[i] - 1; // 0..31
        int bit = (block >> (31 - src)) & 1;
        output |= (BYTE)bit << (47 - i);
    }
    return output;
}

// P 置换，MSB→LSB 输入, MSB-first 输出
BYTE P_permutation(const BYTE block)
{
    BYTE output = 0;
    for (int i = 0; i < 32; i++)
    {
        int src = P[i] - 1;
        int bit = (block >> (31 - src)) & 1;
        output |= (BYTE)bit << (31 - i);
    }
    return output;
}

// S-盒变换
BYTE S_box(const BYTE block)
{
    // 32位输出，MSB-first: 输出放在 31..0
    BYTE output = 0;
    for (int i = 0; i < 8; i++)
    {
        int offset = 48 - (i + 1) * 6; // 从 MSB 取 6 位
        BYTE chunk = (block >> offset) & 0x3F;
        int row = ((chunk >> 5) << 1) | (chunk & 1);
        int col = (chunk >> 1) & 0x0F;
        int sval = S_BOXES[i][row][col] & 0x0F;
        // 将4位值放到输出的 MSB-first 位置
        output |= (BYTE)sval << (28 - i * 4);
    }
    return output;
}

// 辅助调试函数 - 打印64位数据块的二进制表示
void print_bits(BYTE value, const char *label)
{
    printf("%s: 0x%016llX\n", label, value);
    printf("二进制: ");
    for (int i = 63; i >= 0; i--)
    {
        printf("%d", (int)((value >> i) & 1));
        // 每8位添加一个空格，增强可读性
        if (i % 8 == 0 && i > 0)
            printf(" ");
    }
    printf("\n");
}

// 调试函数 - 输出DES加密过程的中间状态
BYTE DES_encryptBlock_debug(DES *des, BYTE block)
{
    printf("\n======== DES加密块调试信息 ========\n");
    printf("原始输入块:\n");
    print_bits(block, "输入");

    // 初始置换
    block = IP_transform(block);
    printf("\n初始置换后:\n");
    print_bits(block, "IP置换");

    // 分为左右两部分
    BYTE left = (block >> 32) & 0xFFFFFFFF;
    BYTE right = block & 0xFFFFFFFF;
    printf("\n分割为左右两部分:\n");
    print_bits(left, "左半部分");
    print_bits(right, "右半部分");

    // 16轮迭代
    for (int i = 0; i < 16; i++)
    {
        printf("\n==== 第%2d轮 ====\n", i + 1);
        printf("轮开始时状态:\n");
        print_bits(left, "左半部分");
        print_bits(right, "右半部分");

        // 扩展右半部分
        BYTE expandedRight = E_expansion(right);
        printf("扩展右半部分:\n");
        print_bits(expandedRight, "扩展后");

        // 与子密钥异或
        printf("使用子密钥:\n");
        print_bits(des->subKeys[i], "子密钥");

        expandedRight ^= des->subKeys[i];
        printf("与子密钥异或后:\n");
        print_bits(expandedRight, "异或结果");

        // S-盒变换
        BYTE sboxOutput = S_box(expandedRight);
        printf("S-盒变换后:\n");
        print_bits(sboxOutput, "S-盒输出");

        // P-置换
        BYTE pOutput = P_permutation(sboxOutput);
        printf("P-置换后:\n");
        print_bits(pOutput, "P置换输出");

        // 左右交换并异或
        BYTE temp = left;
        left = right;
        right = temp ^ pOutput;

        printf("本轮结束后的新状态:\n");
        print_bits(left, "新左半部分");
        print_bits(right, "新右半部分");
    }

    // 最后一轮后交换左右两边
    printf("\n最后交换左右两部分前:\n");
    print_bits(left, "左半部分");
    print_bits(right, "右半部分");

    // 合并左右部分，注意交换左右顺序
    block = ((BYTE)right << 32) | left;
    printf("\n最后合并后 (交换左右):\n");
    print_bits(block, "合并结果");

    // 逆初始置换
    block = IP_inv_transform(block);
    printf("\n逆初始置换后的最终结果:\n");
    print_bits(block, "最终输出");

    printf("======== DES加密块调试结束 ========\n\n");

    return block;
}