#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "DES.h"
#include "enum.h"

// DES相关常量定义
#define BLOCK_SIZE 1 // 现在1个BYTE代表一个64位块
#define KEY_SIZE 1   // 密钥大小为1个BYTE (64位)
#define IV_SIZE 1    // 初始化向量大小为1个BYTE (64位)

// 将字符串转换为加密模式枚举
EncryptionMode parseMode(const char *modeStr)
{
    if (strcmp(modeStr, "ECB") == 0 || strcmp(modeStr, "ecb") == 0)
        return ECB;
    if (strcmp(modeStr, "CBC") == 0 || strcmp(modeStr, "cbc") == 0)
        return CBC;
    if (strcmp(modeStr, "CFB") == 0 || strcmp(modeStr, "cfb") == 0)
        return CFB;
    if (strcmp(modeStr, "OFB") == 0 || strcmp(modeStr, "ofb") == 0)
        return OFB;

    fprintf(stderr, "不支持的加密模式: %s\n", modeStr);
    exit(1);
}

// 读取文件内容到字节数组 - 修改为支持64位BYTE类型
BYTE *readFile(const char *filePath, size_t *fileSize)
{
    FILE *file = fopen(filePath, "rb");
    if (!file)
    {
        fprintf(stderr, "无法打开文件: %s\n", filePath);
        return NULL;
    }

    // 获取文件大小(以字节为单位)
    fseek(file, 0, SEEK_END);
    size_t fileSizeBytes = ftell(file);
    fseek(file, 0, SEEK_SET);

    // 计算需要的BYTE数量 (向上取整，每8个字节一个BYTE)
    *fileSize = (fileSizeBytes + 7) / 8;

    // 分配内存空间
    BYTE *buffer = (BYTE *)malloc(*fileSize * sizeof(BYTE));
    if (!buffer)
    {
        fclose(file);
        fprintf(stderr, "内存分配失败\n");
        return NULL;
    }

    // 临时缓冲区存储实际字节
    unsigned char *tempBuffer = (unsigned char *)malloc(fileSizeBytes);
    if (!tempBuffer)
    {
        free(buffer);
        fclose(file);
        fprintf(stderr, "内存分配失败\n");
        return NULL;
    }

    // 读取文件内容到临时缓冲区
    size_t bytesRead = fread(tempBuffer, 1, fileSizeBytes, file);
    fclose(file);

    if (bytesRead != fileSizeBytes)
    {
        free(buffer);
        free(tempBuffer);
        fprintf(stderr, "读取文件失败: %s\n", filePath);
        return NULL;
    }

    // 将字节数据转换为64位BYTE值
    for (size_t i = 0; i < *fileSize; i++)
    {
        buffer[i] = 0;
        for (size_t j = 0; j < 8 && (i * 8 + j) < fileSizeBytes; j++)
        {
            buffer[i] |= ((BYTE)tempBuffer[i * 8 + j]) << (j * 8);
        }
    }

    free(tempBuffer);
    return buffer;
}

// 将字节数组写入文件 - 修改为支持64位BYTE类型
int writeFile(const char *filePath, const BYTE *data, size_t dataSize)
{
    FILE *file = fopen(filePath, "wb");
    if (!file)
    {
        fprintf(stderr, "无法创建文件: %s\n", filePath);
        return 0;
    }

    // 计算实际字节数 (每个BYTE包含8个字节)
    size_t totalBytes = dataSize * 8;

    // 临时缓冲区存储实际字节
    unsigned char *tempBuffer = (unsigned char *)malloc(totalBytes);
    if (!tempBuffer)
    {
        fclose(file);
        fprintf(stderr, "内存分配失败\n");
        return 0;
    }

    // 将64位BYTE值转换为字节数据
    for (size_t i = 0; i < dataSize; i++)
    {
        for (size_t j = 0; j < 8; j++)
        {
            tempBuffer[i * 8 + j] = (unsigned char)((data[i] >> (j * 8)) & 0xFF);
        }
    }

    // 写入文件
    size_t bytesWritten = fwrite(tempBuffer, 1, totalBytes, file);
    fclose(file);
    free(tempBuffer);

    if (bytesWritten != totalBytes)
    {
        fprintf(stderr, "写入文件失败: %s\n", filePath);
        return 0;
    }

    return 1;
}

void printUsage()
{
    printf("用法: e1des -p plainfile -k keyfile [-v vifile] -m mode -c cipherfile\n");
    printf("参数:\n");
    printf("  -p plainfile   指定明文文件的位置和名称\n");
    printf("  -k keyfile     指定密钥文件的位置和名称\n");
    printf("  -v vifile      指定初始化向量文件的位置和名称\n");
    printf("  -m mode        指定加密的操作模式 (ECB, CBC, CFB, OFB)\n");
    printf("  -c cipherfile  指定密文文件的位置和名称\n");
}

int main(int argc, char *argv[])
{
    // 参数解析
    char *plainFilePath = NULL;
    char *keyFilePath = NULL;
    char *ivFilePath = NULL;
    char *modeName = NULL;
    char *cipherFilePath = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "p:k:v:m:c:h")) != -1)
    {
        switch (opt)
        {
        case 'p':
            plainFilePath = optarg;
            break;
        case 'k':
            keyFilePath = optarg;
            break;
        case 'v':
            ivFilePath = optarg;
            break;
        case 'm':
            modeName = optarg;
            break;
        case 'c':
            cipherFilePath = optarg;
            break;
        case 'h':
            printUsage();
            return 0;
        default:
            printUsage();
            return 1;
        }
    }

    // 检查必要参数
    if (plainFilePath == NULL || keyFilePath == NULL || modeName == NULL || cipherFilePath == NULL)
    {
        fprintf(stderr, "错误: 缺少必要参数\n");
        printUsage();
        return 1;
    }

    // 解析加密模式
    EncryptionMode mode = parseMode(modeName);

    // 如果是CBC、CFB或OFB模式，需要初始化向量
    if ((mode == CBC || mode == CFB || mode == OFB) && ivFilePath == NULL)
    {
        fprintf(stderr, "错误: CBC、CFB和OFB模式需要指定初始化向量文件\n");
        return 1;
    }

    // 读取文件
    size_t plaintextSize, keySize, ivSize;
    BYTE *plaintext = readFile(plainFilePath, &plaintextSize);
    BYTE *key = readFile(keyFilePath, &keySize);
    BYTE *iv = NULL;

    if (!plaintext || !key)
    {
        if (plaintext)
            free(plaintext);
        if (key)
            free(key);
        return 1;
    }

    // 验证密钥大小
    if (keySize != KEY_SIZE)
    {
        fprintf(stderr, "错误: 密钥必须为8字节(64位)\n");
        free(plaintext);
        free(key);
        return 1;
    }

    // 如果需要，读取初始化向量
    if (ivFilePath != NULL)
    {
        iv = readFile(ivFilePath, &ivSize);
        if (!iv)
        {
            free(plaintext);
            free(key);
            return 1;
        }

        if (ivSize != IV_SIZE)
        {
            fprintf(stderr, "错误: 初始化向量必须为8字节(64位)\n");
            free(plaintext);
            free(key);
            free(iv);
            return 1;
        }
    }

    // 创建DES实例
    DES *des = DES_create();
    if (!des)
    {
        fprintf(stderr, "错误: 无法创建DES实例\n");
        free(plaintext);
        free(key);
        if (iv)
            free(iv);
        return 1;
    }

    // 设置密钥和初始化向量
    DES_setKey(des, key, keySize);
    if (iv != NULL)
    {
        DES_setIV(des, iv, ivSize);
    }

    // 执行加密
    size_t ciphertextSize;
    BYTE *ciphertext = DES_encrypt(des, plaintext, plaintextSize, mode, &ciphertextSize);

    if (ciphertext)
    {
        // 写入密文文件
        if (writeFile(cipherFilePath, ciphertext, ciphertextSize))
        {
            printf("加密完成，密文已写入: %s\n", cipherFilePath);
        }

        free(ciphertext);
    }
    else
    {
        fprintf(stderr, "加密失败\n");
    }

    // 清理
    DES_destroy(des);
    free(plaintext);
    free(key);
    if (iv)
        free(iv);

    return 0;
}