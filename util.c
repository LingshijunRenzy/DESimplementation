#include "util.h"
#include "enum.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

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

    fprintf(stderr, "Unsupported encryption mode: %s\n", modeStr);
    exit(1);
}

// 读取文件内容到字节数组 - 修改为支持64位BYTE类型
BYTE *readFile(const char *filePath, size_t *fileSize)
{
    FILE *file = fopen(filePath, "rb");
    if (!file)
    {
        fprintf(stderr, "Error: Unable to open file: %s\n", filePath);
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
        fprintf(stderr, "Error: Memory allocation failed\n");
        return NULL;
    }

    // 临时缓冲区存储实际字节
    unsigned char *tempBuffer = (unsigned char *)malloc(fileSizeBytes);
    if (!tempBuffer)
    {
        free(buffer);
        fclose(file);
        fprintf(stderr, "Error: Memory allocation failed\n");
        return NULL;
    }

    // 读取文件内容到临时缓冲区
    size_t bytesRead = fread(tempBuffer, 1, fileSizeBytes, file);
    fclose(file);

    if (bytesRead != fileSizeBytes)
    {
        free(buffer);
        free(tempBuffer);
        fprintf(stderr, "Error: Failed to read file: %s\n", filePath);
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
        fprintf(stderr, "Error: Unable to create file: %s\n", filePath);
        return 0;
    }

    // 计算实际字节数 (每个BYTE包含8个字节)
    size_t totalBytes = dataSize * 8;

    // 临时缓冲区存储实际字节
    unsigned char *tempBuffer = (unsigned char *)malloc(totalBytes);
    if (!tempBuffer)
    {
        fclose(file);
        fprintf(stderr, "Error: Memory allocation failed\n");
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
        fprintf(stderr, "Error: Failed to write file: %s\n", filePath);
        return 0;
    }

    return 1;
}

// 从十六进制字符串读取一个字节
static int hex2byte(char c)
{
    c = tolower((unsigned char)c);
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1; // 非法十六进制字符
}

// 读取十六进制文本文件内容到BYTE数组 (使用大端序)
BYTE *readHexFile(const char *filePath, size_t *byteSize)
{
    FILE *file = fopen(filePath, "r");
    if (!file)
    {
        fprintf(stderr, "Error: Unable to open file: %s\n", filePath);
        return NULL;
    }

    // 获取文件大小
    fseek(file, 0, SEEK_END);
    size_t fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // 分配缓冲区来存储文件内容
    char *buffer = (char *)malloc(fileSize + 1);
    if (!buffer)
    {
        fclose(file);
        fprintf(stderr, "Error: Memory allocation failed\n");
        return NULL;
    }

    // 读取文件内容
    size_t bytesRead = fread(buffer, 1, fileSize, file);
    fclose(file);

    if (bytesRead != fileSize)
    {
        free(buffer);
        fprintf(stderr, "Error: Failed to read file: %s\n", filePath);
        return NULL;
    }

    buffer[bytesRead] = '\0'; // 确保字符串结束

    // 移除任何空白字符、换行符等
    char *hexString = (char *)malloc(fileSize + 1);
    if (!hexString)
    {
        free(buffer);
        fprintf(stderr, "Error: Memory allocation failed\n");
        return NULL;
    }

    size_t hexLen = 0;
    for (size_t i = 0; i < bytesRead; i++)
    {
        if (isxdigit((unsigned char)buffer[i]))
        {
            hexString[hexLen++] = buffer[i];
        }
    }
    hexString[hexLen] = '\0';

    free(buffer);

    // 检查十六进制字符串长度是否有效
    if (hexLen % 2 != 0)
    {
        free(hexString);
        fprintf(stderr, "Error: Invalid hexadecimal string length: %s\n", filePath);
        return NULL;
    }

    // 计算需要的BYTE数量 (每16个十六进制字符一个BYTE)
    size_t numBytes = hexLen / 16;
    if (hexLen % 16 != 0)
    {
        numBytes++; // 不完整的BYTE
    }
    *byteSize = numBytes;

    // 分配BYTE数组
    BYTE *result = (BYTE *)malloc(numBytes * sizeof(BYTE));
    if (!result)
    {
        free(hexString);
        fprintf(stderr, "Error: Memory allocation failed\n");
        return NULL;
    }

    // 将十六进制字符串转换为BYTE值 (使用大端序)
    memset(result, 0, numBytes * sizeof(BYTE));

    for (size_t i = 0; i < hexLen; i += 2)
    {
        int highNibble = hex2byte(hexString[i]);
        int lowNibble = hex2byte(hexString[i + 1]);

        if (highNibble == -1 || lowNibble == -1)
        {
            free(hexString);
            free(result);
            fprintf(stderr, "Error: Invalid hexadecimal character: %s\n", filePath);
            return NULL;
        }

        unsigned char byte = (highNibble << 4) | lowNibble;
        size_t byteIndex = i / 2;
        size_t byteArrayIndex = byteIndex / 8;

        // 使用大端序 - 修改这里的位置计算，使最高有效字节在前
        size_t bytePosition = 7 - (byteIndex % 8); // 7, 6, 5, 4, 3, 2, 1, 0
        size_t bitShift = bytePosition * 8;

        result[byteArrayIndex] |= ((BYTE)byte << bitShift);
    }

    free(hexString);
    return result;
}

// 读取十六进制文本文件到8位字节数组，每对16进制字符一个字节
unsigned char *readHexFile8(const char *filePath, size_t *outSize)
{
    FILE *f = fopen(filePath, "r");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(len + 1);
    fread(buf, 1, len, f);
    fclose(f);
    buf[len] = '\0';
    // 去除非hex
    char *h = malloc(len + 1);
    size_t hl = 0;
    for (size_t i = 0; i < len; i++)
        if (isxdigit(buf[i]))
            h[hl++] = buf[i];
    h[hl] = '\0';
    free(buf);
    if (hl % 2)
    {
        free(h);
        return NULL;
    }
    *outSize = hl / 2;
    unsigned char *out = malloc(*outSize);
    for (size_t i = 0; i < *outSize; i++)
    {
        int hi = hex2byte(h[2 * i]), lo = hex2byte(h[2 * i + 1]);
        out[i] = (hi << 4) | lo;
    }
    free(h);
    return out;
}

// 将BYTE数组写入为十六进制文本文件 (使用大端序)
int writeHexFile(const char *filePath, const BYTE *data, size_t dataSize)
{
    FILE *file = fopen(filePath, "w");
    if (!file)
    {
        fprintf(stderr, "Error: Unable to create file: %s\n", filePath);
        return 0;
    }

    // 每个BYTE值写入16个十六进制字符 (使用大端序)
    for (size_t i = 0; i < dataSize; i++)
    {
        // 使用大端序输出 - 从最高有效字节开始
        for (size_t j = 0; j < 8; j++)
        {
            // 使用大端序: 从高字节到低字节 (7, 6, 5, 4, 3, 2, 1, 0)
            size_t bytePosition = 7 - j;
            unsigned char byte = (data[i] >> (bytePosition * 8)) & 0xFF;
            fprintf(file, "%02X", byte);
        }
    }

    fclose(file);
    return 1;
}

// 将8位字节数组写入十六进制文本，每字节2字符
int writeHexByteFile(const char *filePath, const unsigned char *data, size_t dataSize)
{
    FILE *f = fopen(filePath, "w");
    if (!f)
        return 0;
    for (size_t i = 0; i < dataSize; i++)
    {
        fprintf(f, "%02X", data[i]);
    }
    fclose(f);
    return 1;
}

void printUsage()
{
    printf("Usage: e1des -p plainfile -k keyfile [-v ivfile] -m mode -c cipherfile [-d]\n");
    printf("Options:\n");
    printf("  -p plainfile   Specify the path to the plaintext file\n");
    printf("  -k keyfile     Specify the path to the key file\n");
    printf("  -v ivfile      Specify the path to the IV file\n");
    printf("  -m mode        Specify the encryption mode (ECB, CBC, CFB, OFB)\n");
    printf("  -c cipherfile  Specify the path to the ciphertext file\n");
    printf("  -d             Decrypt mode (optional)\n");
}