#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include "DES.h"

// 将字符串转换为加密模式枚举
EncryptionMode parseMode(const char *modeStr);

// 文件读写函数 - 二进制格式
BYTE *readFile(const char *filePath, size_t *fileSize);
int writeFile(const char *filePath, const BYTE *data, size_t dataSize);

// 文件读写函数 - 十六进制文本格式
BYTE *readHexFile(const char *filePath, size_t *byteSize);
unsigned char *readHexFile8(const char *filePath, size_t *outSize);
int writeHexFile(const char *filePath, const BYTE *data, size_t dataSize);

// 写入十六进制文本文件，每个字节2个hex字符，用于CFB/OFB 8-bit模式
int writeHexByteFile(const char *filePath, const unsigned char *data, size_t dataSize);

// 帮助信息
void printUsage();

#endif // UTIL_H