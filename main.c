#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include "getopt.h" // 从第三方源码拷贝到项目
#else
#include <getopt.h>
#endif
#include <stdbool.h>
#include "DES.h"
#include "enum.h"
#include "util.h"     // 引入util.h头文件
#include "workMode.h" // 引入workMode.h头文件

// DES相关常量定义
#define BLOCK_SIZE 1 // 现在1个BYTE代表一个64位块
#define KEY_SIZE 1   // 密钥大小为1个BYTE (64位)
#define IV_SIZE 1    // 初始化向量大小为1个BYTE (64位)

int main(int argc, char *argv[])
{
    // 参数解析
    char *plainFilePath = NULL;
    char *keyFilePath = NULL;
    char *ivFilePath = NULL;
    char *modeName = NULL;
    char *cipherFilePath = NULL;
    bool decrypt = false;

    int opt;
    while ((opt = getopt(argc, argv, "p:k:v:m:c:hd")) != -1)
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
        case 'd':
            decrypt = true;
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
        fprintf(stderr, "Error: Missing required arguments\n");
        printUsage();
        return 1;
    }

    // 解析加密模式
    EncryptionMode mode = parseMode(modeName);

    // 如果是CBC、CFB或OFB模式，需要初始化向量
    if ((mode == CBC || mode == CFB || mode == OFB) && ivFilePath == NULL)
    {
        fprintf(stderr, "Error: CBC, CFB and OFB modes require an IV file\n");
        return 1;
    }

    // 读取文件
    size_t plaintextSize = 0, keySize = 0, ivSize = 0;
    BYTE *plaintext = NULL, *key = NULL, *iv = NULL;
    int ret = 0;

    // 先读取明文
    plaintext = readHexFile(plainFilePath, &plaintextSize);
    if (!plaintext)
    {
        fprintf(stderr, "Error: Unable to read plaintext file\n");
        return 1;
    }

    // 读取密钥
    key = readHexFile(keyFilePath, &keySize);
    if (!key)
    {
        fprintf(stderr, "Error: Unable to read key file\n");
        free(plaintext);
        return 1;
    }

    // 验证密钥大小
    if (keySize != KEY_SIZE)
    {
        fprintf(stderr, "Error: Key must be 16 hexadecimal characters (64 bits)\n");
        free(plaintext);
        free(key);
        return 1;
    }

    // 如果需要，读取初始化向量
    if (ivFilePath != NULL)
    {
        iv = readHexFile(ivFilePath, &ivSize);
        if (!iv)
        {
            fprintf(stderr, "Error: Unable to read IV file\n");
            free(plaintext);
            free(key);
            return 1;
        }

        if (ivSize != IV_SIZE)
        {
            fprintf(stderr, "Error: IV must be 16 hexadecimal characters (64 bits)\n");
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
        fprintf(stderr, "Error: Unable to create DES instance\n");
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

    // 解密流程
    if (decrypt)
    {
        // CFB8 解密
        if (mode == CFB)
        {
            // 读取密文字节数组
            size_t ctSize8;
            unsigned char *ct8 = readHexFile8(plainFilePath, &ctSize8);
            if (!ct8)
            {
                fprintf(stderr, "Error: Unable to read ciphertext file\n");
                return 1;
            }
            size_t ptSize8;
            unsigned char *pt8 = CFB8_decrypt(des, ct8, ctSize8, iv[0], &ptSize8);
            if (pt8 && writeHexByteFile(cipherFilePath, pt8, ptSize8))
            {
                printf("Decryption complete, plaintext written to: %s\n", cipherFilePath);
                ret = 0;
            }
            else
            {
                fprintf(stderr, "Error: CFB8 decryption failed\n");
            }
            free(ct8);
            free(pt8);
            DES_destroy(des);
            free(plaintext);
            free(key);
            if (iv)
                free(iv);
            return ret;
        }
        // OFB8 解密
        if (mode == OFB)
        {
            size_t ctSize8;
            unsigned char *ct8 = readHexFile8(plainFilePath, &ctSize8);
            if (!ct8)
            {
                fprintf(stderr, "Error: Unable to read ciphertext file\n");
                return 1;
            }
            size_t ptSize8;
            unsigned char *pt8 = OFB8_decrypt(des, ct8, ctSize8, iv[0], &ptSize8);
            if (pt8 && writeHexByteFile(cipherFilePath, pt8, ptSize8))
            {
                printf("Decryption complete, plaintext written to: %s\n", cipherFilePath);
                ret = 0;
            }
            else
            {
                fprintf(stderr, "Error: OFB8 decryption failed\n");
            }
            free(ct8);
            free(pt8);
            DES_destroy(des);
            free(plaintext);
            free(key);
            if (iv)
                free(iv);
            return ret;
        }
        // 其余模式块解密
        size_t plainOutSize = 0;
        BYTE *plainOut = DES_decrypt(des, plaintext, plaintextSize, mode, &plainOutSize);
        if (plainOut && writeHexFile(cipherFilePath, plainOut, plainOutSize))
        {
            printf("Decryption complete, plaintext written to: %s\n", cipherFilePath);
            ret = 0;
        }
        else
        {
            fprintf(stderr, "Error: Decryption failed\n");
        }
        free(plainOut);
        DES_destroy(des);
        free(plaintext);
        free(key);
        if (iv)
            free(iv);
        return ret;
    }

    // CFB8 模式
    if (mode == CFB)
    {
        size_t ptSize8;
        unsigned char *pt8 = readHexFile8(plainFilePath, &ptSize8);
        if (!pt8)
        {
            fprintf(stderr, "Error: Failed to read plaintext\n");
            return 1;
        }
        size_t ctSize8;
        unsigned char *ct8 = CFB8_encrypt(des, pt8, ptSize8, iv[0], &ctSize8);
        if (ct8 && writeHexByteFile(cipherFilePath, ct8, ctSize8))
        {
            printf("Encryption complete, ciphertext written to: %s\n", cipherFilePath);
            ret = 0;
        }
        else
        {
            fprintf(stderr, "Error: CFB8 encryption failed\n");
        }
        free(pt8);
        free(ct8);
        DES_destroy(des);
        free(plaintext);
        free(key);
        free(iv);
        return ret;
    }
    // OFB8 模式
    if (mode == OFB)
    {
        size_t ptSize8;
        unsigned char *pt8 = readHexFile8(plainFilePath, &ptSize8);
        if (!pt8)
        {
            fprintf(stderr, "Error: Failed to read plaintext\n");
            return 1;
        }
        size_t ctSize8;
        unsigned char *ct8 = OFB8_encrypt(des, pt8, ptSize8, iv[0], &ctSize8);
        if (ct8 && writeHexByteFile(cipherFilePath, ct8, ctSize8))
        {
            printf("Encryption complete, ciphertext written to: %s\n", cipherFilePath);
            ret = 0;
        }
        else
        {
            fprintf(stderr, "Error: OFB8 encryption failed\n");
        }
        free(pt8);
        free(ct8);
        DES_destroy(des);
        free(plaintext);
        free(key);
        free(iv);
        return ret;
    }

    // 执行加密
    size_t ciphertextSize;
    BYTE *ciphertext = DES_encrypt(des, plaintext, plaintextSize, mode, &ciphertextSize);

    // 初始化返回值
    ret = 1;

    if (ciphertext)
    {
        // 写入密文文件（以十六进制文本格式）
        if (writeHexFile(cipherFilePath, ciphertext, ciphertextSize))
        {
            printf("Encryption complete, ciphertext written to: %s\n", cipherFilePath);
            ret = 0; // 成功
        }
        else
        {
            fprintf(stderr, "Error: Failed to write ciphertext file\n");
        }

        free(ciphertext);
    }
    else
    {
        fprintf(stderr, "Error: Encryption failed\n");
    }

    // 清理
    DES_destroy(des);
    free(plaintext);
    free(key);
    if (iv)
        free(iv);

    return ret;
}