// filepath: /Users/lingshi/coding/DESimplementation/workMode.c
#include "workMode.h"
#include "enum.h"
#include <string.h>

// 主加密函数，根据模式调用相应的加密算法
BYTE *DES_encrypt(DES *des, BYTE *data, size_t dataSize, EncryptionMode mode, size_t *ciphertextSize)
{
    // 获取IV（假设DES结构体中有存储IV的成员）
    BYTE iv = des->iv;
    size_t ivSize = 1; // 假设IV大小为1个BYTE (64位)

    switch (mode)
    {
    case ECB:
        return ECB_encrypt(des, data, dataSize, ciphertextSize);
    case CBC:
        return CBC_encrypt(des, data, dataSize, &iv, ivSize, ciphertextSize);
    case CFB:
        return CFB_encrypt(des, data, dataSize, &iv, ivSize, ciphertextSize);
    case OFB:
        return OFB_encrypt(des, data, dataSize, &iv, ivSize, ciphertextSize);
    default:
        fprintf(stderr, "错误: 不支持的加密模式\n");
        return NULL;
    }
}

// 主解密函数，根据模式调用相应的解密算法
BYTE *DES_decrypt(DES *des, BYTE *data, size_t dataSize, EncryptionMode mode, size_t *plaintextSize)
{
    // 获取IV（假设DES结构体中有存储IV的成员）
    BYTE iv = des->iv;
    size_t ivSize = 1; // 假设IV大小为1个BYTE (64位)

    switch (mode)
    {
    case ECB:
        return ECB_decrypt(des, data, dataSize, plaintextSize);
    case CBC:
        return CBC_decrypt(des, data, dataSize, &iv, ivSize, plaintextSize);
    case CFB:
        return CFB_decrypt(des, data, dataSize, &iv, ivSize, plaintextSize);
    case OFB:
        return OFB_decrypt(des, data, dataSize, &iv, ivSize, plaintextSize);
    default:
        fprintf(stderr, "错误: 不支持的解密模式\n");
        return NULL;
    }
}

// ECB模式加密
BYTE *ECB_encrypt(DES *des, BYTE *data, size_t dataSize, size_t *ciphertextSize)
{
    *ciphertextSize = dataSize;
    BYTE *ciphertext = malloc(dataSize * sizeof(BYTE));
    if (!ciphertext)
    {
        fprintf(stderr, "内存分配失败\n");
        return NULL;
    }
    for (size_t i = 0; i < dataSize; i++)
    {
        ciphertext[i] = DES_encryptBlock(des, data[i]);
    }
    return ciphertext;
}

// ECB模式解密
BYTE *ECB_decrypt(DES *des, BYTE *data, size_t dataSize, size_t *plaintextSize)
{
    // 设置输出大小
    *plaintextSize = dataSize;

    // 分配内存存储解密后的数据
    BYTE *plaintext = (BYTE *)malloc(*plaintextSize * sizeof(BYTE));
    if (!plaintext)
    {
        fprintf(stderr, "内存分配失败\n");
        return NULL;
    }

    // 逐块解密
    for (size_t i = 0; i < dataSize; i++)
    {
        plaintext[i] = DES_decryptBlock(des, data[i]);
    }

    return plaintext;
}

// CBC模式加密
BYTE *CBC_encrypt(DES *des, BYTE *data, size_t dataSize, BYTE *iv, size_t ivSize, size_t *ciphertextSize)
{
    // 验证IV大小
    if (ivSize != 1) // 64位 = 1个BYTE
    {
        fprintf(stderr, "错误: IV大小必须为64位(1个BYTE)\n");
        return NULL;
    }

    // 设置输出大小
    *ciphertextSize = dataSize;

    // 分配内存存储加密后的数据
    BYTE *ciphertext = (BYTE *)malloc(*ciphertextSize * sizeof(BYTE));
    if (!ciphertext)
    {
        fprintf(stderr, "内存分配失败\n");
        return NULL;
    }

    // 第一个块与IV异或后加密
    BYTE previous = *iv;
    for (size_t i = 0; i < dataSize; i++)
    {
        BYTE current = data[i] ^ previous;
        ciphertext[i] = DES_encryptBlock(des, current);
        previous = ciphertext[i]; // 使用当前密文作为下一个块的IV
    }

    return ciphertext;
}

// CBC模式解密
BYTE *CBC_decrypt(DES *des, BYTE *data, size_t dataSize, BYTE *iv, size_t ivSize, size_t *plaintextSize)
{
    // 验证IV大小
    if (ivSize != 1) // 64位 = 1个BYTE
    {
        fprintf(stderr, "错误: IV大小必须为64位(1个BYTE)\n");
        return NULL;
    }

    // 设置输出大小
    *plaintextSize = dataSize;

    // 分配内存存储解密后的数据
    BYTE *plaintext = (BYTE *)malloc(*plaintextSize * sizeof(BYTE));
    if (!plaintext)
    {
        fprintf(stderr, "内存分配失败\n");
        return NULL;
    }

    // 第一个块解密后与IV异或
    BYTE previous = *iv;
    for (size_t i = 0; i < dataSize; i++)
    {
        BYTE decrypted = DES_decryptBlock(des, data[i]);
        plaintext[i] = decrypted ^ previous;
        previous = data[i]; // 使用当前密文作为下一个块的IV
    }

    return plaintext;
}

// CFB模式加密
BYTE *CFB_encrypt(DES *des, BYTE *data, size_t dataSize, BYTE *iv, size_t ivSize, size_t *ciphertextSize)
{
    // 验证IV大小
    if (ivSize != 1) // 64位 = 1个BYTE
    {
        fprintf(stderr, "错误: IV大小必须为64位(1个BYTE)\n");
        return NULL;
    }

    // 设置输出大小
    *ciphertextSize = dataSize;

    // 分配内存存储加密后的数据
    BYTE *ciphertext = (BYTE *)malloc(*ciphertextSize * sizeof(BYTE));
    if (!ciphertext)
    {
        fprintf(stderr, "内存分配失败\n");
        return NULL;
    }

    // 第一个块使用IV加密
    BYTE register_value = *iv;
    for (size_t i = 0; i < dataSize; i++)
    {
        BYTE encrypted_reg = DES_encryptBlock(des, register_value);
        ciphertext[i] = data[i] ^ encrypted_reg;
        register_value = ciphertext[i]; // 使用当前密文作为下一个寄存器值
    }

    return ciphertext;
}

// CFB模式解密
BYTE *CFB_decrypt(DES *des, BYTE *data, size_t dataSize, BYTE *iv, size_t ivSize, size_t *plaintextSize)
{
    // 验证IV大小
    if (ivSize != 1) // 64位 = 1个BYTE
    {
        fprintf(stderr, "错误: IV大小必须为64位(1个BYTE)\n");
        return NULL;
    }

    // 设置输出大小
    *plaintextSize = dataSize;

    // 分配内存存储解密后的数据
    BYTE *plaintext = (BYTE *)malloc(*plaintextSize * sizeof(BYTE));
    if (!plaintext)
    {
        fprintf(stderr, "内存分配失败\n");
        return NULL;
    }

    // 第一个块使用IV解密
    BYTE register_value = *iv;
    for (size_t i = 0; i < dataSize; i++)
    {
        BYTE encrypted_reg = DES_encryptBlock(des, register_value);
        plaintext[i] = data[i] ^ encrypted_reg;
        register_value = data[i]; // 使用当前密文作为下一个寄存器值
    }

    return plaintext;
}

// OFB模式加密
BYTE *OFB_encrypt(DES *des, BYTE *data, size_t dataSize, BYTE *iv, size_t ivSize, size_t *ciphertextSize)
{
    // 验证IV大小
    if (ivSize != 1) // 64位 = 1个BYTE
    {
        fprintf(stderr, "错误: IV大小必须为64位(1个BYTE)\n");
        return NULL;
    }

    // 设置输出大小
    *ciphertextSize = dataSize;

    // 分配内存存储加密后的数据
    BYTE *ciphertext = (BYTE *)malloc(*ciphertextSize * sizeof(BYTE));
    if (!ciphertext)
    {
        fprintf(stderr, "内存分配失败\n");
        return NULL;
    }

    // 第一个块使用IV加密
    BYTE register_value = *iv;
    for (size_t i = 0; i < dataSize; i++)
    {
        register_value = DES_encryptBlock(des, register_value);
        ciphertext[i] = data[i] ^ register_value;
    }

    return ciphertext;
}

// OFB模式解密 (与加密相同)
BYTE *OFB_decrypt(DES *des, BYTE *data, size_t dataSize, BYTE *iv, size_t ivSize, size_t *plaintextSize)
{
    // OFB模式下，解密与加密过程相同
    return OFB_encrypt(des, data, dataSize, iv, ivSize, plaintextSize);
}

// 8-bit CFB 加密
unsigned char *CFB8_encrypt(DES *des, unsigned char *data, size_t dataSize, BYTE iv, size_t *ciphertextSize)
{
    *ciphertextSize = dataSize;
    unsigned char *out = (unsigned char *)malloc(dataSize);
    if (!out)
        return NULL;
    BYTE reg = iv;
    for (size_t i = 0; i < dataSize; i++)
    {
        BYTE enc = DES_encryptBlock(des, reg);
        unsigned char msb = (enc >> 56) & 0xFF;
        unsigned char c = data[i] ^ msb;
        out[i] = c;
        // 移位寄存器左移8位, 低8位插入密文字节
        reg = (reg << 8) | c;
    }
    return out;
}

// 8-bit OFB 加密
unsigned char *OFB8_encrypt(DES *des, unsigned char *data, size_t dataSize, BYTE iv, size_t *ciphertextSize)
{
    *ciphertextSize = dataSize;
    unsigned char *out = (unsigned char *)malloc(dataSize);
    if (!out)
        return NULL;
    BYTE reg = iv;
    for (size_t i = 0; i < dataSize; i++)
    {
        BYTE enc = DES_encryptBlock(des, reg);
        unsigned char msb = (enc >> 56) & 0xFF;
        unsigned char c = data[i] ^ msb;
        out[i] = c;
        // 寄存器左移8位, 插入当前输出（伪随机）字节
        reg = (reg << 8) | msb;
    }
    return out;
}

// 8-bit CFB 解密
unsigned char *CFB8_decrypt(DES *des, unsigned char *data, size_t dataSize, BYTE iv, size_t *plaintextSize)
{
    *plaintextSize = dataSize;
    unsigned char *out = malloc(dataSize);
    if (!out)
        return NULL;
    BYTE reg = iv;
    for (size_t i = 0; i < dataSize; i++)
    {
        BYTE enc = DES_encryptBlock(des, reg);
        unsigned char msb = (enc >> 56) & 0xFF;
        unsigned char p = data[i] ^ msb;
        out[i] = p;
        // 更新寄存器：插入密文字节
        reg = (reg << 8) | data[i];
    }
    return out;
}

// 8-bit OFB 解密 (与加密相同)
unsigned char *OFB8_decrypt(DES *des, unsigned char *data, size_t dataSize, BYTE iv, size_t *plaintextSize)
{
    // OFB 解密与加密相同
    return OFB8_encrypt(des, data, dataSize, iv, plaintextSize);
}