#ifndef WORKMODE_H
#define WORKMODE_H
#include <stdio.h>
#include "DES.h"

BYTE *DES_encrypt(DES *des, BYTE *data, size_t dataSize, EncryptionMode mode, size_t *ciphertextSize);
BYTE *DES_decrypt(DES *des, BYTE *data, size_t dataSize, EncryptionMode mode, size_t *plaintextSize);

BYTE *ECB_encrypt(DES *des, BYTE *data, size_t dataSize, size_t *ciphertextSize);
BYTE *ECB_decrypt(DES *des, BYTE *data, size_t dataSize, size_t *plaintextSize);

BYTE *CBC_encrypt(DES *des, BYTE *data, size_t dataSize, BYTE *iv, size_t ivSize, size_t *ciphertextSize);
BYTE *CBC_decrypt(DES *des, BYTE *data, size_t dataSize, BYTE *iv, size_t ivSize, size_t *plaintextSize);

BYTE *CFB_encrypt(DES *des, BYTE *data, size_t dataSize, BYTE *iv, size_t ivSize, size_t *ciphertextSize);
BYTE *CFB_decrypt(DES *des, BYTE *data, size_t dataSize, BYTE *iv, size_t ivSize, size_t *plaintextSize);

BYTE *OFB_encrypt(DES *des, BYTE *data, size_t dataSize, BYTE *iv, size_t ivSize, size_t *ciphertextSize);
BYTE *OFB_decrypt(DES *des, BYTE *data, size_t dataSize, BYTE *iv, size_t ivSize, size_t *plaintextSize);

// 8-bit CFB 和 OFB 模式加密
unsigned char *CFB8_encrypt(DES *des, unsigned char *data, size_t dataSize, BYTE iv, size_t *ciphertextSize);
unsigned char *OFB8_encrypt(DES *des, unsigned char *data, size_t dataSize, BYTE iv, size_t *ciphertextSize);

// 8-bit CFB 和 OFB 模式解密
unsigned char *CFB8_decrypt(DES *des, unsigned char *data, size_t dataSize, BYTE iv, size_t *plaintextSize);
unsigned char *OFB8_decrypt(DES *des, unsigned char *data, size_t dataSize, BYTE iv, size_t *plaintextSize);

#endif