#ifndef WORKMODE_H
#define WORKMODE_H
#include <stdio.h>
#include "DES.h"

BYTE DES_encrypt(DES *des, BYTE *data, size_t dataSize, EncryptionMode mode, size_t *ciphertextSize);
BYTE DES_decrypt(DES *des, BYTE *data, size_t dataSize, EncryptionMode mode, size_t *plaintextSize);

BYTE *ECB_encrypt(DES *des, BYTE *data, size_t dataSize, size_t *ciphertextSize);
BYTE *ECB_decrypt(DES *des, BYTE *data, size_t dataSize, size_t *plaintextSize);

BYTE *CBC_encrypt(DES *des, BYTE *data, size_t dataSize, BYTE *iv, size_t ivSize, size_t *ciphertextSize);
BYTE *CBC_decrypt(DES *des, BYTE *data, size_t dataSize, BYTE *iv, size_t ivSize, size_t *plaintextSize);

BYTE *CFB_encrypt(DES *des, BYTE *data, size_t dataSize, BYTE *iv, size_t ivSize, size_t *ciphertextSize);
BYTE *CFB_decrypt(DES *des, BYTE *data, size_t dataSize, BYTE *iv, size_t ivSize, size_t *plaintextSize);

BYTE *OFB_encrypt(DES *des, BYTE *data, size_t dataSize, BYTE *iv, size_t ivSize, size_t *ciphertextSize);
BYTE *OFB_decrypt(DES *des, BYTE *data, size_t dataSize, BYTE *iv, size_t ivSize, size_t *plaintextSize);

#endif