#ifndef ENUM_H
#define ENUM_H

// 加密模式枚举
typedef enum
{
    ECB, // Electronic Code Book
    CBC, // Cipher Block Chaining
    CFB, // Cipher Feedback
    OFB  // Output Feedback
} EncryptionMode;

#endif // ENUM_H