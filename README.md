# DES 实现项目

## 项目简介
本项目使用 C 语言实现了标准的 DES（Data Encryption Standard）算法，支持以下四种工作模式：

- **ECB** (Electronic Code Book)
- **CBC** (Cipher Block Chaining)
- **CFB-8** (Cipher Feedback，8 位反馈)
- **OFB-8** (Output Feedback，8 位反馈)

同时提供加密和解密功能，并支持大文件的性能测试。

## 文件结构
```
DESimplementation/
├── DES.c, DES.h            // DES 算法核心实现
├── DESConstants.h         // DES 常量表
├── workMode.c, workMode.h  // 四种工作模式（ECB/CBC/CFB8/OFB8）实现
├── util.c, util.h         // 文件读取/写入与十六进制转换工具
├── main.c                 // 命令行接口，参数解析和流程控制
├── enum.h                 // 加密模式枚举定义
├── Makefile               // 构建与测试规则
├── README.md              // 项目说明
└── txts/                  // 测试数据与结果目录
    ├── plain.txt          // 原始明文(十六进制文本)
    ├── key.txt            // 密钥文件(16 字符 hex)
    ├── iv.txt             // 初始化向量文件(16 字符 hex)
    ├── cipher_ecb.txt     // ECB 模式密文
    ├── cipher_cbc.txt     // CBC 模式密文
    ├── cipher_cfb.txt     // CFB-8 模式密文
    ├── cipher_ofb.txt     // OFB-8 模式密文
    ├── plain_*.txt        // 各模式解密输出
    └── speedtest/         // 性能测试脚本与数据
        ├── randomdata.txt // 用于速度测试的 5 MB 随机数据
        └── speed_test.py  // 性能测试脚本
```

## 命令行参数
```
e1des -p <文件> -k <文件> [-v <文件>] -m <模式> [-d] -c <输出>
```
- `-p <plainfile>`: 明文或密文输入文件 (十六进制文本格式)  
- `-k <keyfile>`: 密钥文件，16 个 hex 字符 (64 位)  
- `-v <ivfile>`: IV 文件，16 个 hex 字符 (仅 CBC/CFB/OFB 模式需指定)  
- `-m <mode>`: 模式名称，可选 `ECB|CBC|CFB|OFB`  
- `-d`: 指定后执行**解密**；不加则执行加密  
- `-c <cipherfile>`: 输出文件路径  

## 构建与测试
1. 编译项目：
   ```bash
   make
   ```
2. 快速功能测试：
   ```bash
   make test-ecb      # 测试 ECB 加密
   make test-cbc      # 测试 CBC 加密
   make test-cfb      # 测试 CFB-8 加密
   make test-ofb      # 测试 OFB-8 加密
   make test-dec-ecb  # 测试 ECB 解密
   make test-dec-cbc  # 测试 CBC 解密
   make test-dec-cfb  # 测试 CFB-8 解密
   make test-dec-ofb  # 测试 OFB-8 解密
   ```
3. 性能测试 (Python 脚本)：
   ```bash
   cd txts/speedtest
   chmod +x data_generator.py
   chmod +x speed_test.py
   ./data_generator.py
   ```
   生成 5 MB 随机数据文件 `randomdata.txt`，用于性能测试。  
   ```bash
   ./speed_test.py
   ```
   执行后会生成 `test_report_YYYY-MM-DD-HH-MM-SS.log`，记录 20 次加/解密的总耗时和吞吐率。

## 注意事项
- 需安装 **Python 3**，用于速度测试脚本和十六进制毫秒计算。  
- 输入输出文件均为十六进制文本，CFB/OFB 模式按 8 bit 反馈。  
- 解密时请务必加上 `-d` 参数，否则程序默认执行加密。  

---