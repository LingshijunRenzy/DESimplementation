# DES加密实现项目的Makefile
# 编译器设置
CC = gcc
CFLAGS = -Wall -g

# 源文件和目标文件
SRCS = main.c DES.c workMode.c util.c
OBJS = $(SRCS:.c=.o)
TARGET = e1des

# 头文件
INCLUDES = -I.

# 速度测试目录和随机文件
SPEED_DIR = txts/speedtest
RANDOM_FILE = $(SPEED_DIR)/randomdata.txt

# 默认目标
all: $(TARGET)

# 编译可执行文件
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# 编译源文件为目标文件
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# 清理编译产物
clean:
	rm -f $(OBJS) $(TARGET)

# 运行测试
test: $(TARGET)
	./$(TARGET) -p txts/plain.txt -k txts/key.txt -v txts/iv.txt -m CBC -c txts/cipher.txt

# ECB模式测试
test-ecb: $(TARGET)
	./$(TARGET) -p txts/plain.txt -k txts/key.txt -m ECB -c txts/cipher_ecb.txt

# CBC模式测试
test-cbc: $(TARGET)
	./$(TARGET) -p txts/plain.txt -k txts/key.txt -v txts/iv.txt -m CBC -c txts/cipher_cbc.txt

# CFB模式测试
test-cfb: $(TARGET)
	./$(TARGET) -p txts/plain.txt -k txts/key.txt -v txts/iv.txt -m CFB -c txts/cipher_cfb.txt

# OFB模式测试
test-ofb: $(TARGET)
	./$(TARGET) -p txts/plain.txt -k txts/key.txt -v txts/iv.txt -m OFB -c txts/cipher_ofb.txt

# 解密测试
# ECB模式解密
test-dec-ecb: $(TARGET)
	./$(TARGET) -d -p txts/cipher_ecb.txt -k txts/key.txt -m ECB -c txts/plain_ecb.txt

# CBC模式解密
test-dec-cbc: $(TARGET)
	./$(TARGET) -d -p txts/cipher_cbc.txt -k txts/key.txt -v txts/iv.txt -m CBC -c txts/plain_cbc.txt

# CFB8模式解密
test-dec-cfb: $(TARGET)
	./$(TARGET) -d -p txts/cipher_cfb.txt -k txts/key.txt -v txts/iv.txt -m CFB -c txts/plain_cfb.txt

# OFB8模式解密
test-dec-ofb: $(TARGET)
	./$(TARGET) -d -p txts/cipher_ofb.txt -k txts/key.txt -v txts/iv.txt -m OFB -c txts/plain_ofb.txt

# 性能测试：对随机数据连续加解密20次，并报告时间和吞吐率
.PHONY: test-speed
test-speed: $(TARGET)
	@echo "=== Speed Test on $(RANDOM_FILE) ==="
	@for mode in ECB CBC CFB OFB; do \
		echo "-- $$mode --"; \
		start=`python3 -c 'import time; print(int(time.time()*1000))'`; \
		for i in $$(seq 1 20); do \
			./$(TARGET) -p $(SPEED_DIR)/randomdata.txt -k txts/key.txt -v txts/iv.txt -m $$mode -c $(SPEED_DIR)/enc_$$mode_$$i.bin; \
		done; \
		end=`python3 -c 'import time; print(int(time.time()*1000))'`; \
		diff=$$((end - start)); \
		echo "Encrypt $$mode: $$diff ms, $$(awk 'BEGIN{printf "%.2f", 20*5*1000/('$$diff')}') MB/s"; \
		start=`python3 -c 'import time; print(int(time.time()*1000))'`; \
		for i in $$(seq 1 20); do \
			./$(TARGET) -d -p $(SPEED_DIR)/enc_$$mode_$$i.bin -k txts/key.txt -v txts/iv.txt -m $$mode -c $(SPEED_DIR)/dec_$$mode_$$i.bin; \
		done; \
		end=`python3 -c 'import time; print(int(time.time()*1000))'`; \
		diff=$$((end - start)); \
		echo "Decrypt $$mode: $$diff ms, $$(awk 'BEGIN{printf "%.2f", 20*5*1000/('$$diff')}') MB/s"; \
	done

# 编译帮助
help:
	@echo "DES加密实现项目 Makefile"
	@echo "使用方法:"
	@echo "  make       - 编译项目"
	@echo "  make clean - 清理编译产物"
	@echo "  make test  - 运行默认测试(CBC模式)"
	@echo "  make test-ecb - 运行ECB模式测试"
	@echo "  make test-cbc - 运行CBC模式测试"
	@echo "  make test-cfb - 运行CFB模式测试"
	@echo "  make test-ofb - 运行OFB模式测试"
	@echo "  make test-dec-ecb - 运行ECB模式解密测试"
	@echo "  make test-dec-cbc - 运行CBC模式解密测试"
	@echo "  make test-dec-cfb - 运行CFB模式解密测试"
	@echo "  make test-dec-ofb - 运行OFB模式解密测试"

# 指定伪目标
.PHONY: all clean test test-ecb test-cbc test-cfb test-ofb help