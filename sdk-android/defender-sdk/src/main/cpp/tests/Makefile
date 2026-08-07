# 宿主端单元测试(PC 上跑,不需 Android/NDK)
#
# 用法:
#   make            # 编译全部
#   make test       # 编译并逐个运行(任一失败则非零退出)
#   make clean
#
# 说明:
#   - android/log.h 由 host/ 下宿主桩提供(-Ihost),defender_log.h 可在 PC 编译。
#   - test_hash_calculator.c 以 #include 方式并入 hash_calculator.c 以测 static 函数,
#     故不单独编译 hash_calculator.c;integrity.c 提供 defender_sha256,
#     hash_storage.c 提供 get_embedded_hash。

CC      = gcc
CFLAGS  ?= -O2 -DNDEBUG -Wall -Ihost -I..
LDLIBS_HASH = -lz -lpthread

TESTS = t_so_cipher t_obfstr_poly t_hash

all: $(TESTS)

# so_cipher.h / obfstr_poly.h 为 header-only(static inline),只需头文件。
t_so_cipher: test_so_cipher.c ../so_cipher.h
	$(CC) $(CFLAGS) -o $@ test_so_cipher.c

t_obfstr_poly: test_obfstr_poly.c ../obfstr_poly.h test_vectors_generated.h
	$(CC) $(CFLAGS) -o $@ test_obfstr_poly.c

t_hash: test_hash_calculator.c ../hash_calculator.c ../integrity.c ../hash_storage.c
	$(CC) $(CFLAGS) -o $@ test_hash_calculator.c ../integrity.c ../hash_storage.c $(LDLIBS_HASH)

test: $(TESTS)
	@set -e; for t in $(TESTS); do echo "== $$t =="; ./$$t; done

clean:
	rm -f $(TESTS) *.exe *.o c_synth_apk.bin

.PHONY: all test clean
