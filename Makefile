# 这是外置内核模块使用的 Kbuild Makefile。
#
# 用法示例：
#   make KERNEL_DIR=/lib/modules/$(uname -r)/build
#
# 外置模块不是在内核源码树里编译，所以要通过 `make -C <kernel-build-tree> M=<本目录>`
# 让内核 Kbuild 系统进入本项目目录并读取这个文件。

# 默认编译当前正在运行的内核；脚本可以通过 osVersion 覆盖为目标内核版本。
osVersion     ?= $(shell uname -r)

# 目标内核的 build 目录，里面必须有已准备好的内核头文件和 Kbuild 生成文件。
KERNEL_DIR    ?= /lib/modules/$(osVersion)/build

# 生成的模块名是 dm-andsec.ko。
obj-m += dm-andsec.o

# dm-andsec.ko 由 src/dm-andsec.o 链接而来。后续如果拆分文件，可继续往这里追加。
dm-andsec-y := src/dm-andsec.o

# 把项目 src 目录加入头文件搜索路径，方便后续放本项目自己的兼容头或公共头。
ccflags-y += -I$(src)/src

.PHONY: all modules clean debug

# debug/all/modules 都走内核模块构建目标。这里的 debug 只是为了兼容现有脚本命名，
# 不代表额外打开调试选项。
debug all modules:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) modules

# 清理 Kbuild 生成的 .o/.ko/.mod.c/Module.symvers 等文件。
clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) clean
