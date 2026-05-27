# dm-safe
基于dm框架的磁盘分区加密，参考dm-crypt + LUKS 实现

## 构建

当前项目先集成 Linux 5.4.150 的 `drivers/md/dm-crypt.c`，以 out-of-tree
内核模块方式编译，输出模块名为 `dm-crypt.ko`：

```sh
make KERNEL_DIR=/path/to/linux-build-tree
```

如果目标内核只跑过 `modules_prepare`、没有完整 `Module.symvers`，modpost 会把
内核导出符号报成 unresolved；这种源码兼容验证可加：

```sh
make KERNEL_DIR=/path/to/linux-build-tree KBUILD_MODPOST_WARN=1
```

新内核源码树如果使用 GCC 15 构建，当前系统默认 GCC 过旧时需要显式指定：

```sh
make KERNEL_DIR=/path/to/linux-build-tree CC=gcc-15
```

批量验证本机内核源码树：

```sh
./scripts/build-matrix.sh
```

脚本只编译已经 `modules_prepare` 过的内核树；未准备的源码树会跳过。某个
版本编译失败时脚本会继续验证后续版本，最后用非 0 退出码表示有失败项。
