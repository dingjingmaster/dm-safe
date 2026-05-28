# dm-safe
基于 Device Mapper 框架的 `dm-andsec` 透传 target。当前实现只把 IO 线性映射到底层
块设备，不做加密、解密、key、IV 或完整性 tag 处理，后续可按需补充自己的处理逻辑。

## 构建

当前项目以 out-of-tree 内核模块方式编译，输出模块名为 `dm-andsec.ko`，注册的
Device Mapper target 名为 `andsec`：

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

如果批量验证的新内核源码树需要 GCC 15，可指定：

```sh
CC=gcc-15 ./scripts/build-matrix.sh
```

脚本只编译已经 `modules_prepare` 过的内核树；未准备的源码树会跳过。某个
版本编译失败时脚本会继续验证后续版本，最后用非 0 退出码表示有失败项。

## 映射参数

推荐使用新的透传参数格式：

```sh
dmsetup create andsec0 --table "0 <sectors> andsec <dev_path> <start>"
```

为方便从旧表迁移，`andsec` 也接受原固定参数格式，并忽略 cipher/key/iv/options：

```sh
dmsetup create andsec0 --table "0 <sectors> andsec <cipher> <key> <iv_offset> <dev_path> <start>"
```
