#!/usr/bin/env sh
set -eu

# 项目根目录。脚本可能从任意目录执行，所以先根据脚本路径反推仓库根。
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

# 允许外部通过 MAKE=... 指定 make 命令，例如 MAKE=make-4.4。
MAKE_CMD=${MAKE:-make}

# 只要有一个内核构建失败，最后就用非 0 退出；但中间继续跑后续版本。
status=0

run_make()
{
	# 允许外部通过 CC=... 指定和目标内核一致的编译器，例如 CC=gcc-15。
	if [ -n "${CC:-}" ]; then
		"$MAKE_CMD" "$@" CC="$CC"
	else
		"$MAKE_CMD" "$@"
	fi
}

if [ "$#" -eq 0 ]; then
	# 不传参数时，默认验证这些本机源码树。传参数时，每个参数都是一个内核构建目录。
	set -- \
		/data/kernel/linux-4.19.1 \
		/data/kernel/linux-5.4.150 \
		/data/kernel/linux-6.12.1 \
		/data/kernel/linux-6.14.0 \
		/data/kernel/linux-6.16.12 \
		/data/kernel/linux-6.17.1
fi

case "${ARCH:-$(uname -m)}" in
	x86_64|i?86)
		kernel_arch=x86
		;;
	aarch64)
		kernel_arch=arm64
		;;
	*)
		kernel_arch=${ARCH:-$(uname -m)}
		;;
esac

for kernel_dir in "$@"; do
	printf '\n==> %s\n' "$kernel_dir"

	# 外置模块编译至少需要 modules_prepare 生成 include/generated/autoconf.h。
	# 如果这里只是原始源码树，直接跳过，避免输出一大串 Kbuild 报错。
	if [ ! -e "$kernel_dir/include/generated/autoconf.h" ]; then
		printf 'skip: kernel tree is not prepared; run modules_prepare first or pass an O= build directory\n'
		continue
	fi
	if [ ! -e "$kernel_dir/arch/$kernel_arch/include/generated/uapi/asm/types.h" ] &&
		[ ! -e "$kernel_dir/arch/$kernel_arch/include/uapi/asm/types.h" ]; then
		printf 'skip: kernel tree is missing generated asm headers; run modules_prepare first or pass an O= build directory\n'
		continue
	fi

	# 没有 Module.symvers 时，modpost 无法确认内核导出符号，会把很多符号报成
	# 未解析符号。做源码兼容性验证时可降级成警告，让编译继续走完。
	modpost_warn=${KBUILD_MODPOST_WARN:-}
	if [ -z "$modpost_warn" ] && [ ! -e "$kernel_dir/Module.symvers" ]; then
		modpost_warn=1
	fi

	# M="$ROOT" 告诉内核 Kbuild：外置模块源码在本项目根目录。
	if [ -n "$modpost_warn" ]; then
		if ! run_make -C "$kernel_dir" M="$ROOT" KBUILD_MODPOST_WARN="$modpost_warn" modules; then
			status=1
			continue
		fi
	else
		if ! run_make -C "$kernel_dir" M="$ROOT" modules; then
			status=1
			continue
		fi
	fi

	# 每个版本编完后清理本项目生成物，避免下一个内核版本复用旧的 .o/.mod 文件。
	run_make -C "$kernel_dir" M="$ROOT" clean >/dev/null || status=1
done

exit "$status"
