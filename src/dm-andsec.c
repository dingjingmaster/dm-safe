// SPDX-License-Identifier: GPL-2.0
/*
 * 这个文件实现的是 Device Mapper 里的 "andsec" target。Device Mapper 可以把一个
 * “逻辑块设备”映射到一个或多个真实块设备上；当前 dm-andsec 只做线性透传，不做
 * 加密、解密、IV、key 或完整性 tag 处理。
 *
 * 主要流程：
 *   1. dm_andsec_init()：模块加载时注册名为 "andsec" 的 target。
 *   2. andsec_ctr()：创建一条映射时调用，解析 device/start 并打开底层设备。
 *   3. andsec_map()：每个 bio 进来时调用，把 bio 的目标设备和 sector 改到底层设备。
 *   4. andsec_dtr()：映射销毁时释放 andsec_ctr() 里申请的资源。
 *
 * 当前代码刻意保留成透传骨架，后续可在 andsec_map() 前后按需增加自己的数据处理逻辑。
 */

#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/device-mapper.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>

#define DM_MSG_PREFIX "andsec"

struct andsec_config {
	/* 底层真实块设备，以及本 target 在底层设备上的起始 sector。 */
	struct dm_dev *dev;
	sector_t start;
};

static sector_t andsec_map_sector(struct dm_target *ti, sector_t sector)
{
	struct andsec_config *ac = ti->private;

	return ac->start + dm_target_offset(ti, sector);
}

static void andsec_map_bio(struct dm_target *ti, struct bio *bio)
{
	struct andsec_config *ac = ti->private;

	/* 透传只改写 bio 的目标设备和 sector，不修改 bio 数据页。 */
	bio_set_dev(bio, ac->dev->bdev);
	if (bio_sectors(bio))
		bio->bi_iter.bi_sector =
			andsec_map_sector(ti, bio->bi_iter.bi_sector);
}

/*
 * 函数：andsec_parse_args
 * 作用：解析 dm-andsec 映射参数。
 *
 * 新格式：
 *   <dev_path> <start>
 *
 * 兼容旧固定参数格式，便于从原项目迁移：
 *   <cipher> <key> <iv_offset> <dev_path> <start> [ignored_options...]
 *
 * 兼容格式里的 cipher/key/iv_offset/options 只用于定位 dev/start，不参与任何处理。
 */
static int andsec_parse_args(struct dm_target *ti, unsigned int argc, char **argv,
			     const char **dev_path, const char **start_arg)
{
	if (argc == 2) {
		*dev_path = argv[0];
		*start_arg = argv[1];
		return 0;
	}

	if (argc >= 5) {
		*dev_path = argv[3];
		*start_arg = argv[4];
		return 0;
	}

	ti->error = "Invalid argument count";
	return -EINVAL;
}

/*
 * 函数：andsec_ctr
 * 作用：构造一条 dm-andsec 透传映射。
 */
static int andsec_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct andsec_config *ac;
	const char *dev_path;
	const char *start_arg;
	unsigned long long tmp;
	char dummy;
	int ret;

	ret = andsec_parse_args(ti, argc, argv, &dev_path, &start_arg);
	if (ret)
		return ret;

	ac = kzalloc(sizeof(*ac), GFP_KERNEL);
	if (!ac) {
		ti->error = "Cannot allocate andsec context";
		return -ENOMEM;
	}

	ret = -EINVAL;
	if (sscanf(start_arg, "%llu%c", &tmp, &dummy) != 1 || tmp != (sector_t)tmp) {
		ti->error = "Invalid device sector";
		goto bad;
	}
	ac->start = tmp;

	ret = dm_get_device(ti, dev_path, dm_table_get_mode(ti->table), &ac->dev);
	if (ret) {
		ti->error = "Device lookup failed";
		goto bad;
	}

	/* 告诉 dm core：flush/discard/secure erase/write zeroes 都可以下发到底层设备。 */
	ti->num_flush_bios = 1;
	ti->num_discard_bios = 1;
	ti->num_secure_erase_bios = 1;
	ti->num_write_zeroes_bios = 1;
	ti->private = ac;

	return 0;

bad:
	kfree(ac);
	return ret;
}

/*
 * 函数：andsec_dtr
 * 作用：销毁 dm-andsec target，释放 andsec_ctr() 创建的资源。
 */
static void andsec_dtr(struct dm_target *ti)
{
	struct andsec_config *ac = ti->private;

	ti->private = NULL;
	if (!ac)
		return;

	if (ac->dev)
		dm_put_device(ti, ac->dev);
	kfree(ac);
}

/*
 * 函数：andsec_map
 * 作用：dm-andsec 的 IO 快路径入口，当前只做透传 remap。
 */
static int andsec_map(struct dm_target *ti, struct bio *bio)
{
	andsec_map_bio(ti, bio);

	return DM_MAPIO_REMAPPED;
}

/*
 * 函数：andsec_status
 * 作用：响应 dmsetup table/status，输出当前 target 的表项或运行状态。
 */
static void andsec_status(struct dm_target *ti, status_type_t type,
			  unsigned int status_flags, char *result, unsigned int maxlen)
{
	struct andsec_config *ac = ti->private;

	switch (type) {
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;
	case STATUSTYPE_TABLE:
		snprintf(result, maxlen, "%s %llu", ac->dev->name,
			 (unsigned long long)ac->start);
		break;
	default:
		result[0] = '\0';
		break;
	}
}

/*
 * 函数：andsec_iterate_devices
 * 作用：向 dm core 汇报本 target 覆盖的底层设备范围。
 */
static int andsec_iterate_devices(struct dm_target *ti,
				  iterate_devices_callout_fn fn, void *data)
{
	struct andsec_config *ac = ti->private;

	/* 告诉 dm core：本 target 覆盖底层设备 ac->dev 上从 ac->start 开始的 ti->len。 */
	return fn(ti, ac->dev, ac->start, ti->len, data);
}

static struct target_type andsec_target = {
	/*
	 * Device Mapper target 注册表。dm_register_target() 后，用户态映射表里写
	 * "andsec" 就会绑定到这一组回调。
	 */
	.name   = "andsec",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr    = andsec_ctr,
	.dtr    = andsec_dtr,
	.map    = andsec_map,
	.status = andsec_status,
	.iterate_devices = andsec_iterate_devices,
};

/*
 * 函数：dm_andsec_init
 * 作用：模块加载入口，把 andsec target 注册到 Device Mapper core。
 */
static int __init dm_andsec_init(void)
{
	int r;

	/*
	 * bio 相关基础知识：
	 *
	 * bio 是 Linux 块层描述一次块 IO 的核心结构。文件系统、swap、直接块设备访问等
	 * 都会把读写请求组织成 bio，再交给块层。一个 bio 里通常包含：
	 *   1. 操作类型：读、写、flush、discard 等，保存在 bi_opf/操作码里。
	 *   2. 目标设备：请求最终要发到哪个块设备。
	 *   3. 起始 sector：从设备哪个 512B sector 开始访问。
	 *   4. 数据页数组：bio_vec 描述哪些 page、page 内偏移和长度参与 IO。
	 *
	 * 当前 dm-andsec 和 bio 的关系：
	 *   1. dm-andsec 不改变文件系统看到的逻辑地址空间，只在 dm target 内把逻辑
	 *      sector 映射到底层设备 sector。
	 *   2. bio 的顺序一致性主要由块层、dm core、flush/FUA 语义和底层设备保证。
	 *   3. 对读写请求，上层收到的完成时机等同于底层透传 IO 的完成时机。
	 */
	/* 步骤0：注册 target_type，让用户态可以创建名为 "andsec" 的 dm target。 */
	r = dm_register_target(&andsec_target);
	if (r < 0)
		DMERR("register failed %d", r);

	return r;
}

/*
 * 函数：dm_andsec_exit
 * 作用：模块卸载入口，从 Device Mapper core 注销 andsec target。
 */
static void __exit dm_andsec_exit(void)
{
	/* 步骤0：注销 target_type；仍有映射使用时模块引用计数会阻止卸载。 */
	dm_unregister_target(&andsec_target);
}

module_init(dm_andsec_init);
module_exit(dm_andsec_exit);

MODULE_AUTHOR("andsec");
MODULE_DESCRIPTION(DM_NAME " andsec passthrough target");
MODULE_LICENSE("GPL");
