/*
 * Copyright (C) 2003 Jana Saout <jana@saout.de>
 * Copyright (C) 2004 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2006-2017 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2013-2017 Milan Broz <gmazyland@gmail.com>
 *
 * This file is released under the GPL.
 */

/*
 * 代码阅读指南
 * ============
 *
 * 这个文件实现的是 Device Mapper 里的 "crypt" target。Device Mapper 可以把一个
 * “逻辑块设备”映射到一个或多个真实块设备上，dm-crypt 在映射过程中额外做加密和
 * 解密。用户态通常通过 dmsetup 或 LUKS/cryptsetup 传入映射表，内核随后按下面的
 * 入口调用本文件：
 *
 *   1. dm_crypt_init()：模块加载时注册名为 "crypt" 的 target。
 *   2. crypt_ctr()：创建一条映射时调用，解析 cipher/key/device/offset/options，
 *      分配 crypto tfm、mempool、bioset、workqueue 等长期资源。
 *   3. crypt_map()：每个 bio 进来时调用。bio 是块层的一次 IO 请求，可能是读、
 *      写、flush 或 discard。
 *   4. crypt_dtr()：映射销毁时释放 crypt_ctr() 里申请的资源。
 *
 * 最重要的 IO 主流程：
 *
 *   写入：
 *     原始 bio 进入 crypt_map()
 *       -> kcryptd_queue_crypt()
 *       -> kcryptd_crypt_write_convert()
 *       -> crypt_alloc_buffer() 分配一个 clone bio 作为密文输出缓冲
 *       -> crypt_convert() 按 sector 逐块加密
 *       -> kcryptd_crypt_write_io_submit() 把 clone bio 提交到底层设备
 *       -> crypt_endio() 收到底层完成通知
 *       -> crypt_dec_pending() 完成原始 bio
 *
 *   读取：
 *     原始 bio 进入 crypt_map()
 *       -> kcryptd_io_read() 先 clone 一个读请求提交到底层设备
 *       -> crypt_endio() 收到底层读完成
 *       -> kcryptd_queue_crypt()
 *       -> kcryptd_crypt_read_convert() 在原始 bio 缓冲区里解密
 *       -> crypt_dec_pending() 完成原始 bio
 *
 * 几个初学者需要先记住的术语：
 *
 *   bio：block IO，请求里带着操作类型、起始 sector、数据页数组等。
 *   sector：块设备的逻辑扇区，内核里常以 512 字节为单位计数。
 *   clone bio：为了提交到底层设备而复制或新建的 bio。
 *   crypto tfm/request：Linux Crypto API 的算法实例和一次加/解密请求。
 *   IV：initialization vector，同一个 sector 使用什么 IV 由 iv_gen_ops 决定。
 *   mempool/bioset：内核 IO 路径不能随意睡眠等待内存，所以预留对象池。
 *   workqueue/kthread：加解密和提交 IO 不直接在 map/endio 上下文里做，避免阻塞
 *      块层或中断完成路径。
 *
 * 本项目当前目标是把 Linux 5.4.150 的 dm-crypt 作为 out-of-tree 模块维护，并用
 * 小范围兼容层适配 4.19 到 6.17 的内核接口差异。下面的注释以理解运行机制为主，
 * 代码行为应尽量保持和上游 dm-crypt 一致。
 */

#include <linux/completion.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/key.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#if defined(__has_include) && __has_include(<linux/blk-integrity.h>)
#include <linux/blk-integrity.h>
#endif
#include <linux/mempool.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/backing-dev.h>
#include <linux/atomic.h>
#include <linux/scatterlist.h>
#include <linux/rbtree.h>
#include <linux/ctype.h>
#include <asm/page.h>
#if defined(__has_include) && __has_include(<linux/unaligned.h>)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif
#include <crypto/hash.h>
#include <crypto/md5.h>
#include <crypto/algapi.h>
#include <crypto/skcipher.h>
#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <linux/rtnetlink.h> /* for struct rtattr and RTA macros only */
#include <keys/user-type.h>

#include <linux/device-mapper.h>

#define DM_MSG_PREFIX "crypt"

/*
 * 版本兼容层：不同内核版本会改函数名或函数签名。这里把差异收敛成 dm-safe 自己
 * 使用的一组小包装，后面的业务代码就不用到处写版本判断。
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
/* 5.9 后 kzfree() 被 kfree_sensitive() 替代，语义都是释放前清零敏感数据。 */
#define kzfree kfree_sensitive
#endif

#ifndef BIO_MAX_PAGES
/* 老内核没有 BIO_MAX_PAGES，用 BIO_MAX_VECS 表示一个 bio 最多能挂多少段。 */
#define BIO_MAX_PAGES BIO_MAX_VECS
#endif

#ifndef fallthrough
/* 老编译环境可能没有 fallthrough 注解，这里定义成空语句保持 switch 语义不变。 */
#define fallthrough do {} while (0)
#endif

static const char *crypt_bio_devname(struct bio *bio, char *buffer)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
	snprintf(buffer, BDEVNAME_SIZE, "%pg", bio->bi_bdev);
	return buffer;
#else
	return bio_devname(bio, buffer);
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
/* totalram_pages 在 5.0 前是变量，5.0 后变成函数。 */
#define crypt_totalram_pages() totalram_pages
#define crypt_totalhigh_pages() totalhigh_pages
#else
#define crypt_totalram_pages() totalram_pages()
#define crypt_totalhigh_pages() totalhigh_pages()
#endif

/*
 * 一次“bio 转换”的游标。
 *
 * crypt_convert() 不一定一次就把整个 bio 加/解密完：bio 可能跨多个 page，crypto
 * driver 也可能异步返回。因此这里保存输入/输出 bio 的当前位置、当前 sector、还
 * 有异步请求完成计数。把它理解成“这次加/解密任务走到哪里了”。
 */
struct convert_context {
	/* crypto driver 返回 -EBUSY 时，用它等待 backlog 中的请求重新启动。 */
	struct completion restart;
	/* 输入 bio：写路径通常是明文原始 bio，读路径通常是刚读回来的密文 bio。 */
	struct bio *bio_in;
	/* 输出 bio：写路径是 clone 密文 bio，读路径一般还是原始 bio。 */
	struct bio *bio_out;
	/* 输入/输出 bio 当前处理到的 bvec 位置。 */
	struct bvec_iter iter_in;
	struct bvec_iter iter_out;
	/* 当前正在处理的 512B sector 号，生成 IV 时会用到。 */
	u64 cc_sector;
	/* crypt_convert() 内部未完成的 crypto request 数。 */
	atomic_t cc_pending;
	union {
		/* 普通块密码请求，例如 cbc(aes)、xts(aes)。 */
		struct skcipher_request *req;
		/* 带认证标签的 AEAD 请求，例如 authenc(...)。 */
		struct aead_request *req_aead;
	} r;

};

/*
 * 每个原始 bio 对应的一份私有数据。
 *
 * dm core 会按 ti->per_io_data_size 给每个 bio 预留一段内存，crypt_map() 通过
 * dm_per_bio_data() 拿到这里。它连接了“用户原始 bio”、“底层 clone bio”、“crypto
 * request”和“完成计数”，是整个 IO 生命周期的锚点。
 */
struct dm_crypt_io {
	/* 该映射的全局配置，crypt_ctr() 创建。 */
	struct crypt_config *cc;
	/* 上层传进来的原始 bio，最终要调用 bio_endio() 完成它。 */
	struct bio *base_bio;
	/* integrity/AEAD 模式下，每个 sector 的认证标签或额外 IV 存在这里。 */
	u8 *integrity_metadata;
	/* 标记 integrity_metadata 是来自 tag_pool 还是 kmalloc，释放路径不同。 */
	bool integrity_metadata_from_pool;
	/* 挂到 workqueue 上执行读、写、加密或解密任务。 */
	struct work_struct work;

	/* 当前 bio 的加/解密游标。 */
	struct convert_context ctx;

	/* 整个 bio 生命周期内还没完成的子任务数。归零后完成 base_bio。 */
	atomic_t io_pending;
	/* 子任务发现的第一个块层错误，最终写回 base_bio->bi_status。 */
	blk_status_t error;
	/* 该 bio 映射到 dm target 内的起始 sector。 */
	sector_t sector;

	/* 写路径为了按 sector 排序提交到底层设备，会挂到红黑树里。 */
	struct rb_node rb_node;
} CRYPTO_MINALIGN_ATTR;

/*
 * 每个 crypto request 后面附带的 dm-crypt 私有头。
 *
 * request 本身由 Linux Crypto API 使用，dmreq 记录 dm-crypt 需要的上下文、sg
 * 表、IV 对应的 sector 等。dmreq_of_req()/req_of_dmreq() 负责在二者之间换算。
 */
struct dm_crypt_request {
	struct convert_context *ctx;
	/* 输入/输出 scatterlist，描述本次只处理的一个加密 sector。 */
	struct scatterlist sg_in[4];
	struct scatterlist sg_out[4];
	/* 生成 IV 使用的 sector。iv_large_sectors 时会按加密 sector 缩放。 */
	u64 iv_sector;
};

struct crypt_config;

/*
 * IV 生成算法的虚函数表。
 *
 * 不同磁盘加密格式对 IV 的要求不同，例如 plain/plain64/essiv/lmk/tcw。crypt_ctr()
 * 解析 cipher 字符串后选择一套 ops；crypt_convert_block_*() 每处理一个 sector
 * 时调用 generator() 生成 IV，必要时调用 post() 做后处理。
 */
struct crypt_iv_operations {
	int (*ctr)(struct crypt_config *cc, struct dm_target *ti,
		   const char *opts);
	void (*dtr)(struct crypt_config *cc);
	int (*init)(struct crypt_config *cc);
	int (*wipe)(struct crypt_config *cc);
	int (*generator)(struct crypt_config *cc, u8 *iv,
			 struct dm_crypt_request *dmreq);
	int (*post)(struct crypt_config *cc, u8 *iv,
		    struct dm_crypt_request *dmreq);
};

struct iv_benbi_private {
	int shift;
};

#define LMK_SEED_SIZE 64 /* hash + 0 */
struct iv_lmk_private {
	struct crypto_shash *hash_tfm;
	u8 *seed;
};

#define TCW_WHITENING_SIZE 16
struct iv_tcw_private {
	struct crypto_shash *crc32_tfm;
	u8 *iv_seed;
	u8 *whitening;
};

/*
 * Crypt: maps a linear range of a block device
 * and encrypts / decrypts at the same time.
 */
enum flags { DM_CRYPT_SUSPENDED, DM_CRYPT_KEY_VALID,
	     DM_CRYPT_SAME_CPU, DM_CRYPT_NO_OFFLOAD };

enum cipher_flags {
	CRYPT_MODE_INTEGRITY_AEAD,	/* Use authenticated mode for cihper */
	CRYPT_IV_LARGE_SECTORS,		/* Calculate IV from sector_size, not 512B sectors */
};

/*
 * 一条 dm-crypt 映射的全局配置。
 *
 * crypt_ctr() 创建并填充它，后续每个 bio 都通过 ti->private 找到这份配置。除少数
 * 运行期状态外，大部分字段初始化完成后只读，这样 IO 快路径不需要复杂加锁。
 */
struct crypt_config {
	/* 底层真实块设备，以及本 target 在底层设备上的起始 sector。 */
	struct dm_dev *dev;
	sector_t start;

	/* 当前实例已从 page_pool 分配的页数，用于限制所有 dm-crypt 实例的总内存。 */
	struct percpu_counter n_allocated_pages;

	/* io_queue 负责提交底层 IO；crypt_queue 负责 CPU 密集的加/解密。 */
	struct workqueue_struct *io_queue;
	struct workqueue_struct *crypt_queue;

	/* 写请求按 sector 排序后由专门 kthread 提交，改善底层设备顺序写入特性。 */
	spinlock_t write_thread_lock;
	struct task_struct *write_thread;
	struct rb_root write_tree;

	/* 原始参数字符串：status/table 输出时会重新拼回用户可见的映射表。 */
	char *cipher_string;
	char *cipher_auth;
	char *key_string;

	/* IV 算法和它需要的私有状态。 */
	const struct crypt_iv_operations *iv_gen_ops;
	union {
		struct iv_benbi_private benbi;
		struct iv_lmk_private lmk;
		struct iv_tcw_private tcw;
	} iv_gen_private;
	/* IV 计算的 sector 偏移；sector_size/sector_shift 是内部加密 sector 大小。 */
	u64 iv_offset;
	unsigned int iv_size;
	unsigned short int sector_size;
	unsigned char sector_shift;

	/* Linux Crypto API 的算法实例。普通模式用 skcipher，AEAD/integrity 模式用 aead。 */
	union {
		struct crypto_skcipher **tfms;
		struct crypto_aead **tfms_aead;
	} cipher_tfm;
	/* 多 key 模式下的 tfm 数量，以及 cipher_flags 里的 AEAD/large-sector 标记。 */
	unsigned tfms_count;
	unsigned long cipher_flags;

	/*
	 * Layout of each crypto request:
	 *
	 *   struct skcipher_request
	 *      context
	 *      padding
	 *   struct dm_crypt_request
	 *      padding
	 *   IV
	 *
	 * The padding is added so that dm_crypt_request and the IV are
	 * correctly aligned.
	 */
	unsigned int dmreq_start;

	/* 每个原始 bio 需要预留的私有数据大小，交给 dm core 使用。 */
	unsigned int per_bio_data_size;

	/* 运行期状态位和 key 拆分信息。key_parts 用于多 key 或 IV 私有 key。 */
	unsigned long flags;
	unsigned int key_size;
	unsigned int key_parts;      /* independent parts in key buffer */
	unsigned int key_extra_size; /* additional keys length */
	unsigned int key_mac_size;   /* MAC key size for authenc(...) */

	/* integrity 元数据布局：认证 tag、额外 IV、以及实际落盘 tag 的大小。 */
	unsigned int integrity_tag_size;
	unsigned int integrity_iv_size;
	unsigned int on_disk_tag_size;

	/*
	 * pool for per bio private data, crypto requests,
	 * encryption requeusts/buffer pages and integrity tags
	 */
	unsigned tag_pool_max_sectors;
	mempool_t tag_pool;
	mempool_t req_pool;
	mempool_t page_pool;

	/* clone bio 从这个 bioset 分配，避免 IO 路径临时创建 bio 时内存回收死锁。 */
	struct bio_set bs;
	/* 保护批量从 page_pool 分配页的慢路径，避免多个大 bio 同时耗尽 mempool。 */
	struct mutex bio_alloc_lock;

	u8 *authenc_key; /* space for keys in authenc() format (if used) */
	/* 变长数组，crypt_ctr() 按 key_size 把 key 数据挂在结构体尾部。 */
	u8 key[0];
};

/*
 * bio API 兼容封装。
 *
 * 5.18 开始 bio_alloc_bioset()/bio_alloc_clone() 需要显式传入 bdev/opf；
 * 6.12 开始 dm 提供 dm_submit_bio_remap() 来提交重映射 bio。业务代码统一调用
 * crypt_alloc_bio()/crypt_clone_bio()/crypt_submit_bio()，避免 IO 主流程被版本差异
 * 打散。
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
#define crypt_alloc_bio(io, nr_iovecs, gfp) \
	bio_alloc_bioset((io)->cc->dev->bdev, (nr_iovecs), \
			 (io)->base_bio->bi_opf, (gfp), &(io)->cc->bs)
#define crypt_clone_bio(io, gfp) \
	bio_alloc_clone((io)->cc->dev->bdev, (io)->base_bio, (gfp), \
			&(io)->cc->bs)
#define crypt_submit_bio(io, clone) \
	dm_submit_bio_remap((io)->base_bio, (clone))
#else
#define crypt_alloc_bio(io, nr_iovecs, gfp) \
	bio_alloc_bioset((gfp), (nr_iovecs), &(io)->cc->bs)
#define crypt_clone_bio(io, gfp) \
	bio_clone_fast((io)->base_bio, (gfp), &(io)->cc->bs)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#define crypt_submit_bio(io, clone) \
	dm_submit_bio_remap((io)->base_bio, (clone))
#else
#define crypt_submit_bio(io, clone) \
	submit_bio((clone))
#endif

#define MIN_IOS		64
#define MAX_TAG_SIZE	480
#define POOL_ENTRY_SIZE	512

/*
 * 全局客户端统计。
 *
 * 每创建一个 dm-crypt target，dm_crypt_clients_n 加一；销毁时减一。
 * crypt_calculate_pages_per_client() 会按实例数量重新计算每个实例最多能从 page_pool
 * 申请多少页，避免多个加密卷同时跑大 IO 时把系统内存压垮。
 */
static DEFINE_SPINLOCK(dm_crypt_clients_lock);
static unsigned dm_crypt_clients_n = 0;
static volatile unsigned long dm_crypt_pages_per_client;
#define DM_CRYPT_MEMORY_PERCENT			2
#define DM_CRYPT_MIN_PAGES_PER_CLIENT		(BIO_MAX_PAGES * 16)

static void clone_init(struct dm_crypt_io *, struct bio *);
static void kcryptd_queue_crypt(struct dm_crypt_io *io);
static struct scatterlist *crypt_get_sg_data(struct crypt_config *cc,
					     struct scatterlist *sg);

/*
 * Use this to access cipher attributes that are independent of the key.
 *
 * 多 key 模式下 cc->cipher_tfm.tfms[] 可能有很多个元素，但 blocksize、ivsize、
 * alignmask 这类算法属性对所有元素都一样，所以取第 0 个代表即可。
 */
static struct crypto_skcipher *any_tfm(struct crypt_config *cc)
{
	return cc->cipher_tfm.tfms[0];
}

static struct crypto_aead *any_tfm_aead(struct crypt_config *cc)
{
	return cc->cipher_tfm.tfms_aead[0];
}

/*
 * Different IV generation algorithms:
 *
 * IV 决定“同一个明文块在不同 sector 上如何变成不同密文”。如果 IV 设计不好，相同
 * 明文可能泄露出可识别的密文模式。下面每个 generator() 都把 dmreq->iv_sector
 * 转换成当前 sector 使用的 IV；部分旧格式还需要在 post() 里对数据做额外修正。
 *
 * plain: the initial vector is the 32-bit little-endian version of the sector
 *        number, padded with zeros if necessary.
 *
 * plain64: the initial vector is the 64-bit little-endian version of the sector
 *        number, padded with zeros if necessary.
 *
 * plain64be: the initial vector is the 64-bit big-endian version of the sector
 *        number, padded with zeros if necessary.
 *
 * essiv: "encrypted sector|salt initial vector", the sector number is
 *        encrypted with the bulk cipher using a salt as key. The salt
 *        should be derived from the bulk cipher's key via hashing.
 *
 * benbi: the 64-bit "big-endian 'narrow block'-count", starting at 1
 *        (needed for LRW-32-AES and possible other narrow block modes)
 *
 * null: the initial vector is always zero.  Provides compatibility with
 *       obsolete loop_fish2 devices.  Do not use for new devices.
 *
 * lmk:  Compatible implementation of the block chaining mode used
 *       by the Loop-AES block device encryption system
 *       designed by Jari Ruusu. See http://loop-aes.sourceforge.net/
 *       It operates on full 512 byte sectors and uses CBC
 *       with an IV derived from the sector number, the data and
 *       optionally extra IV seed.
 *       This means that after decryption the first block
 *       of sector must be tweaked according to decrypted data.
 *       Loop-AES can use three encryption schemes:
 *         version 1: is plain aes-cbc mode
 *         version 2: uses 64 multikey scheme with lmk IV generator
 *         version 3: the same as version 2 with additional IV seed
 *                   (it uses 65 keys, last key is used as IV seed)
 *
 * tcw:  Compatible implementation of the block chaining mode used
 *       by the TrueCrypt device encryption system (prior to version 4.1).
 *       For more info see: https://gitlab.com/cryptsetup/cryptsetup/wikis/TrueCryptOnDiskFormat
 *       It operates on full 512 byte sectors and uses CBC
 *       with an IV derived from initial key and the sector number.
 *       In addition, whitening value is applied on every sector, whitening
 *       is calculated from initial key, sector number and mixed using CRC32.
 *       Note that this encryption scheme is vulnerable to watermarking attacks
 *       and should be used for old compatible containers access only.
 *
 * eboiv: Encrypted byte-offset IV (used in Bitlocker in CBC mode)
 *        The IV is encrypted little-endian byte-offset (with the same key
 *        and cipher as the volume).
 */

static int crypt_iv_plain_gen(struct crypt_config *cc, u8 *iv,
			      struct dm_crypt_request *dmreq)
{
	/* plain 只取低 32 位 sector，小盘兼容可以用，新格式通常更推荐 plain64。 */
	memset(iv, 0, cc->iv_size);
	*(__le32 *)iv = cpu_to_le32(dmreq->iv_sector & 0xffffffff);

	return 0;
}

static int crypt_iv_plain64_gen(struct crypt_config *cc, u8 *iv,
				struct dm_crypt_request *dmreq)
{
	/* plain64 用完整 64 位 sector，避免大设备上 sector 号截断。 */
	memset(iv, 0, cc->iv_size);
	*(__le64 *)iv = cpu_to_le64(dmreq->iv_sector);

	return 0;
}

static int crypt_iv_plain64be_gen(struct crypt_config *cc, u8 *iv,
				  struct dm_crypt_request *dmreq)
{
	memset(iv, 0, cc->iv_size);
	/* iv_size is at least of size u64; usually it is 16 bytes */
	*(__be64 *)&iv[cc->iv_size - sizeof(u64)] = cpu_to_be64(dmreq->iv_sector);

	return 0;
}

static int crypt_iv_essiv_gen(struct crypt_config *cc, u8 *iv,
			      struct dm_crypt_request *dmreq)
{
	/*
	 * ESSIV encryption of the IV is now handled by the crypto API,
	 * so just pass the plain sector number here.
	 *
	 * 也就是说，这里只准备“待加密的 sector 号”；真正的 ESSIV 加密由
	 * crypto API 里 essiv(...) 这个组合算法完成。
	 */
	memset(iv, 0, cc->iv_size);
	*(__le64 *)iv = cpu_to_le64(dmreq->iv_sector);

	return 0;
}

static int crypt_iv_benbi_ctr(struct crypt_config *cc, struct dm_target *ti,
			      const char *opts)
{
	unsigned bs;
	int log;

	if (test_bit(CRYPT_MODE_INTEGRITY_AEAD, &cc->cipher_flags))
		bs = crypto_aead_blocksize(any_tfm_aead(cc));
	else
		bs = crypto_skcipher_blocksize(any_tfm(cc));
	log = ilog2(bs);

	/* we need to calculate how far we must shift the sector count
	 * to get the cipher block count, we use this shift in _gen
	 *
	 * benbi 要的是“密码块编号”而不是 512B sector 编号，所以这里先算好移位量，
	 * 后面 generator() 直接用。
	 */

	if (1 << log != bs) {
		ti->error = "cypher blocksize is not a power of 2";
		return -EINVAL;
	}

	if (log > 9) {
		ti->error = "cypher blocksize is > 512";
		return -EINVAL;
	}

	cc->iv_gen_private.benbi.shift = 9 - log;

	return 0;
}

static void crypt_iv_benbi_dtr(struct crypt_config *cc)
{
}

static int crypt_iv_benbi_gen(struct crypt_config *cc, u8 *iv,
			      struct dm_crypt_request *dmreq)
{
	__be64 val;

	memset(iv, 0, cc->iv_size - sizeof(u64)); /* rest is cleared below */

	val = cpu_to_be64(((u64)dmreq->iv_sector << cc->iv_gen_private.benbi.shift) + 1);
	put_unaligned(val, (__be64 *)(iv + cc->iv_size - sizeof(u64)));

	return 0;
}

static int crypt_iv_null_gen(struct crypt_config *cc, u8 *iv,
			     struct dm_crypt_request *dmreq)
{
	memset(iv, 0, cc->iv_size);

	return 0;
}

static void crypt_iv_lmk_dtr(struct crypt_config *cc)
{
	struct iv_lmk_private *lmk = &cc->iv_gen_private.lmk;

	if (lmk->hash_tfm && !IS_ERR(lmk->hash_tfm))
		crypto_free_shash(lmk->hash_tfm);
	lmk->hash_tfm = NULL;

	kzfree(lmk->seed);
	lmk->seed = NULL;
}

static int crypt_iv_lmk_ctr(struct crypt_config *cc, struct dm_target *ti,
			    const char *opts)
{
	struct iv_lmk_private *lmk = &cc->iv_gen_private.lmk;

	if (cc->sector_size != (1 << SECTOR_SHIFT)) {
		ti->error = "Unsupported sector size for LMK";
		return -EINVAL;
	}

	/* LMK 是 Loop-AES 兼容格式，历史格式固定按 512B sector 工作。 */
	lmk->hash_tfm = crypto_alloc_shash("md5", 0, 0);
	if (IS_ERR(lmk->hash_tfm)) {
		ti->error = "Error initializing LMK hash";
		return PTR_ERR(lmk->hash_tfm);
	}

	/* No seed in LMK version 2 */
	if (cc->key_parts == cc->tfms_count) {
		lmk->seed = NULL;
		return 0;
	}

	lmk->seed = kzalloc(LMK_SEED_SIZE, GFP_KERNEL);
	if (!lmk->seed) {
		crypt_iv_lmk_dtr(cc);
		ti->error = "Error kmallocing seed storage in LMK";
		return -ENOMEM;
	}

	return 0;
}

static int crypt_iv_lmk_init(struct crypt_config *cc)
{
	struct iv_lmk_private *lmk = &cc->iv_gen_private.lmk;
	int subkey_size = cc->key_size / cc->key_parts;

	/* LMK seed is on the position of LMK_KEYS + 1 key */
	if (lmk->seed)
		memcpy(lmk->seed, cc->key + (cc->tfms_count * subkey_size),
		       crypto_shash_digestsize(lmk->hash_tfm));

	return 0;
}

static int crypt_iv_lmk_wipe(struct crypt_config *cc)
{
	struct iv_lmk_private *lmk = &cc->iv_gen_private.lmk;

	if (lmk->seed)
		memset(lmk->seed, 0, LMK_SEED_SIZE);

	return 0;
}

static int crypt_iv_lmk_one(struct crypt_config *cc, u8 *iv,
			    struct dm_crypt_request *dmreq,
			    u8 *data)
{
	struct iv_lmk_private *lmk = &cc->iv_gen_private.lmk;
	SHASH_DESC_ON_STACK(desc, lmk->hash_tfm);
	struct md5_state md5state;
	__le32 buf[4];
	int i, r;

	desc->tfm = lmk->hash_tfm;

	/*
	 * LMK 的 IV 依赖 sector 内容本身，因此读路径和写路径处理顺序不同：
	 * 写入时从明文数据算 IV；读取时先解密，再在 post() 里按解密后的数据修正。
	 */
	r = crypto_shash_init(desc);
	if (r)
		return r;

	if (lmk->seed) {
		r = crypto_shash_update(desc, lmk->seed, LMK_SEED_SIZE);
		if (r)
			return r;
	}

	/* Sector is always 512B, block size 16, add data of blocks 1-31 */
	r = crypto_shash_update(desc, data + 16, 16 * 31);
	if (r)
		return r;

	/* Sector is cropped to 56 bits here */
	buf[0] = cpu_to_le32(dmreq->iv_sector & 0xFFFFFFFF);
	buf[1] = cpu_to_le32((((u64)dmreq->iv_sector >> 32) & 0x00FFFFFF) | 0x80000000);
	buf[2] = cpu_to_le32(4024);
	buf[3] = 0;
	r = crypto_shash_update(desc, (u8 *)buf, sizeof(buf));
	if (r)
		return r;

	/* No MD5 padding here */
	r = crypto_shash_export(desc, &md5state);
	if (r)
		return r;

	for (i = 0; i < MD5_HASH_WORDS; i++)
		__cpu_to_le32s(&md5state.hash[i]);
	memcpy(iv, &md5state.hash, cc->iv_size);

	return 0;
}

static int crypt_iv_lmk_gen(struct crypt_config *cc, u8 *iv,
			    struct dm_crypt_request *dmreq)
{
	struct scatterlist *sg;
	u8 *src;
	int r = 0;

	if (bio_data_dir(dmreq->ctx->bio_in) == WRITE) {
		sg = crypt_get_sg_data(cc, dmreq->sg_in);
		src = kmap_atomic(sg_page(sg));
		r = crypt_iv_lmk_one(cc, iv, dmreq, src + sg->offset);
		kunmap_atomic(src);
	} else
		memset(iv, 0, cc->iv_size);

	return r;
}

static int crypt_iv_lmk_post(struct crypt_config *cc, u8 *iv,
			     struct dm_crypt_request *dmreq)
{
	struct scatterlist *sg;
	u8 *dst;
	int r;

	if (bio_data_dir(dmreq->ctx->bio_in) == WRITE)
		return 0;

	sg = crypt_get_sg_data(cc, dmreq->sg_out);
	dst = kmap_atomic(sg_page(sg));
	r = crypt_iv_lmk_one(cc, iv, dmreq, dst + sg->offset);

	/* Tweak the first block of plaintext sector */
	if (!r)
		crypto_xor(dst + sg->offset, iv, cc->iv_size);

	kunmap_atomic(dst);
	return r;
}

static void crypt_iv_tcw_dtr(struct crypt_config *cc)
{
	struct iv_tcw_private *tcw = &cc->iv_gen_private.tcw;

	kzfree(tcw->iv_seed);
	tcw->iv_seed = NULL;
	kzfree(tcw->whitening);
	tcw->whitening = NULL;

	if (tcw->crc32_tfm && !IS_ERR(tcw->crc32_tfm))
		crypto_free_shash(tcw->crc32_tfm);
	tcw->crc32_tfm = NULL;
}

static int crypt_iv_tcw_ctr(struct crypt_config *cc, struct dm_target *ti,
			    const char *opts)
{
	struct iv_tcw_private *tcw = &cc->iv_gen_private.tcw;

	if (cc->sector_size != (1 << SECTOR_SHIFT)) {
		ti->error = "Unsupported sector size for TCW";
		return -EINVAL;
	}

	if (cc->key_size <= (cc->iv_size + TCW_WHITENING_SIZE)) {
		ti->error = "Wrong key size for TCW";
		return -EINVAL;
	}

	tcw->crc32_tfm = crypto_alloc_shash("crc32", 0, 0);
	if (IS_ERR(tcw->crc32_tfm)) {
		ti->error = "Error initializing CRC32 in TCW";
		return PTR_ERR(tcw->crc32_tfm);
	}

	tcw->iv_seed = kzalloc(cc->iv_size, GFP_KERNEL);
	tcw->whitening = kzalloc(TCW_WHITENING_SIZE, GFP_KERNEL);
	if (!tcw->iv_seed || !tcw->whitening) {
		crypt_iv_tcw_dtr(cc);
		ti->error = "Error allocating seed storage in TCW";
		return -ENOMEM;
	}

	return 0;
}

static int crypt_iv_tcw_init(struct crypt_config *cc)
{
	struct iv_tcw_private *tcw = &cc->iv_gen_private.tcw;
	int key_offset = cc->key_size - cc->iv_size - TCW_WHITENING_SIZE;

	memcpy(tcw->iv_seed, &cc->key[key_offset], cc->iv_size);
	memcpy(tcw->whitening, &cc->key[key_offset + cc->iv_size],
	       TCW_WHITENING_SIZE);

	return 0;
}

static int crypt_iv_tcw_wipe(struct crypt_config *cc)
{
	struct iv_tcw_private *tcw = &cc->iv_gen_private.tcw;

	memset(tcw->iv_seed, 0, cc->iv_size);
	memset(tcw->whitening, 0, TCW_WHITENING_SIZE);

	return 0;
}

static int crypt_iv_tcw_whitening(struct crypt_config *cc,
				  struct dm_crypt_request *dmreq,
				  u8 *data)
{
	struct iv_tcw_private *tcw = &cc->iv_gen_private.tcw;
	__le64 sector = cpu_to_le64(dmreq->iv_sector);
	u8 buf[TCW_WHITENING_SIZE];
	SHASH_DESC_ON_STACK(desc, tcw->crc32_tfm);
	int i, r;

	/* xor whitening with sector number */
	crypto_xor_cpy(buf, tcw->whitening, (u8 *)&sector, 8);
	crypto_xor_cpy(&buf[8], tcw->whitening + 8, (u8 *)&sector, 8);

	/* calculate crc32 for every 32bit part and xor it */
	desc->tfm = tcw->crc32_tfm;
	for (i = 0; i < 4; i++) {
		r = crypto_shash_init(desc);
		if (r)
			goto out;
		r = crypto_shash_update(desc, &buf[i * 4], 4);
		if (r)
			goto out;
		r = crypto_shash_final(desc, &buf[i * 4]);
		if (r)
			goto out;
	}
	crypto_xor(&buf[0], &buf[12], 4);
	crypto_xor(&buf[4], &buf[8], 4);

	/* apply whitening (8 bytes) to whole sector */
	for (i = 0; i < ((1 << SECTOR_SHIFT) / 8); i++)
		crypto_xor(data + i * 8, buf, 8);
out:
	memzero_explicit(buf, sizeof(buf));
	return r;
}

static int crypt_iv_tcw_gen(struct crypt_config *cc, u8 *iv,
			    struct dm_crypt_request *dmreq)
{
	struct scatterlist *sg;
	struct iv_tcw_private *tcw = &cc->iv_gen_private.tcw;
	__le64 sector = cpu_to_le64(dmreq->iv_sector);
	u8 *src;
	int r = 0;

	/* Remove whitening from ciphertext */
	if (bio_data_dir(dmreq->ctx->bio_in) != WRITE) {
		sg = crypt_get_sg_data(cc, dmreq->sg_in);
		src = kmap_atomic(sg_page(sg));
		r = crypt_iv_tcw_whitening(cc, dmreq, src + sg->offset);
		kunmap_atomic(src);
	}

	/* Calculate IV */
	crypto_xor_cpy(iv, tcw->iv_seed, (u8 *)&sector, 8);
	if (cc->iv_size > 8)
		crypto_xor_cpy(&iv[8], tcw->iv_seed + 8, (u8 *)&sector,
			       cc->iv_size - 8);

	return r;
}

static int crypt_iv_tcw_post(struct crypt_config *cc, u8 *iv,
			     struct dm_crypt_request *dmreq)
{
	struct scatterlist *sg;
	u8 *dst;
	int r;

	if (bio_data_dir(dmreq->ctx->bio_in) != WRITE)
		return 0;

	/* Apply whitening on ciphertext */
	sg = crypt_get_sg_data(cc, dmreq->sg_out);
	dst = kmap_atomic(sg_page(sg));
	r = crypt_iv_tcw_whitening(cc, dmreq, dst + sg->offset);
	kunmap_atomic(dst);

	return r;
}

static int crypt_iv_random_gen(struct crypt_config *cc, u8 *iv,
				struct dm_crypt_request *dmreq)
{
	/* Used only for writes, there must be an additional space to store IV */
	get_random_bytes(iv, cc->iv_size);
	return 0;
}

static int crypt_iv_eboiv_ctr(struct crypt_config *cc, struct dm_target *ti,
			    const char *opts)
{
	if (test_bit(CRYPT_MODE_INTEGRITY_AEAD, &cc->cipher_flags)) {
		ti->error = "AEAD transforms not supported for EBOIV";
		return -EINVAL;
	}

	if (crypto_skcipher_blocksize(any_tfm(cc)) != cc->iv_size) {
		ti->error = "Block size of EBOIV cipher does "
			    "not match IV size of block cipher";
		return -EINVAL;
	}

	return 0;
}

static int crypt_iv_eboiv_gen(struct crypt_config *cc, u8 *iv,
			    struct dm_crypt_request *dmreq)
{
	u8 buf[MAX_CIPHER_BLOCKSIZE] __aligned(__alignof__(__le64));
	struct skcipher_request *req;
	struct scatterlist src, dst;
	DECLARE_CRYPTO_WAIT(wait);
	int err;

	/*
	 * EBOIV 把“字节偏移”再经过一次块密码加密作为 IV。这里临时分配一个
	 * skcipher_request，只处理 IV 本身，不处理用户数据。
	 */
	req = skcipher_request_alloc(any_tfm(cc), GFP_NOIO);
	if (!req)
		return -ENOMEM;

	memset(buf, 0, cc->iv_size);
	*(__le64 *)buf = cpu_to_le64(dmreq->iv_sector * cc->sector_size);

	sg_init_one(&src, page_address(ZERO_PAGE(0)), cc->iv_size);
	sg_init_one(&dst, iv, cc->iv_size);
	skcipher_request_set_crypt(req, &src, &dst, cc->iv_size, buf);
	skcipher_request_set_callback(req, 0, crypto_req_done, &wait);
	err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	skcipher_request_free(req);

	return err;
}

static const struct crypt_iv_operations crypt_iv_plain_ops = {
	.generator = crypt_iv_plain_gen
};

static const struct crypt_iv_operations crypt_iv_plain64_ops = {
	.generator = crypt_iv_plain64_gen
};

static const struct crypt_iv_operations crypt_iv_plain64be_ops = {
	.generator = crypt_iv_plain64be_gen
};

static const struct crypt_iv_operations crypt_iv_essiv_ops = {
	.generator = crypt_iv_essiv_gen
};

static const struct crypt_iv_operations crypt_iv_benbi_ops = {
	.ctr	   = crypt_iv_benbi_ctr,
	.dtr	   = crypt_iv_benbi_dtr,
	.generator = crypt_iv_benbi_gen
};

static const struct crypt_iv_operations crypt_iv_null_ops = {
	.generator = crypt_iv_null_gen
};

static const struct crypt_iv_operations crypt_iv_lmk_ops = {
	.ctr	   = crypt_iv_lmk_ctr,
	.dtr	   = crypt_iv_lmk_dtr,
	.init	   = crypt_iv_lmk_init,
	.wipe	   = crypt_iv_lmk_wipe,
	.generator = crypt_iv_lmk_gen,
	.post	   = crypt_iv_lmk_post
};

static const struct crypt_iv_operations crypt_iv_tcw_ops = {
	.ctr	   = crypt_iv_tcw_ctr,
	.dtr	   = crypt_iv_tcw_dtr,
	.init	   = crypt_iv_tcw_init,
	.wipe	   = crypt_iv_tcw_wipe,
	.generator = crypt_iv_tcw_gen,
	.post	   = crypt_iv_tcw_post
};

static struct crypt_iv_operations crypt_iv_random_ops = {
	.generator = crypt_iv_random_gen
};

static struct crypt_iv_operations crypt_iv_eboiv_ops = {
	.ctr	   = crypt_iv_eboiv_ctr,
	.generator = crypt_iv_eboiv_gen
};

/*
 * Integrity extensions
 *
 * dm-crypt 可以把每个加密 sector 的认证 tag 或额外 IV 放在块设备的 integrity
 * metadata 区域里。普通加密模式不需要这些字段；AEAD 模式会同时做加密和认证。
 */
static bool crypt_integrity_aead(struct crypt_config *cc)
{
	return test_bit(CRYPT_MODE_INTEGRITY_AEAD, &cc->cipher_flags);
}

static bool crypt_integrity_hmac(struct crypt_config *cc)
{
	return crypt_integrity_aead(cc) && cc->key_mac_size;
}

/* Get sg containing data */
static struct scatterlist *crypt_get_sg_data(struct crypt_config *cc,
					     struct scatterlist *sg)
{
	/*
	 * AEAD scatterlist 的前两个条目是 AAD：sector 编号和原始 IV。
	 * 真正的数据从 sg[2] 开始；普通 skcipher 模式只有 sg[0]。
	 */
	if (unlikely(crypt_integrity_aead(cc)))
		return &sg[2];

	return sg;
}

static int dm_crypt_integrity_io_alloc(struct dm_crypt_io *io, struct bio *bio)
{
	struct bio_integrity_payload *bip;
	unsigned int tag_len;
	int ret;

	if (!bio_sectors(bio) || !io->cc->on_disk_tag_size)
		return 0;

	/*
	 * 给 clone bio 挂 integrity payload。底层带 integrity profile 的设备会把
	 * payload 里的 tag 和数据一起读写。
	 */
	bip = bio_integrity_alloc(bio, GFP_NOIO, 1);
	if (IS_ERR(bip))
		return PTR_ERR(bip);

	tag_len = io->cc->on_disk_tag_size * (bio_sectors(bio) >> io->cc->sector_shift);

	bip->bip_iter.bi_size = tag_len;
	bip->bip_iter.bi_sector = io->cc->start + io->sector;

	ret = bio_integrity_add_page(bio, virt_to_page(io->integrity_metadata),
				     tag_len, offset_in_page(io->integrity_metadata));
	if (unlikely(ret != tag_len))
		return -ENOMEM;

	return 0;
}

static int crypt_integrity_ctr(struct crypt_config *cc, struct dm_target *ti)
{
#ifdef CONFIG_BLK_DEV_INTEGRITY
	struct blk_integrity *bi = blk_get_integrity(cc->dev->bdev->bd_disk);
	struct mapped_device *md = dm_table_get_md(ti->table);

	/* From now we require underlying device with our integrity profile */
	/*
	 * 只有底层设备声明 DM-DIF-EXT-TAG profile 时，dm-crypt 才能安全使用
	 * integrity metadata 存放认证 tag/IV。
	 */
	if (!bi || strcasecmp(bi->profile->name, "DM-DIF-EXT-TAG")) {
		ti->error = "Integrity profile not supported.";
		return -EINVAL;
	}

	if (bi->tag_size != cc->on_disk_tag_size ||
	    bi->tuple_size != cc->on_disk_tag_size) {
		ti->error = "Integrity profile tag size mismatch.";
		return -EINVAL;
	}
	if (1 << bi->interval_exp != cc->sector_size) {
		ti->error = "Integrity profile sector size mismatch.";
		return -EINVAL;
	}

	if (crypt_integrity_aead(cc)) {
		cc->integrity_tag_size = cc->on_disk_tag_size - cc->integrity_iv_size;
		DMDEBUG("%s: Integrity AEAD, tag size %u, IV size %u.", dm_device_name(md),
		       cc->integrity_tag_size, cc->integrity_iv_size);

		if (crypto_aead_setauthsize(any_tfm_aead(cc), cc->integrity_tag_size)) {
			ti->error = "Integrity AEAD auth tag size is not supported.";
			return -EINVAL;
		}
	} else if (cc->integrity_iv_size)
		DMDEBUG("%s: Additional per-sector space %u bytes for IV.", dm_device_name(md),
		       cc->integrity_iv_size);

	if ((cc->integrity_tag_size + cc->integrity_iv_size) != bi->tag_size) {
		ti->error = "Not enough space for integrity tag in the profile.";
		return -EINVAL;
	}

	return 0;
#else
	ti->error = "Integrity profile not supported.";
	return -EINVAL;
#endif
}

static void crypt_convert_init(struct crypt_config *cc,
			       struct convert_context *ctx,
			       struct bio *bio_out, struct bio *bio_in,
			       sector_t sector)
{
	/*
	 * 初始化一次 bio 转换的游标。bio_in/bio_out 可以相同：读路径通常原地把
	 * base_bio 从密文解成明文；写路径则从 base_bio 读明文，写入 clone bio。
	 */
	ctx->bio_in = bio_in;
	ctx->bio_out = bio_out;
	if (bio_in)
		ctx->iter_in = bio_in->bi_iter;
	if (bio_out)
		ctx->iter_out = bio_out->bi_iter;
	ctx->cc_sector = sector + cc->iv_offset;
	init_completion(&ctx->restart);
}

static struct dm_crypt_request *dmreq_of_req(struct crypt_config *cc,
					     void *req)
{
	/* request 内存布局里，dmreq 位于 crypto request 后面的 cc->dmreq_start 偏移。 */
	return (struct dm_crypt_request *)((char *)req + cc->dmreq_start);
}

static void *req_of_dmreq(struct crypt_config *cc, struct dm_crypt_request *dmreq)
{
	/* dmreq_of_req() 的反向换算，用于异步完成时释放原始 crypto request。 */
	return (void *)((char *)dmreq - cc->dmreq_start);
}

static u8 *iv_of_dmreq(struct crypt_config *cc,
		       struct dm_crypt_request *dmreq)
{
	/*
	 * IV 紧跟在 dmreq 后面，但必须满足算法要求的 alignmask，因此不能简单用
	 * (u8 *)(dmreq + 1)，需要 ALIGN()。
	 */
	if (crypt_integrity_aead(cc))
		return (u8 *)ALIGN((unsigned long)(dmreq + 1),
			crypto_aead_alignmask(any_tfm_aead(cc)) + 1);
	else
		return (u8 *)ALIGN((unsigned long)(dmreq + 1),
			crypto_skcipher_alignmask(any_tfm(cc)) + 1);
}

static u8 *org_iv_of_dmreq(struct crypt_config *cc,
		       struct dm_crypt_request *dmreq)
{
	return iv_of_dmreq(cc, dmreq) + cc->iv_size;
}

static __le64 *org_sector_of_dmreq(struct crypt_config *cc,
		       struct dm_crypt_request *dmreq)
{
	u8 *ptr = iv_of_dmreq(cc, dmreq) + cc->iv_size + cc->iv_size;
	return (__le64 *) ptr;
}

static unsigned int *org_tag_of_dmreq(struct crypt_config *cc,
		       struct dm_crypt_request *dmreq)
{
	u8 *ptr = iv_of_dmreq(cc, dmreq) + cc->iv_size +
		  cc->iv_size + sizeof(uint64_t);
	return (unsigned int*)ptr;
}

static void *tag_from_dmreq(struct crypt_config *cc,
				struct dm_crypt_request *dmreq)
{
	struct convert_context *ctx = dmreq->ctx;
	struct dm_crypt_io *io = container_of(ctx, struct dm_crypt_io, ctx);

	return &io->integrity_metadata[*org_tag_of_dmreq(cc, dmreq) *
		cc->on_disk_tag_size];
}

static void *iv_tag_from_dmreq(struct crypt_config *cc,
			       struct dm_crypt_request *dmreq)
{
	return tag_from_dmreq(cc, dmreq) + cc->integrity_tag_size;
}

static int crypt_convert_block_aead(struct crypt_config *cc,
				     struct convert_context *ctx,
				     struct aead_request *req,
				     unsigned int tag_offset)
{
	struct bio_vec bv_in = bio_iter_iovec(ctx->bio_in, ctx->iter_in);
	struct bio_vec bv_out = bio_iter_iovec(ctx->bio_out, ctx->iter_out);
	struct dm_crypt_request *dmreq;
	u8 *iv, *org_iv, *tag_iv, *tag;
	__le64 *sector;
	int r = 0;

	/*
	 * 处理一个加密 sector 的 AEAD 模式。AEAD 不只是加/解密数据，还会认证 AAD
	 * 和密文 tag；tag 错误时会返回 -EBADMSG，最终转换成 BLK_STS_PROTECTION。
	 */
	BUG_ON(cc->integrity_iv_size && cc->integrity_iv_size != cc->iv_size);

	/* Reject unexpected unaligned bio. */
	if (unlikely(bv_in.bv_len & (cc->sector_size - 1)))
		return -EIO;

	dmreq = dmreq_of_req(cc, req);
	dmreq->iv_sector = ctx->cc_sector;
	if (test_bit(CRYPT_IV_LARGE_SECTORS, &cc->cipher_flags))
		dmreq->iv_sector >>= cc->sector_shift;
	dmreq->ctx = ctx;

	*org_tag_of_dmreq(cc, dmreq) = tag_offset;

	sector = org_sector_of_dmreq(cc, dmreq);
	*sector = cpu_to_le64(ctx->cc_sector - cc->iv_offset);

	/* 当前 request 的临时缓冲都在 dmreq 后面，靠这些 helper 按布局取地址。 */
	iv = iv_of_dmreq(cc, dmreq);
	org_iv = org_iv_of_dmreq(cc, dmreq);
	tag = tag_from_dmreq(cc, dmreq);
	tag_iv = iv_tag_from_dmreq(cc, dmreq);

	/* AEAD request:
	 *  |----- AAD -------|------ DATA -------|-- AUTH TAG --|
	 *  | (authenticated) | (auth+encryption) |              |
	 *  | sector_LE |  IV |  sector in/out    |  tag in/out  |
	 */
	sg_init_table(dmreq->sg_in, 4);
	sg_set_buf(&dmreq->sg_in[0], sector, sizeof(uint64_t));
	sg_set_buf(&dmreq->sg_in[1], org_iv, cc->iv_size);
	sg_set_page(&dmreq->sg_in[2], bv_in.bv_page, cc->sector_size, bv_in.bv_offset);
	sg_set_buf(&dmreq->sg_in[3], tag, cc->integrity_tag_size);

	sg_init_table(dmreq->sg_out, 4);
	sg_set_buf(&dmreq->sg_out[0], sector, sizeof(uint64_t));
	sg_set_buf(&dmreq->sg_out[1], org_iv, cc->iv_size);
	sg_set_page(&dmreq->sg_out[2], bv_out.bv_page, cc->sector_size, bv_out.bv_offset);
	sg_set_buf(&dmreq->sg_out[3], tag, cc->integrity_tag_size);

	if (cc->iv_gen_ops) {
		/* For READs use IV stored in integrity metadata */
		if (cc->integrity_iv_size && bio_data_dir(ctx->bio_in) != WRITE) {
			memcpy(org_iv, tag_iv, cc->iv_size);
		} else {
			r = cc->iv_gen_ops->generator(cc, org_iv, dmreq);
			if (r < 0)
				return r;
			/* Store generated IV in integrity metadata */
			if (cc->integrity_iv_size)
				memcpy(tag_iv, org_iv, cc->iv_size);
		}
		/* Working copy of IV, to be modified in crypto API */
		memcpy(iv, org_iv, cc->iv_size);
	}

	aead_request_set_ad(req, sizeof(uint64_t) + cc->iv_size);
	if (bio_data_dir(ctx->bio_in) == WRITE) {
		aead_request_set_crypt(req, dmreq->sg_in, dmreq->sg_out,
				       cc->sector_size, iv);
		r = crypto_aead_encrypt(req);
		if (cc->integrity_tag_size + cc->integrity_iv_size != cc->on_disk_tag_size)
			memset(tag + cc->integrity_tag_size + cc->integrity_iv_size, 0,
			       cc->on_disk_tag_size - (cc->integrity_tag_size + cc->integrity_iv_size));
	} else {
		aead_request_set_crypt(req, dmreq->sg_in, dmreq->sg_out,
				       cc->sector_size + cc->integrity_tag_size, iv);
		r = crypto_aead_decrypt(req);
	}

	if (r == -EBADMSG) {
		char b[BDEVNAME_SIZE];
		DMERR_LIMIT("%s: INTEGRITY AEAD ERROR, sector %llu", crypt_bio_devname(ctx->bio_in, b),
			    (unsigned long long)le64_to_cpu(*sector));
	}

	if (!r && cc->iv_gen_ops && cc->iv_gen_ops->post)
		r = cc->iv_gen_ops->post(cc, org_iv, dmreq);

	bio_advance_iter(ctx->bio_in, &ctx->iter_in, cc->sector_size);
	bio_advance_iter(ctx->bio_out, &ctx->iter_out, cc->sector_size);

	return r;
}

static int crypt_convert_block_skcipher(struct crypt_config *cc,
					struct convert_context *ctx,
					struct skcipher_request *req,
					unsigned int tag_offset)
{
	struct bio_vec bv_in = bio_iter_iovec(ctx->bio_in, ctx->iter_in);
	struct bio_vec bv_out = bio_iter_iovec(ctx->bio_out, ctx->iter_out);
	struct scatterlist *sg_in, *sg_out;
	struct dm_crypt_request *dmreq;
	u8 *iv, *org_iv, *tag_iv;
	__le64 *sector;
	int r = 0;

	/*
	 * 处理一个加密 sector 的普通 skcipher 模式。它只关心输入数据、输出数据和 IV，
	 * 不负责认证 tag；如果配置了 integrity_iv_size，也只把 IV 存进 metadata。
	 */
	/* Reject unexpected unaligned bio. */
	if (unlikely(bv_in.bv_len & (cc->sector_size - 1)))
		return -EIO;

	dmreq = dmreq_of_req(cc, req);
	dmreq->iv_sector = ctx->cc_sector;
	if (test_bit(CRYPT_IV_LARGE_SECTORS, &cc->cipher_flags))
		dmreq->iv_sector >>= cc->sector_shift;
	dmreq->ctx = ctx;

	*org_tag_of_dmreq(cc, dmreq) = tag_offset;

	iv = iv_of_dmreq(cc, dmreq);
	org_iv = org_iv_of_dmreq(cc, dmreq);
	tag_iv = iv_tag_from_dmreq(cc, dmreq);

	sector = org_sector_of_dmreq(cc, dmreq);
	*sector = cpu_to_le64(ctx->cc_sector - cc->iv_offset);

	/* For skcipher we use only the first sg item */
	sg_in  = &dmreq->sg_in[0];
	sg_out = &dmreq->sg_out[0];

	sg_init_table(sg_in, 1);
	sg_set_page(sg_in, bv_in.bv_page, cc->sector_size, bv_in.bv_offset);

	sg_init_table(sg_out, 1);
	sg_set_page(sg_out, bv_out.bv_page, cc->sector_size, bv_out.bv_offset);

	if (cc->iv_gen_ops) {
		/* For READs use IV stored in integrity metadata */
		if (cc->integrity_iv_size && bio_data_dir(ctx->bio_in) != WRITE) {
			memcpy(org_iv, tag_iv, cc->integrity_iv_size);
		} else {
			r = cc->iv_gen_ops->generator(cc, org_iv, dmreq);
			if (r < 0)
				return r;
			/* Store generated IV in integrity metadata */
			if (cc->integrity_iv_size)
				memcpy(tag_iv, org_iv, cc->integrity_iv_size);
		}
		/* Working copy of IV, to be modified in crypto API */
		memcpy(iv, org_iv, cc->iv_size);
	}

	skcipher_request_set_crypt(req, sg_in, sg_out, cc->sector_size, iv);

	if (bio_data_dir(ctx->bio_in) == WRITE)
		r = crypto_skcipher_encrypt(req);
	else
		r = crypto_skcipher_decrypt(req);

	if (!r && cc->iv_gen_ops && cc->iv_gen_ops->post)
		r = cc->iv_gen_ops->post(cc, org_iv, dmreq);

	bio_advance_iter(ctx->bio_in, &ctx->iter_in, cc->sector_size);
	bio_advance_iter(ctx->bio_out, &ctx->iter_out, cc->sector_size);

	return r;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
static void kcryptd_async_done(void *data, int error);
#else
static void kcryptd_async_done(struct crypto_async_request *async_req,
			       int error);
#endif

static void crypt_alloc_req_skcipher(struct crypt_config *cc,
				     struct convert_context *ctx)
{
	unsigned key_index = ctx->cc_sector & (cc->tfms_count - 1);

	/*
	 * 多 key 模式按 sector 在 tfms[] 中轮转。tfms_count 要求是 2 的幂，所以用
	 * 按位与比取模更快。
	 */
	if (!ctx->r.req)
		ctx->r.req = mempool_alloc(&cc->req_pool, GFP_NOIO);

	skcipher_request_set_tfm(ctx->r.req, cc->cipher_tfm.tfms[key_index]);

	/*
	 * Use REQ_MAY_BACKLOG so a cipher driver internally backlogs
	 * requests if driver request queue is full.
	 */
	skcipher_request_set_callback(ctx->r.req,
	    CRYPTO_TFM_REQ_MAY_BACKLOG,
	    kcryptd_async_done, dmreq_of_req(cc, ctx->r.req));
}

static void crypt_alloc_req_aead(struct crypt_config *cc,
				 struct convert_context *ctx)
{
	if (!ctx->r.req_aead)
		ctx->r.req_aead = mempool_alloc(&cc->req_pool, GFP_NOIO);

	aead_request_set_tfm(ctx->r.req_aead, cc->cipher_tfm.tfms_aead[0]);

	/*
	 * Use REQ_MAY_BACKLOG so a cipher driver internally backlogs
	 * requests if driver request queue is full.
	 */
	aead_request_set_callback(ctx->r.req_aead,
	    CRYPTO_TFM_REQ_MAY_BACKLOG,
	    kcryptd_async_done, dmreq_of_req(cc, ctx->r.req_aead));
}

static void crypt_alloc_req(struct crypt_config *cc,
			    struct convert_context *ctx)
{
	/* 根据当前映射是否使用 AEAD，分配对应类型的 crypto request。 */
	if (crypt_integrity_aead(cc))
		crypt_alloc_req_aead(cc, ctx);
	else
		crypt_alloc_req_skcipher(cc, ctx);
}

static void crypt_free_req_skcipher(struct crypt_config *cc,
				    struct skcipher_request *req, struct bio *base_bio)
{
	struct dm_crypt_io *io = dm_per_bio_data(base_bio, cc->per_bio_data_size);

	if ((struct skcipher_request *)(io + 1) != req)
		mempool_free(req, &cc->req_pool);
}

static void crypt_free_req_aead(struct crypt_config *cc,
				struct aead_request *req, struct bio *base_bio)
{
	struct dm_crypt_io *io = dm_per_bio_data(base_bio, cc->per_bio_data_size);

	if ((struct aead_request *)(io + 1) != req)
		mempool_free(req, &cc->req_pool);
}

static void crypt_free_req(struct crypt_config *cc, void *req, struct bio *base_bio)
{
	if (crypt_integrity_aead(cc))
		crypt_free_req_aead(cc, req, base_bio);
	else
		crypt_free_req_skcipher(cc, req, base_bio);
}

/*
 * Encrypt / decrypt data from one bio to another one (can be the same one)
 *
 * 这是核心转换循环。它每次只处理 cc->sector_size 字节：
 *   - 准备一个 crypto request；
 *   - 生成当前 sector 的 IV；
 *   - 调用 crypto API 加密或解密；
 *   - 根据同步/异步返回值更新游标和 pending 计数。
 *
 * 返回 0 只表示“已经成功发起或同步完成所有转换”。如果有异步请求，真正的完成会
 * 走 kcryptd_async_done()。
 */
static blk_status_t crypt_convert(struct crypt_config *cc,
			 struct convert_context *ctx)
{
	unsigned int tag_offset = 0;
	unsigned int sector_step = cc->sector_size >> SECTOR_SHIFT;
	int r;

	atomic_set(&ctx->cc_pending, 1);

	while (ctx->iter_in.bi_size && ctx->iter_out.bi_size) {

		crypt_alloc_req(cc, ctx);
		atomic_inc(&ctx->cc_pending);

		if (crypt_integrity_aead(cc))
			r = crypt_convert_block_aead(cc, ctx, ctx->r.req_aead, tag_offset);
		else
			r = crypt_convert_block_skcipher(cc, ctx, ctx->r.req, tag_offset);

		switch (r) {
		/*
		 * The request was queued by a crypto driver
		 * but the driver request queue is full, let's wait.
		 */
		case -EBUSY:
			wait_for_completion(&ctx->restart);
			reinit_completion(&ctx->restart);
			fallthrough;
		/*
		 * The request is queued and processed asynchronously,
		 * completion function kcryptd_async_done() will be called.
		 */
		case -EINPROGRESS:
			ctx->r.req = NULL;
			ctx->cc_sector += sector_step;
			tag_offset++;
			continue;
		/*
		 * The request was already processed (synchronously).
		 */
		case 0:
			atomic_dec(&ctx->cc_pending);
			ctx->cc_sector += sector_step;
			tag_offset++;
			cond_resched();
			continue;
		/*
		 * There was a data integrity error.
		 */
		case -EBADMSG:
			atomic_dec(&ctx->cc_pending);
			return BLK_STS_PROTECTION;
		/*
		 * There was an error while processing the request.
		 */
		default:
			atomic_dec(&ctx->cc_pending);
			return BLK_STS_IOERR;
		}
	}

	return 0;
}

static void crypt_free_buffer_pages(struct crypt_config *cc, struct bio *clone);

/*
 * Generate a new unfragmented bio with the given size
 * This should never violate the device limitations (but only because
 * max_segment_size is being constrained to PAGE_SIZE).
 *
 * This function may be called concurrently. If we allocate from the mempool
 * concurrently, there is a possibility of deadlock. For example, if we have
 * mempool of 256 pages, two processes, each wanting 256, pages allocate from
 * the mempool concurrently, it may deadlock in a situation where both processes
 * have allocated 128 pages and the mempool is exhausted.
 *
 * In order to avoid this scenario we allocate the pages under a mutex.
 *
 * In order to not degrade performance with excessive locking, we try
 * non-blocking allocations without a mutex first but on failure we fallback
 * to blocking allocations with a mutex.
 */
static struct bio *crypt_alloc_buffer(struct dm_crypt_io *io, unsigned size)
{
	struct crypt_config *cc = io->cc;
	struct bio *clone;
	unsigned int nr_iovecs = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	gfp_t gfp_mask = GFP_NOWAIT | __GFP_HIGHMEM;
	unsigned i, len, remaining_size;
	struct page *page;

retry:
	/*
	 * 写路径不能直接把密文覆盖到上层传来的明文 bio，所以需要新建 clone bio
	 * 和一组 page 作为密文缓冲。这里优先尝试 NOWAIT，失败后进入带 mutex 的
	 * 阻塞慢路径。
	 */
	if (unlikely(gfp_mask & __GFP_DIRECT_RECLAIM))
		mutex_lock(&cc->bio_alloc_lock);

	clone = crypt_alloc_bio(io, nr_iovecs, GFP_NOIO);
	if (!clone)
		goto out;

	clone_init(io, clone);

	remaining_size = size;

	for (i = 0; i < nr_iovecs; i++) {
		page = mempool_alloc(&cc->page_pool, gfp_mask);
		if (!page) {
			crypt_free_buffer_pages(cc, clone);
			bio_put(clone);
			gfp_mask |= __GFP_DIRECT_RECLAIM;
			goto retry;
		}

		len = (remaining_size > PAGE_SIZE) ? PAGE_SIZE : remaining_size;

		__bio_add_page(clone, page, len, 0);

		remaining_size -= len;
	}

	/* Allocate space for integrity tags */
	if (dm_crypt_integrity_io_alloc(io, clone)) {
		crypt_free_buffer_pages(cc, clone);
		bio_put(clone);
		clone = NULL;
	}
out:
	if (unlikely(gfp_mask & __GFP_DIRECT_RECLAIM))
		mutex_unlock(&cc->bio_alloc_lock);

	return clone;
}

static void crypt_free_buffer_pages(struct crypt_config *cc, struct bio *clone)
{
	struct bio_vec *bv;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
	int iter_all;
#else
	struct bvec_iter_all iter_all;
#endif

	/* clone bio 中的 page 都来自 page_pool，IO 完成后必须逐个归还。 */
	bio_for_each_segment_all(bv, clone, iter_all) {
		BUG_ON(!bv->bv_page);
		mempool_free(bv->bv_page, &cc->page_pool);
	}
}

static void crypt_io_init(struct dm_crypt_io *io, struct crypt_config *cc,
			  struct bio *bio, sector_t sector)
{
	/*
	 * crypt_map() 每接到一个新 bio 都会初始化一份 dm_crypt_io。这里不分配
	 * 大对象，只把生命周期状态清零，后续读写路径再按需申请 clone/tag/request。
	 */
	io->cc = cc;
	io->base_bio = bio;
	io->sector = sector;
	io->error = 0;
	io->ctx.r.req = NULL;
	io->integrity_metadata = NULL;
	io->integrity_metadata_from_pool = false;
	atomic_set(&io->io_pending, 0);
}

static void crypt_inc_pending(struct dm_crypt_io *io)
{
	/* 增加一个未完成子任务，防止 base_bio 过早 bio_endio()。 */
	atomic_inc(&io->io_pending);
}

/*
 * One of the bios was finished. Check for completion of
 * the whole request and correctly clean up the buffer.
 */
static void crypt_dec_pending(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;
	struct bio *base_bio = io->base_bio;
	blk_status_t error = io->error;

	/*
	 * 每个提交出去的 clone bio、每个排队的 work、每段异步 crypto request 都会
	 * 持有一个 pending。只有最后一个 pending 归零，才说明原始 bio 的所有工作
	 * 都结束了。
	 */
	if (!atomic_dec_and_test(&io->io_pending))
		return;

	if (io->ctx.r.req)
		crypt_free_req(cc, io->ctx.r.req, base_bio);

	if (unlikely(io->integrity_metadata_from_pool))
		mempool_free(io->integrity_metadata, &io->cc->tag_pool);
	else
		kfree(io->integrity_metadata);

	base_bio->bi_status = error;
	/* 这是上层真正看到的完成通知。 */
	bio_endio(base_bio);
}

/*
 * kcryptd/kcryptd_io:
 *
 * Needed because it would be very unwise to do decryption in an
 * interrupt context.
 *
 * kcryptd performs the actual encryption or decryption.
 *
 * kcryptd_io performs the IO submission.
 *
 * They must be separated as otherwise the final stages could be
 * starved by new requests which can block in the first stages due
 * to memory allocation.
 *
 * The work is done per CPU global for all dm-crypt instances.
 * They should not depend on each other and do not block.
 */
static void crypt_endio(struct bio *clone)
{
	struct dm_crypt_io *io = clone->bi_private;
	struct crypt_config *cc = io->cc;
	unsigned rw = bio_data_dir(clone);
	blk_status_t error;

	/*
	 * free the processed pages
	 *
	 * 写路径 clone bio 的 page 是 dm-crypt 分配的密文缓冲；底层写完成后即可释放。
	 * 读路径 clone 是基于原始 bio 的 fast clone，数据还要继续解密，不能在这里
	 * 释放原始 page。
	 */
	if (rw == WRITE)
		crypt_free_buffer_pages(cc, clone);

	error = clone->bi_status;
	bio_put(clone);

	if (rw == READ && !error) {
		/* 底层已经读回密文，下一步排队到 crypt_queue 做解密。 */
		kcryptd_queue_crypt(io);
		return;
	}

	if (unlikely(error))
		io->error = error;

	crypt_dec_pending(io);
}

static void clone_init(struct dm_crypt_io *io, struct bio *clone)
{
	struct crypt_config *cc = io->cc;

	/*
	 * clone bio 是提交到底层真实设备的 bio。bi_private 指回 dm_crypt_io，
	 * end_io 时才能找到原始 bio 和 pending 计数。
	 */
	clone->bi_private = io;
	clone->bi_end_io  = crypt_endio;
	bio_set_dev(clone, cc->dev->bdev);
	clone->bi_opf	  = io->base_bio->bi_opf;
}

static int kcryptd_io_read(struct dm_crypt_io *io, gfp_t gfp)
{
	struct crypt_config *cc = io->cc;
	struct bio *clone;

	/*
	 * We need the original biovec array in order to decrypt
	 * the whole bio data *afterwards* -- thanks to immutable
	 * biovecs we don't need to worry about the block layer
	 * modifying the biovec array; so leverage a fast clone.
	 */
	clone = crypt_clone_bio(io, gfp);
	if (!clone)
		return 1;

	/*
	 * 读路径先把“同一批 page”提交到底层设备读密文。底层完成后 crypt_endio()
	 * 再把这些 page 原地解密成明文。
	 */
	crypt_inc_pending(io);

	clone_init(io, clone);
	clone->bi_iter.bi_sector = cc->start + io->sector;

	if (dm_crypt_integrity_io_alloc(io, clone)) {
		crypt_dec_pending(io);
		bio_put(clone);
		return 1;
	}

	crypt_submit_bio(io, clone);
	return 0;
}

static void kcryptd_io_read_work(struct work_struct *work)
{
	struct dm_crypt_io *io = container_of(work, struct dm_crypt_io, work);

	/* GFP_NOWAIT 读 clone 失败时，退到工作队列里用 GFP_NOIO 再尝试一次。 */
	crypt_inc_pending(io);
	if (kcryptd_io_read(io, GFP_NOIO))
		io->error = BLK_STS_RESOURCE;
	crypt_dec_pending(io);
}

static void kcryptd_queue_read(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;

	/* 把读 IO 提交动作放到 io_queue，避免 crypt_map() 快路径里阻塞等待内存。 */
	INIT_WORK(&io->work, kcryptd_io_read_work);
	queue_work(cc->io_queue, &io->work);
}

static void kcryptd_io_write(struct dm_crypt_io *io)
{
	struct bio *clone = io->ctx.bio_out;

	/* clone 里已经是密文，直接提交到底层设备。完成回调是 crypt_endio()。 */
	crypt_submit_bio(io, clone);
}

#define crypt_io_from_node(node) rb_entry((node), struct dm_crypt_io, rb_node)

static int dmcrypt_write(void *data)
{
	struct crypt_config *cc = data;
	struct dm_crypt_io *io;

	/*
	 * 写线程的职责很窄：把加密完成的写 clone bio 按 sector 顺序弹出并提交。
	 * 这样可以减少多个 CPU 并行加密导致的乱序写，对机械盘和部分后端更友好。
	 */
	while (1) {
		struct rb_root write_tree;
		struct blk_plug plug;

		spin_lock_irq(&cc->write_thread_lock);
continue_locked:

		if (!RB_EMPTY_ROOT(&cc->write_tree))
			goto pop_from_list;

		set_current_state(TASK_INTERRUPTIBLE);

		spin_unlock_irq(&cc->write_thread_lock);

		if (unlikely(kthread_should_stop())) {
			set_current_state(TASK_RUNNING);
			break;
		}

		schedule();

		set_current_state(TASK_RUNNING);
		spin_lock_irq(&cc->write_thread_lock);
		goto continue_locked;

pop_from_list:
		write_tree = cc->write_tree;
		cc->write_tree = RB_ROOT;
		spin_unlock_irq(&cc->write_thread_lock);

		BUG_ON(rb_parent(write_tree.rb_node));

		/*
		 * Note: we cannot walk the tree here with rb_next because
		 * the structures may be freed when kcryptd_io_write is called.
		 */
		blk_start_plug(&plug);
		do {
			io = crypt_io_from_node(rb_first(&write_tree));
			rb_erase(&io->rb_node, &write_tree);
			kcryptd_io_write(io);
		} while (!RB_EMPTY_ROOT(&write_tree));
		blk_finish_plug(&plug);
	}
	return 0;
}

static void kcryptd_crypt_write_io_submit(struct dm_crypt_io *io, int async)
{
	struct bio *clone = io->ctx.bio_out;
	struct crypt_config *cc = io->cc;
	unsigned long flags;
	sector_t sector;
	struct rb_node **rbp, *parent;

	/*
	 * 写路径到这里时，数据已经加密到了 clone bio。若加密失败，释放 clone 并
	 * 完成原始 bio；若成功，则设置底层 sector 后提交。
	 */
	if (unlikely(io->error)) {
		crypt_free_buffer_pages(cc, clone);
		bio_put(clone);
		crypt_dec_pending(io);
		return;
	}

	/* crypt_convert should have filled the clone bio */
	BUG_ON(io->ctx.iter_out.bi_size);

	clone->bi_iter.bi_sector = cc->start + io->sector;

	if (likely(!async) && test_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags)) {
		/* submit_from_crypt_cpus：不经过写线程排序，直接由当前加密上下文提交。 */
		crypt_submit_bio(io, clone);
		return;
	}

	/* 默认把写请求插入红黑树，由 dmcrypt_write 线程按 sector 顺序提交。 */
	spin_lock_irqsave(&cc->write_thread_lock, flags);
	if (RB_EMPTY_ROOT(&cc->write_tree))
		wake_up_process(cc->write_thread);
	rbp = &cc->write_tree.rb_node;
	parent = NULL;
	sector = io->sector;
	while (*rbp) {
		parent = *rbp;
		if (sector < crypt_io_from_node(parent)->sector)
			rbp = &(*rbp)->rb_left;
		else
			rbp = &(*rbp)->rb_right;
	}
	rb_link_node(&io->rb_node, parent, rbp);
	rb_insert_color(&io->rb_node, &cc->write_tree);
	spin_unlock_irqrestore(&cc->write_thread_lock, flags);
}

static void kcryptd_crypt_write_convert(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;
	struct bio *clone;
	int crypt_finished;
	sector_t sector = io->sector;
	blk_status_t r;

	/*
	 * Prevent io from disappearing until this function completes.
	 *
	 * 当前 work 自己也持有一个 pending，否则同步加密并提交完成得太快时，io 可能
	 * 在函数返回前被最后一个完成路径释放。
	 */
	crypt_inc_pending(io);
	crypt_convert_init(cc, &io->ctx, NULL, io->base_bio, sector);

	/* 写路径分配密文输出 clone bio。 */
	clone = crypt_alloc_buffer(io, io->base_bio->bi_iter.bi_size);
	if (unlikely(!clone)) {
		io->error = BLK_STS_IOERR;
		goto dec;
	}

	io->ctx.bio_out = clone;
	io->ctx.iter_out = clone->bi_iter;

	sector += bio_sectors(clone);

	crypt_inc_pending(io);
	/* 从 base_bio 明文加密到 clone bio 密文。 */
	r = crypt_convert(cc, &io->ctx);
	if (r)
		io->error = r;
	crypt_finished = atomic_dec_and_test(&io->ctx.cc_pending);

	/* Encryption was already finished, submit io now */
	if (crypt_finished) {
		kcryptd_crypt_write_io_submit(io, 0);
		io->sector = sector;
	}

dec:
	crypt_dec_pending(io);
}

static void kcryptd_crypt_read_done(struct dm_crypt_io *io)
{
	/* 读路径解密完成后只需要减少 pending，最后会完成 base_bio。 */
	crypt_dec_pending(io);
}

static void kcryptd_crypt_read_convert(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;
	blk_status_t r;

	/*
	 * 读路径的底层读已经把密文放进 base_bio 的 page，这里原地解密。bio_in 和
	 * bio_out 都传 base_bio，crypt_convert() 会从同一批 page 读写。
	 */
	crypt_inc_pending(io);

	crypt_convert_init(cc, &io->ctx, io->base_bio, io->base_bio,
			   io->sector);

	r = crypt_convert(cc, &io->ctx);
	if (r)
		io->error = r;

	if (atomic_dec_and_test(&io->ctx.cc_pending))
		kcryptd_crypt_read_done(io);

	crypt_dec_pending(io);
}

static void kcryptd_async_done(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
			       void *data,
#else
			       struct crypto_async_request *async_req,
#endif
			       int error)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	struct dm_crypt_request *dmreq = data;
#else
	struct dm_crypt_request *dmreq = async_req->data;
#endif
	struct convert_context *ctx = dmreq->ctx;
	struct dm_crypt_io *io = container_of(ctx, struct dm_crypt_io, ctx);
	struct crypt_config *cc = io->cc;

	/*
	 * A request from crypto driver backlog is going to be processed now,
	 * finish the completion and continue in crypt_convert().
	 * (Callback will be called for the second time for this request.)
	 */
	if (error == -EINPROGRESS) {
		complete(&ctx->restart);
		return;
	}

	/*
	 * 真正完成一次异步 crypto request。这里可能是读路径的某个 sector 解密完成，
	 * 也可能是写路径的某个 sector 加密完成。最后一个 sector 完成时，读路径完成
	 * base_bio，写路径提交 clone bio。
	 */
	if (!error && cc->iv_gen_ops && cc->iv_gen_ops->post)
		error = cc->iv_gen_ops->post(cc, org_iv_of_dmreq(cc, dmreq), dmreq);

	if (error == -EBADMSG) {
		char b[BDEVNAME_SIZE];
		DMERR_LIMIT("%s: INTEGRITY AEAD ERROR, sector %llu", crypt_bio_devname(ctx->bio_in, b),
			    (unsigned long long)le64_to_cpu(*org_sector_of_dmreq(cc, dmreq)));
		io->error = BLK_STS_PROTECTION;
	} else if (error < 0)
		io->error = BLK_STS_IOERR;

	crypt_free_req(cc, req_of_dmreq(cc, dmreq), io->base_bio);

	if (!atomic_dec_and_test(&ctx->cc_pending))
		return;

	if (bio_data_dir(io->base_bio) == READ)
		kcryptd_crypt_read_done(io);
	else
		kcryptd_crypt_write_io_submit(io, 1);
}

static void kcryptd_crypt(struct work_struct *work)
{
	struct dm_crypt_io *io = container_of(work, struct dm_crypt_io, work);

	/* crypt_queue 的统一入口，根据 bio 方向分到读解密或写加密。 */
	if (bio_data_dir(io->base_bio) == READ)
		kcryptd_crypt_read_convert(io);
	else
		kcryptd_crypt_write_convert(io);
}

static void kcryptd_queue_crypt(struct dm_crypt_io *io)
{
	struct crypt_config *cc = io->cc;

	/* 把 CPU 密集的加/解密工作交给 crypt_queue。 */
	INIT_WORK(&io->work, kcryptd_crypt);
	queue_work(cc->crypt_queue, &io->work);
}

static void crypt_free_tfms_aead(struct crypt_config *cc)
{
	if (!cc->cipher_tfm.tfms_aead)
		return;

	if (cc->cipher_tfm.tfms_aead[0] && !IS_ERR(cc->cipher_tfm.tfms_aead[0])) {
		crypto_free_aead(cc->cipher_tfm.tfms_aead[0]);
		cc->cipher_tfm.tfms_aead[0] = NULL;
	}

	kfree(cc->cipher_tfm.tfms_aead);
	cc->cipher_tfm.tfms_aead = NULL;
}

static void crypt_free_tfms_skcipher(struct crypt_config *cc)
{
	unsigned i;

	if (!cc->cipher_tfm.tfms)
		return;

	for (i = 0; i < cc->tfms_count; i++)
		if (cc->cipher_tfm.tfms[i] && !IS_ERR(cc->cipher_tfm.tfms[i])) {
			crypto_free_skcipher(cc->cipher_tfm.tfms[i]);
			cc->cipher_tfm.tfms[i] = NULL;
		}

	kfree(cc->cipher_tfm.tfms);
	cc->cipher_tfm.tfms = NULL;
}

static void crypt_free_tfms(struct crypt_config *cc)
{
	/* crypt_dtr() 统一调用这里释放算法实例，内部按 AEAD/普通模式分支。 */
	if (crypt_integrity_aead(cc))
		crypt_free_tfms_aead(cc);
	else
		crypt_free_tfms_skcipher(cc);
}

static int crypt_alloc_tfms_skcipher(struct crypt_config *cc, char *ciphermode)
{
	unsigned i;
	int err;

	/*
	 * 普通模式可能有多个 tfm。典型单 key 只有 1 个；Loop-AES 兼容的 lmk 可有
	 * 64 个，按 sector 轮转选择。
	 */
	cc->cipher_tfm.tfms = kcalloc(cc->tfms_count,
				      sizeof(struct crypto_skcipher *),
				      GFP_KERNEL);
	if (!cc->cipher_tfm.tfms)
		return -ENOMEM;

	for (i = 0; i < cc->tfms_count; i++) {
		cc->cipher_tfm.tfms[i] = crypto_alloc_skcipher(ciphermode, 0, 0);
		if (IS_ERR(cc->cipher_tfm.tfms[i])) {
			err = PTR_ERR(cc->cipher_tfm.tfms[i]);
			crypt_free_tfms(cc);
			return err;
		}
	}

	/*
	 * dm-crypt performance can vary greatly depending on which crypto
	 * algorithm implementation is used.  Help people debug performance
	 * problems by logging the ->cra_driver_name.
	 */
	DMDEBUG_LIMIT("%s using implementation \"%s\"", ciphermode,
	       crypto_skcipher_alg(any_tfm(cc))->base.cra_driver_name);
	return 0;
}

static int crypt_alloc_tfms_aead(struct crypt_config *cc, char *ciphermode)
{
	int err;

	/* AEAD 模式在这版代码里只分配一个 aead tfm。 */
	cc->cipher_tfm.tfms = kmalloc(sizeof(struct crypto_aead *), GFP_KERNEL);
	if (!cc->cipher_tfm.tfms)
		return -ENOMEM;

	cc->cipher_tfm.tfms_aead[0] = crypto_alloc_aead(ciphermode, 0, 0);
	if (IS_ERR(cc->cipher_tfm.tfms_aead[0])) {
		err = PTR_ERR(cc->cipher_tfm.tfms_aead[0]);
		crypt_free_tfms(cc);
		return err;
	}

	DMDEBUG_LIMIT("%s using implementation \"%s\"", ciphermode,
	       crypto_aead_alg(any_tfm_aead(cc))->base.cra_driver_name);
	return 0;
}

static int crypt_alloc_tfms(struct crypt_config *cc, char *ciphermode)
{
	if (crypt_integrity_aead(cc))
		return crypt_alloc_tfms_aead(cc, ciphermode);
	else
		return crypt_alloc_tfms_skcipher(cc, ciphermode);
}

static unsigned crypt_subkey_size(struct crypt_config *cc)
{
	/*
	 * key buffer 可能包含额外 IV seed/whitening key。真正给数据加密算法使用的
	 * 子 key 长度要先扣掉 key_extra_size，再按 tfms_count 平分。
	 */
	return (cc->key_size - cc->key_extra_size) >> ilog2(cc->tfms_count);
}

static unsigned crypt_authenckey_size(struct crypt_config *cc)
{
	return crypt_subkey_size(cc) + RTA_SPACE(sizeof(struct crypto_authenc_key_param));
}

/*
 * If AEAD is composed like authenc(hmac(sha256),xts(aes)),
 * the key must be for some reason in special format.
 * This funcion converts cc->key to this special format.
 */
static void crypt_copy_authenckey(char *p, const void *key,
				  unsigned enckeylen, unsigned authkeylen)
{
	struct crypto_authenc_key_param *param;
	struct rtattr *rta;

	rta = (struct rtattr *)p;
	param = RTA_DATA(rta);
	param->enckeylen = cpu_to_be32(enckeylen);
	rta->rta_len = RTA_LENGTH(sizeof(*param));
	rta->rta_type = CRYPTO_AUTHENC_KEYA_PARAM;
	p += RTA_SPACE(sizeof(*param));
	memcpy(p, key + enckeylen, authkeylen);
	p += authkeylen;
	memcpy(p, key, enckeylen);
}

static int crypt_setkey(struct crypt_config *cc)
{
	unsigned subkey_size;
	int err = 0, i, r;

	/* Ignore extra keys (which are used for IV etc) */
	subkey_size = crypt_subkey_size(cc);

	/*
	 * 把 cc->key 安装到 Linux Crypto API 的 tfm 中。普通 skcipher 直接传子 key；
	 * AEAD/authenc 需要按算法要求把加密 key 和认证 key 重新打包。
	 */
	if (crypt_integrity_hmac(cc)) {
		if (subkey_size < cc->key_mac_size)
			return -EINVAL;

		crypt_copy_authenckey(cc->authenc_key, cc->key,
				      subkey_size - cc->key_mac_size,
				      cc->key_mac_size);
	}

	for (i = 0; i < cc->tfms_count; i++) {
		if (crypt_integrity_hmac(cc))
			r = crypto_aead_setkey(cc->cipher_tfm.tfms_aead[i],
				cc->authenc_key, crypt_authenckey_size(cc));
		else if (crypt_integrity_aead(cc))
			r = crypto_aead_setkey(cc->cipher_tfm.tfms_aead[i],
					       cc->key + (i * subkey_size),
					       subkey_size);
		else
			r = crypto_skcipher_setkey(cc->cipher_tfm.tfms[i],
						   cc->key + (i * subkey_size),
						   subkey_size);
		if (r)
			err = r;
	}

	if (crypt_integrity_hmac(cc))
		memzero_explicit(cc->authenc_key, crypt_authenckey_size(cc));

	return err;
}

#ifdef CONFIG_KEYS

static bool contains_whitespace(const char *str)
{
	while (*str)
		if (isspace(*str++))
			return true;
	return false;
}

static int crypt_set_keyring_key(struct crypt_config *cc, const char *key_string)
{
	char *new_key_string, *key_desc;
	int ret;
	struct key *key;
	const struct user_key_payload *ukp;

	/*
	 * Reject key_string with whitespace. dm core currently lacks code for
	 * proper whitespace escaping in arguments on DM_TABLE_STATUS path.
	 *
	 * keyring 形式的 key 不直接写在映射表里，而是形如 :<size>:logon:<desc>。
	 * 真正的 key payload 从内核 keyring 里按描述符查出来。
	 */
	if (contains_whitespace(key_string)) {
		DMERR("whitespace chars not allowed in key string");
		return -EINVAL;
	}

	/* look for next ':' separating key_type from key_description */
	key_desc = strpbrk(key_string, ":");
	if (!key_desc || key_desc == key_string || !strlen(key_desc + 1))
		return -EINVAL;

	if (strncmp(key_string, "logon:", key_desc - key_string + 1) &&
	    strncmp(key_string, "user:", key_desc - key_string + 1))
		return -EINVAL;

	new_key_string = kstrdup(key_string, GFP_KERNEL);
	if (!new_key_string)
		return -ENOMEM;

	key = request_key(key_string[0] == 'l' ? &key_type_logon : &key_type_user,
			  key_desc + 1, NULL);
	if (IS_ERR(key)) {
		kzfree(new_key_string);
		return PTR_ERR(key);
	}

	down_read(&key->sem);

	ukp = user_key_payload_locked(key);
	if (!ukp) {
		up_read(&key->sem);
		key_put(key);
		kzfree(new_key_string);
		return -EKEYREVOKED;
	}

	if (cc->key_size != ukp->datalen) {
		up_read(&key->sem);
		key_put(key);
		kzfree(new_key_string);
		return -EINVAL;
	}

	memcpy(cc->key, ukp->data, cc->key_size);

	up_read(&key->sem);
	key_put(key);

	/* clear the flag since following operations may invalidate previously valid key */
	clear_bit(DM_CRYPT_KEY_VALID, &cc->flags);

	ret = crypt_setkey(cc);

	if (!ret) {
		set_bit(DM_CRYPT_KEY_VALID, &cc->flags);
		kzfree(cc->key_string);
		cc->key_string = new_key_string;
	} else
		kzfree(new_key_string);

	return ret;
}

static int get_key_size(char **key_string)
{
	char *colon, dummy;
	int ret;

	/*
	 * 普通十六进制 key：两个字符表示一个字节。
	 * keyring key：:<size>:<type>:<desc>，size 明确写在字符串开头。
	 */
	if (*key_string[0] != ':')
		return strlen(*key_string) >> 1;

	/* look for next ':' in key string */
	colon = strpbrk(*key_string + 1, ":");
	if (!colon)
		return -EINVAL;

	if (sscanf(*key_string + 1, "%u%c", &ret, &dummy) != 2 || dummy != ':')
		return -EINVAL;

	*key_string = colon;

	/* remaining key string should be :<logon|user>:<key_desc> */

	return ret;
}

#else

static int crypt_set_keyring_key(struct crypt_config *cc, const char *key_string)
{
	return -EINVAL;
}

static int get_key_size(char **key_string)
{
	return (*key_string[0] == ':') ? -EINVAL : strlen(*key_string) >> 1;
}

#endif

static int crypt_set_key(struct crypt_config *cc, char *key)
{
	int r = -EINVAL;
	int key_string_len = strlen(key);

	/*
	 * table 里传进来的 key 可能是十六进制明文，也可能是 keyring 引用。
	 * 这里完成解析、写入 cc->key、调用 crypt_setkey()，最后尽量擦除字符串副本。
	 */
	/* Hyphen (which gives a key_size of zero) means there is no key. */
	if (!cc->key_size && strcmp(key, "-"))
		goto out;

	/* ':' means the key is in kernel keyring, short-circuit normal key processing */
	if (key[0] == ':') {
		r = crypt_set_keyring_key(cc, key + 1);
		goto out;
	}

	/* clear the flag since following operations may invalidate previously valid key */
	clear_bit(DM_CRYPT_KEY_VALID, &cc->flags);

	/* wipe references to any kernel keyring key */
	kzfree(cc->key_string);
	cc->key_string = NULL;

	/* Decode key from its hex representation. */
	if (cc->key_size && hex2bin(cc->key, key, cc->key_size) < 0)
		goto out;

	r = crypt_setkey(cc);
	if (!r)
		set_bit(DM_CRYPT_KEY_VALID, &cc->flags);

out:
	/* Hex key string not needed after here, so wipe it. */
	memset(key, '0', key_string_len);

	return r;
}

static int crypt_wipe_key(struct crypt_config *cc)
{
	int r;

	/*
	 * wipe 并不是简单把 key 清零后结束。为了让已经存在的 tfm 不再持有旧 key，
	 * 这里先用随机 key 覆盖并重新 setkey，然后再清掉 cc->key。
	 */
	clear_bit(DM_CRYPT_KEY_VALID, &cc->flags);
	get_random_bytes(&cc->key, cc->key_size);

	/* Wipe IV private keys */
	if (cc->iv_gen_ops && cc->iv_gen_ops->wipe) {
		r = cc->iv_gen_ops->wipe(cc);
		if (r)
			return r;
	}

	kzfree(cc->key_string);
	cc->key_string = NULL;
	r = crypt_setkey(cc);
	memset(&cc->key, 0, cc->key_size * sizeof(u8));

	return r;
}

static void crypt_calculate_pages_per_client(void)
{
	unsigned long pages = (crypt_totalram_pages() - crypt_totalhigh_pages()) * DM_CRYPT_MEMORY_PERCENT / 100;

	/* 每个实例至少保留 DM_CRYPT_MIN_PAGES_PER_CLIENT，内存多时按 2% 低端内存平分。 */
	if (!dm_crypt_clients_n)
		return;

	pages /= dm_crypt_clients_n;
	if (pages < DM_CRYPT_MIN_PAGES_PER_CLIENT)
		pages = DM_CRYPT_MIN_PAGES_PER_CLIENT;
	dm_crypt_pages_per_client = pages;
}

static void *crypt_page_alloc(gfp_t gfp_mask, void *pool_data)
{
	struct crypt_config *cc = pool_data;
	struct page *page;

	/*
	 * Note, percpu_counter_read_positive() may over (and under) estimate
	 * the current usage by at most (batch - 1) * num_online_cpus() pages,
	 * but avoids potential spinlock contention of an exact result.
	 */
	if (unlikely(percpu_counter_read_positive(&cc->n_allocated_pages) >= dm_crypt_pages_per_client) &&
	    likely(gfp_mask & __GFP_NORETRY))
		return NULL;

	/* 真正的页分配入口，配合 page_pool 供 crypt_alloc_buffer() 使用。 */
	page = alloc_page(gfp_mask);
	if (likely(page != NULL))
		percpu_counter_add(&cc->n_allocated_pages, 1);

	return page;
}

static void crypt_page_free(void *page, void *pool_data)
{
	struct crypt_config *cc = pool_data;

	__free_page(page);
	percpu_counter_sub(&cc->n_allocated_pages, 1);
}

static void crypt_dtr(struct dm_target *ti)
{
	struct crypt_config *cc = ti->private;

	/*
	 * Device Mapper 销毁 target 时调用。释放顺序大致和 crypt_ctr() 的申请顺序相反：
	 * 先停后台线程/队列，再释放 crypto tfm、mempool、底层设备、key 字符串和配置。
	 */
	ti->private = NULL;

	if (!cc)
		return;

	if (cc->write_thread)
		kthread_stop(cc->write_thread);

	if (cc->io_queue)
		destroy_workqueue(cc->io_queue);
	if (cc->crypt_queue)
		destroy_workqueue(cc->crypt_queue);

	crypt_free_tfms(cc);

	bioset_exit(&cc->bs);

	mempool_exit(&cc->page_pool);
	mempool_exit(&cc->req_pool);
	mempool_exit(&cc->tag_pool);

	WARN_ON(percpu_counter_sum(&cc->n_allocated_pages) != 0);
	percpu_counter_destroy(&cc->n_allocated_pages);

	if (cc->iv_gen_ops && cc->iv_gen_ops->dtr)
		cc->iv_gen_ops->dtr(cc);

	if (cc->dev)
		dm_put_device(ti, cc->dev);

	kzfree(cc->cipher_string);
	kzfree(cc->key_string);
	kzfree(cc->cipher_auth);
	kzfree(cc->authenc_key);

	mutex_destroy(&cc->bio_alloc_lock);

	/* Must zero key material before freeing */
	kzfree(cc);

	spin_lock(&dm_crypt_clients_lock);
	WARN_ON(!dm_crypt_clients_n);
	dm_crypt_clients_n--;
	crypt_calculate_pages_per_client();
	spin_unlock(&dm_crypt_clients_lock);
}

static int crypt_ctr_ivmode(struct dm_target *ti, const char *ivmode)
{
	struct crypt_config *cc = ti->private;

	/*
	 * 根据 cipher 的 IV 大小和用户指定的 ivmode，选择一套 crypt_iv_operations。
	 * 有些 IV 模式还会调整 key_parts/key_extra_size，因为 key 尾部包含 IV seed。
	 */
	if (crypt_integrity_aead(cc))
		cc->iv_size = crypto_aead_ivsize(any_tfm_aead(cc));
	else
		cc->iv_size = crypto_skcipher_ivsize(any_tfm(cc));

	if (cc->iv_size)
		/* at least a 64 bit sector number should fit in our buffer */
		cc->iv_size = max(cc->iv_size,
				  (unsigned int)(sizeof(u64) / sizeof(u8)));
	else if (ivmode) {
		DMWARN("Selected cipher does not support IVs");
		ivmode = NULL;
	}

	/* Choose ivmode, see comments at iv code. */
	if (ivmode == NULL)
		cc->iv_gen_ops = NULL;
	else if (strcmp(ivmode, "plain") == 0)
		cc->iv_gen_ops = &crypt_iv_plain_ops;
	else if (strcmp(ivmode, "plain64") == 0)
		cc->iv_gen_ops = &crypt_iv_plain64_ops;
	else if (strcmp(ivmode, "plain64be") == 0)
		cc->iv_gen_ops = &crypt_iv_plain64be_ops;
	else if (strcmp(ivmode, "essiv") == 0)
		cc->iv_gen_ops = &crypt_iv_essiv_ops;
	else if (strcmp(ivmode, "benbi") == 0)
		cc->iv_gen_ops = &crypt_iv_benbi_ops;
	else if (strcmp(ivmode, "null") == 0)
		cc->iv_gen_ops = &crypt_iv_null_ops;
	else if (strcmp(ivmode, "eboiv") == 0)
		cc->iv_gen_ops = &crypt_iv_eboiv_ops;
	else if (strcmp(ivmode, "lmk") == 0) {
		cc->iv_gen_ops = &crypt_iv_lmk_ops;
		/*
		 * Version 2 and 3 is recognised according
		 * to length of provided multi-key string.
		 * If present (version 3), last key is used as IV seed.
		 * All keys (including IV seed) are always the same size.
		 */
		if (cc->key_size % cc->key_parts) {
			cc->key_parts++;
			cc->key_extra_size = cc->key_size / cc->key_parts;
		}
	} else if (strcmp(ivmode, "tcw") == 0) {
		cc->iv_gen_ops = &crypt_iv_tcw_ops;
		cc->key_parts += 2; /* IV + whitening */
		cc->key_extra_size = cc->iv_size + TCW_WHITENING_SIZE;
	} else if (strcmp(ivmode, "random") == 0) {
		cc->iv_gen_ops = &crypt_iv_random_ops;
		/* Need storage space in integrity fields. */
		cc->integrity_iv_size = cc->iv_size;
	} else {
		ti->error = "Invalid IV mode";
		return -EINVAL;
	}

	return 0;
}

/*
 * Workaround to parse HMAC algorithm from AEAD crypto API spec.
 * The HMAC is needed to calculate tag size (HMAC digest size).
 * This should be probably done by crypto-api calls (once available...)
 */
static int crypt_ctr_auth_cipher(struct crypt_config *cc, char *cipher_api)
{
	char *start, *end, *mac_alg = NULL;
	struct crypto_ahash *mac;

	/*
	 * authenc(hmac(...),cipher(...)) 这种 AEAD 组合需要知道 HMAC digest 大小，
	 * 因为 key 里要切出一段 MAC key。
	 */
	if (!strstarts(cipher_api, "authenc("))
		return 0;

	start = strchr(cipher_api, '(');
	end = strchr(cipher_api, ',');
	if (!start || !end || ++start > end)
		return -EINVAL;

	mac_alg = kzalloc(end - start + 1, GFP_KERNEL);
	if (!mac_alg)
		return -ENOMEM;
	strncpy(mac_alg, start, end - start);

	mac = crypto_alloc_ahash(mac_alg, 0, 0);
	kfree(mac_alg);

	if (IS_ERR(mac))
		return PTR_ERR(mac);

	cc->key_mac_size = crypto_ahash_digestsize(mac);
	crypto_free_ahash(mac);

	cc->authenc_key = kmalloc(crypt_authenckey_size(cc), GFP_KERNEL);
	if (!cc->authenc_key)
		return -ENOMEM;

	return 0;
}

static int crypt_ctr_cipher_new(struct dm_target *ti, char *cipher_in, char *key,
				char **ivmode, char **ivopts)
{
	struct crypt_config *cc = ti->private;
	char *tmp, *cipher_api, buf[CRYPTO_MAX_ALG_NAME];
	int ret = -EINVAL;

	cc->tfms_count = 1;

	/*
	 * New format (capi: prefix)
	 * capi:cipher_api_spec-iv:ivopts
	 *
	 * 新格式直接暴露 Linux Crypto API 的算法描述，例如 capi:xts(aes)-plain64。
	 * 好处是可以表达更复杂的组合算法，AEAD 也只支持这个格式。
	 */
	tmp = &cipher_in[strlen("capi:")];

	/* Separate IV options if present, it can contain another '-' in hash name */
	*ivopts = strrchr(tmp, ':');
	if (*ivopts) {
		**ivopts = '\0';
		(*ivopts)++;
	}
	/* Parse IV mode */
	*ivmode = strrchr(tmp, '-');
	if (*ivmode) {
		**ivmode = '\0';
		(*ivmode)++;
	}
	/* The rest is crypto API spec */
	cipher_api = tmp;

	/* Alloc AEAD, can be used only in new format. */
	if (crypt_integrity_aead(cc)) {
		ret = crypt_ctr_auth_cipher(cc, cipher_api);
		if (ret < 0) {
			ti->error = "Invalid AEAD cipher spec";
			return -ENOMEM;
		}
	}

	if (*ivmode && !strcmp(*ivmode, "lmk"))
		cc->tfms_count = 64;

	if (*ivmode && !strcmp(*ivmode, "essiv")) {
		if (!*ivopts) {
			ti->error = "Digest algorithm missing for ESSIV mode";
			return -EINVAL;
		}
		ret = snprintf(buf, CRYPTO_MAX_ALG_NAME, "essiv(%s,%s)",
			       cipher_api, *ivopts);
		if (ret < 0 || ret >= CRYPTO_MAX_ALG_NAME) {
			ti->error = "Cannot allocate cipher string";
			return -ENOMEM;
		}
		cipher_api = buf;
	}

	cc->key_parts = cc->tfms_count;

	/* Allocate cipher */
	ret = crypt_alloc_tfms(cc, cipher_api);
	if (ret < 0) {
		ti->error = "Error allocating crypto tfm";
		return ret;
	}

	if (crypt_integrity_aead(cc))
		cc->iv_size = crypto_aead_ivsize(any_tfm_aead(cc));
	else
		cc->iv_size = crypto_skcipher_ivsize(any_tfm(cc));

	return 0;
}

static int crypt_ctr_cipher_old(struct dm_target *ti, char *cipher_in, char *key,
				char **ivmode, char **ivopts)
{
	struct crypt_config *cc = ti->private;
	char *tmp, *cipher, *chainmode, *keycount;
	char *cipher_api = NULL;
	int ret = -EINVAL;
	char dummy;

	/*
	 * 老格式是 dm-crypt 早期的用户接口，例如 aes-cbc-essiv:sha256。
	 * 这里把它翻译成 Crypto API 能识别的 "cbc(aes)" 或 "essiv(cbc(aes),sha256)"。
	 */
	if (strchr(cipher_in, '(') || crypt_integrity_aead(cc)) {
		ti->error = "Bad cipher specification";
		return -EINVAL;
	}

	/*
	 * Legacy dm-crypt cipher specification
	 * cipher[:keycount]-mode-iv:ivopts
	 */
	tmp = cipher_in;
	keycount = strsep(&tmp, "-");
	cipher = strsep(&keycount, ":");

	if (!keycount)
		cc->tfms_count = 1;
	else if (sscanf(keycount, "%u%c", &cc->tfms_count, &dummy) != 1 ||
		 !is_power_of_2(cc->tfms_count)) {
		ti->error = "Bad cipher key count specification";
		return -EINVAL;
	}
	cc->key_parts = cc->tfms_count;

	chainmode = strsep(&tmp, "-");
	*ivmode = strsep(&tmp, ":");
	*ivopts = tmp;

	/*
	 * For compatibility with the original dm-crypt mapping format, if
	 * only the cipher name is supplied, use cbc-plain.
	 */
	if (!chainmode || (!strcmp(chainmode, "plain") && !*ivmode)) {
		chainmode = "cbc";
		*ivmode = "plain";
	}

	if (strcmp(chainmode, "ecb") && !*ivmode) {
		ti->error = "IV mechanism required";
		return -EINVAL;
	}

	cipher_api = kmalloc(CRYPTO_MAX_ALG_NAME, GFP_KERNEL);
	if (!cipher_api)
		goto bad_mem;

	if (*ivmode && !strcmp(*ivmode, "essiv")) {
		if (!*ivopts) {
			ti->error = "Digest algorithm missing for ESSIV mode";
			kfree(cipher_api);
			return -EINVAL;
		}
		ret = snprintf(cipher_api, CRYPTO_MAX_ALG_NAME,
			       "essiv(%s(%s),%s)", chainmode, cipher, *ivopts);
	} else {
		ret = snprintf(cipher_api, CRYPTO_MAX_ALG_NAME,
			       "%s(%s)", chainmode, cipher);
	}
	if (ret < 0 || ret >= CRYPTO_MAX_ALG_NAME) {
		kfree(cipher_api);
		goto bad_mem;
	}

	/* Allocate cipher */
	ret = crypt_alloc_tfms(cc, cipher_api);
	if (ret < 0) {
		ti->error = "Error allocating crypto tfm";
		kfree(cipher_api);
		return ret;
	}
	kfree(cipher_api);

	return 0;
bad_mem:
	ti->error = "Cannot allocate cipher strings";
	return -ENOMEM;
}

static int crypt_ctr_cipher(struct dm_target *ti, char *cipher_in, char *key)
{
	struct crypt_config *cc = ti->private;
	char *ivmode = NULL, *ivopts = NULL;
	int ret;

	/*
	 * cipher 构造的总入口：
	 *   1. 保存原始 cipher 字符串；
	 *   2. 按新/老格式解析并分配 crypto tfm；
	 *   3. 选择 IV 生成器；
	 *   4. 安装 key；
	 *   5. 初始化 IV 私有状态。
	 */
	cc->cipher_string = kstrdup(cipher_in, GFP_KERNEL);
	if (!cc->cipher_string) {
		ti->error = "Cannot allocate cipher strings";
		return -ENOMEM;
	}

	if (strstarts(cipher_in, "capi:"))
		ret = crypt_ctr_cipher_new(ti, cipher_in, key, &ivmode, &ivopts);
	else
		ret = crypt_ctr_cipher_old(ti, cipher_in, key, &ivmode, &ivopts);
	if (ret)
		return ret;

	/* Initialize IV */
	ret = crypt_ctr_ivmode(ti, ivmode);
	if (ret < 0)
		return ret;

	/* Initialize and set key */
	ret = crypt_set_key(cc, key);
	if (ret < 0) {
		ti->error = "Error decoding and setting key";
		return ret;
	}

	/* Allocate IV */
	if (cc->iv_gen_ops && cc->iv_gen_ops->ctr) {
		ret = cc->iv_gen_ops->ctr(cc, ti, ivopts);
		if (ret < 0) {
			ti->error = "Error creating IV";
			return ret;
		}
	}

	/* Initialize IV (set keys for ESSIV etc) */
	if (cc->iv_gen_ops && cc->iv_gen_ops->init) {
		ret = cc->iv_gen_ops->init(cc);
		if (ret < 0) {
			ti->error = "Error initialising IV";
			return ret;
		}
	}

	/* wipe the kernel key payload copy */
	if (cc->key_string)
		memset(cc->key, 0, cc->key_size * sizeof(u8));

	return ret;
}

static int crypt_ctr_optional(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct crypt_config *cc = ti->private;
	struct dm_arg_set as;
	static const struct dm_arg _args[] = {
		{0, 6, "Invalid number of feature args"},
	};
	unsigned int opt_params, val;
	const char *opt_string, *sval;
	char dummy;
	int ret;

	/* Optional parameters */
	/*
	 * 映射表前 5 个参数是固定项，后面是可选特性。格式是：
	 *   <num_feature_args> <feature1> <feature2> ...
	 * 这里支持 discard、CPU 亲和、integrity、sector_size、iv_large_sectors 等。
	 */
	as.argc = argc;
	as.argv = argv;

	ret = dm_read_arg_group(_args, &as, &opt_params, &ti->error);
	if (ret)
		return ret;

	while (opt_params--) {
		opt_string = dm_shift_arg(&as);
		if (!opt_string) {
			ti->error = "Not enough feature arguments";
			return -EINVAL;
		}

		if (!strcasecmp(opt_string, "allow_discards"))
			ti->num_discard_bios = 1;

		else if (!strcasecmp(opt_string, "same_cpu_crypt"))
			set_bit(DM_CRYPT_SAME_CPU, &cc->flags);

		else if (!strcasecmp(opt_string, "submit_from_crypt_cpus"))
			set_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags);
		else if (sscanf(opt_string, "integrity:%u:", &val) == 1) {
			if (val == 0 || val > MAX_TAG_SIZE) {
				ti->error = "Invalid integrity arguments";
				return -EINVAL;
			}
			cc->on_disk_tag_size = val;
			sval = strchr(opt_string + strlen("integrity:"), ':') + 1;
			if (!strcasecmp(sval, "aead")) {
				set_bit(CRYPT_MODE_INTEGRITY_AEAD, &cc->cipher_flags);
			} else  if (strcasecmp(sval, "none")) {
				ti->error = "Unknown integrity profile";
				return -EINVAL;
			}

			cc->cipher_auth = kstrdup(sval, GFP_KERNEL);
			if (!cc->cipher_auth)
				return -ENOMEM;
		} else if (sscanf(opt_string, "sector_size:%hu%c", &cc->sector_size, &dummy) == 1) {
			if (cc->sector_size < (1 << SECTOR_SHIFT) ||
			    cc->sector_size > 4096 ||
			    (cc->sector_size & (cc->sector_size - 1))) {
				ti->error = "Invalid feature value for sector_size";
				return -EINVAL;
			}
			if (ti->len & ((cc->sector_size >> SECTOR_SHIFT) - 1)) {
				ti->error = "Device size is not multiple of sector_size feature";
				return -EINVAL;
			}
			cc->sector_shift = __ffs(cc->sector_size) - SECTOR_SHIFT;
		} else if (!strcasecmp(opt_string, "iv_large_sectors"))
			set_bit(CRYPT_IV_LARGE_SECTORS, &cc->cipher_flags);
		else {
			ti->error = "Invalid feature arguments";
			return -EINVAL;
		}
	}

	return 0;
}

/*
 * Construct an encryption mapping:
 * <cipher> [<key>|:<key_size>:<user|logon>:<key_description>] <iv_offset> <dev_path> <start>
 *
 * crypt_ctr() 是创建 target 的入口，相当于构造函数。Device Mapper 把映射表切成
 * argv[] 传进来，本函数负责把这些字符串变成运行时对象。
 *
 * 参数示例：
 *   aes-cbc-essiv:sha256 <hex-key> 0 /dev/sdb1 0
 *   capi:xts(aes)-plain64 <hex-key> 0 /dev/sdb1 0 1 allow_discards
 */
static int crypt_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct crypt_config *cc;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
	const char *devname = dm_table_device_name(ti->table);
#else
	const char *devname = "";
#endif
	int key_size;
	unsigned int align_mask;
	unsigned long long tmpll;
	int ret;
	size_t iv_size_padding, additional_req_size;
	char dummy;

	if (argc < 5) {
		ti->error = "Not enough arguments";
		return -EINVAL;
	}

	/* 先从 key 字符串推导 key_size，这决定 crypt_config 尾部 key[] 的分配大小。 */
	key_size = get_key_size(&argv[1]);
	if (key_size < 0) {
		ti->error = "Cannot parse key size";
		return -EINVAL;
	}

	cc = kzalloc(struct_size(cc, key, key_size), GFP_KERNEL);
	if (!cc) {
		ti->error = "Cannot allocate encryption context";
		return -ENOMEM;
	}
	cc->key_size = key_size;
	cc->sector_size = (1 << SECTOR_SHIFT);
	cc->sector_shift = 0;

	/* ti->private 是 Device Mapper target 保存私有配置的标准位置。 */
	ti->private = cc;

	spin_lock(&dm_crypt_clients_lock);
	dm_crypt_clients_n++;
	crypt_calculate_pages_per_client();
	spin_unlock(&dm_crypt_clients_lock);

	ret = percpu_counter_init(&cc->n_allocated_pages, 0, GFP_KERNEL);
	if (ret < 0)
		goto bad;

	/* Optional parameters need to be read before cipher constructor */
	if (argc > 5) {
		ret = crypt_ctr_optional(ti, argc - 5, &argv[5]);
		if (ret)
			goto bad;
	}

	ret = crypt_ctr_cipher(ti, argv[0], argv[1]);
	if (ret < 0)
		goto bad;

	/*
	 * 计算每个 crypto request 的内存布局。per-bio 预留区里先放 dm_crypt_io，
	 * 后面紧跟一个默认 crypto request；如果异步并发超出这份内存，再从 req_pool
	 * 额外分配 request。
	 */
	if (crypt_integrity_aead(cc)) {
		cc->dmreq_start = sizeof(struct aead_request);
		cc->dmreq_start += crypto_aead_reqsize(any_tfm_aead(cc));
		align_mask = crypto_aead_alignmask(any_tfm_aead(cc));
	} else {
		cc->dmreq_start = sizeof(struct skcipher_request);
		cc->dmreq_start += crypto_skcipher_reqsize(any_tfm(cc));
		align_mask = crypto_skcipher_alignmask(any_tfm(cc));
	}
	cc->dmreq_start = ALIGN(cc->dmreq_start, __alignof__(struct dm_crypt_request));

	if (align_mask < CRYPTO_MINALIGN) {
		/* Allocate the padding exactly */
		iv_size_padding = -(cc->dmreq_start + sizeof(struct dm_crypt_request))
				& align_mask;
	} else {
		/*
		 * If the cipher requires greater alignment than kmalloc
		 * alignment, we don't know the exact position of the
		 * initialization vector. We must assume worst case.
		 */
		iv_size_padding = align_mask;
	}

	/*  ...| IV + padding | original IV | original sec. number | bio tag offset | */
	additional_req_size = sizeof(struct dm_crypt_request) +
		iv_size_padding + cc->iv_size +
		cc->iv_size +
		sizeof(uint64_t) +
		sizeof(unsigned int);

	ret = mempool_init_kmalloc_pool(&cc->req_pool, MIN_IOS, cc->dmreq_start + additional_req_size);
	if (ret) {
		ti->error = "Cannot allocate crypt request mempool";
		goto bad;
	}

	cc->per_bio_data_size = ti->per_io_data_size =
		ALIGN(sizeof(struct dm_crypt_io) + cc->dmreq_start + additional_req_size,
		      ARCH_KMALLOC_MINALIGN);

	ret = mempool_init(&cc->page_pool, BIO_MAX_PAGES, crypt_page_alloc, crypt_page_free, cc);
	if (ret) {
		ti->error = "Cannot allocate page mempool";
		goto bad;
	}

	ret = bioset_init(&cc->bs, MIN_IOS, 0, BIOSET_NEED_BVECS);
	if (ret) {
		ti->error = "Cannot allocate crypt bioset";
		goto bad;
	}

	mutex_init(&cc->bio_alloc_lock);

	ret = -EINVAL;
	/* argv[2] 是 IV sector 偏移，必须按加密 sector 对齐。 */
	if ((sscanf(argv[2], "%llu%c", &tmpll, &dummy) != 1) ||
	    (tmpll & ((cc->sector_size >> SECTOR_SHIFT) - 1))) {
		ti->error = "Invalid iv_offset sector";
		goto bad;
	}
	cc->iv_offset = tmpll;

	ret = dm_get_device(ti, argv[3], dm_table_get_mode(ti->table), &cc->dev);
	if (ret) {
		ti->error = "Device lookup failed";
		goto bad;
	}

	ret = -EINVAL;
	/* argv[4] 是底层设备的起始 sector。 */
	if (sscanf(argv[4], "%llu%c", &tmpll, &dummy) != 1 || tmpll != (sector_t)tmpll) {
		ti->error = "Invalid device sector";
		goto bad;
	}
	cc->start = tmpll;

	if (crypt_integrity_aead(cc) || cc->integrity_iv_size) {
		/* integrity 模式需要验证底层设备 profile，并为 tag 分配 mempool。 */
		ret = crypt_integrity_ctr(cc, ti);
		if (ret)
			goto bad;

		cc->tag_pool_max_sectors = POOL_ENTRY_SIZE / cc->on_disk_tag_size;
		if (!cc->tag_pool_max_sectors)
			cc->tag_pool_max_sectors = 1;

		ret = mempool_init_kmalloc_pool(&cc->tag_pool, MIN_IOS,
			cc->tag_pool_max_sectors * cc->on_disk_tag_size);
		if (ret) {
			ti->error = "Cannot allocate integrity tags mempool";
			goto bad;
		}

		cc->tag_pool_max_sectors <<= cc->sector_shift;
	}

	ret = -ENOMEM;
	/* io_queue 串行度为 1，负责底层 IO 提交；crypt_queue 可按 CPU 并行跑加/解密。 */
	cc->io_queue = alloc_workqueue("kcryptd_io/%s", WQ_MEM_RECLAIM, 1, devname);
	if (!cc->io_queue) {
		ti->error = "Couldn't create kcryptd io queue";
		goto bad;
	}

	if (test_bit(DM_CRYPT_SAME_CPU, &cc->flags))
		cc->crypt_queue = alloc_workqueue("kcryptd/%s", WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM,
						  1, devname);
	else
		cc->crypt_queue = alloc_workqueue("kcryptd/%s",
						  WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM | WQ_UNBOUND,
						  num_online_cpus(), devname);
	if (!cc->crypt_queue) {
		ti->error = "Couldn't create kcryptd queue";
		goto bad;
	}

	spin_lock_init(&cc->write_thread_lock);
	cc->write_tree = RB_ROOT;

	/* 写线程只负责按 sector 顺序提交已经加密好的写 clone bio。 */
	cc->write_thread = kthread_create(dmcrypt_write, cc, "dmcrypt_write/%s", devname);
	if (IS_ERR(cc->write_thread)) {
		ret = PTR_ERR(cc->write_thread);
		cc->write_thread = NULL;
		ti->error = "Couldn't spawn write thread";
		goto bad;
	}
	wake_up_process(cc->write_thread);

	ti->num_flush_bios = 1;
#ifdef DM_CRYPT_HAVE_LIMIT_SWAP_BIOS
	/* 只有目标内核的 struct dm_target 存在该字段时才设置，兼容部分 5.4 发行版。 */
	ti->limit_swap_bios = true;
#endif
#ifdef DM_CRYPT_HAVE_ACCOUNTS_REMAPPED_IO
	/* 新内核用于统计 remap 后的 IO，老内核没有该字段。 */
	ti->accounts_remapped_io = true;
#endif

	return 0;

bad:
	crypt_dtr(ti);
	return ret;
}

static int crypt_map(struct dm_target *ti, struct bio *bio)
{
	struct dm_crypt_io *io;
	struct crypt_config *cc = ti->private;

	/*
	 * crypt_map() 是 IO 快路径入口。这里不应该做长时间阻塞的事情，只负责：
	 *   - 对无需加密的数据管理请求直接 remap；
	 *   - 校验 bio 对齐和大小；
	 *   - 初始化 dm_crypt_io；
	 *   - 把真正的读写加/解密工作扔到对应队列。
	 */
	/*
	 * If bio is REQ_PREFLUSH or REQ_OP_DISCARD, just bypass crypt queues.
	 * - for REQ_PREFLUSH device-mapper core ensures that no IO is in-flight
	 * - for REQ_OP_DISCARD caller must use flush if IO ordering matters
	 */
	if (unlikely(bio->bi_opf & REQ_PREFLUSH ||
	    bio_op(bio) == REQ_OP_DISCARD)) {
		bio_set_dev(bio, cc->dev->bdev);
		if (bio_sectors(bio))
			bio->bi_iter.bi_sector = cc->start +
				dm_target_offset(ti, bio->bi_iter.bi_sector);
		return DM_MAPIO_REMAPPED;
	}

	/*
	 * Check if bio is too large, split as needed.
	 */
	if (unlikely(bio->bi_iter.bi_size > (BIO_MAX_PAGES << PAGE_SHIFT)) &&
	    (bio_data_dir(bio) == WRITE || cc->on_disk_tag_size))
		dm_accept_partial_bio(bio, ((BIO_MAX_PAGES << PAGE_SHIFT) >> SECTOR_SHIFT));

	/*
	 * Ensure that bio is a multiple of internal sector encryption size
	 * and is aligned to this size as defined in IO hints.
	 */
	if (unlikely((bio->bi_iter.bi_sector & ((cc->sector_size >> SECTOR_SHIFT) - 1)) != 0))
		return DM_MAPIO_KILL;

	if (unlikely(bio->bi_iter.bi_size & (cc->sector_size - 1)))
		return DM_MAPIO_KILL;

	io = dm_per_bio_data(bio, cc->per_bio_data_size);
	crypt_io_init(io, cc, bio, dm_target_offset(ti, bio->bi_iter.bi_sector));

	if (cc->on_disk_tag_size) {
		/* integrity 模式为每个加密 sector 准备 tag 缓冲，太大时拆分 bio。 */
		unsigned tag_len = cc->on_disk_tag_size * (bio_sectors(bio) >> cc->sector_shift);

		if (unlikely(tag_len > KMALLOC_MAX_SIZE) ||
		    unlikely(!(io->integrity_metadata = kmalloc(tag_len,
				GFP_NOIO | __GFP_NORETRY | __GFP_NOMEMALLOC | __GFP_NOWARN)))) {
			if (bio_sectors(bio) > cc->tag_pool_max_sectors)
				dm_accept_partial_bio(bio, cc->tag_pool_max_sectors);
			io->integrity_metadata = mempool_alloc(&cc->tag_pool, GFP_NOIO);
			io->integrity_metadata_from_pool = true;
		}
	}

	if (crypt_integrity_aead(cc))
		io->ctx.r.req_aead = (struct aead_request *)(io + 1);
	else
		io->ctx.r.req = (struct skcipher_request *)(io + 1);

	/*
	 * 读写路径方向不同：
	 *   读：先提交底层读拿到密文，再解密；
	 *   写：先加密到 clone bio，再提交底层写。
	 */
	if (bio_data_dir(io->base_bio) == READ) {
		if (kcryptd_io_read(io, GFP_NOWAIT))
			kcryptd_queue_read(io);
	} else
		kcryptd_queue_crypt(io);

	return DM_MAPIO_SUBMITTED;
}

static void crypt_status(struct dm_target *ti, status_type_t type,
			 unsigned status_flags, char *result, unsigned maxlen)
{
	struct crypt_config *cc = ti->private;
	unsigned i, sz = 0;
	int num_feature_args = 0;

	/*
	 * dmsetup table/status 会走到这里。TABLE 要尽量重建创建时的参数，INFO 在这版
	 * dm-crypt 里没有额外运行时统计。
	 */
	switch (type) {
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;

	case STATUSTYPE_TABLE:
		DMEMIT("%s ", cc->cipher_string);

		if (cc->key_size > 0) {
			if (cc->key_string)
				DMEMIT(":%u:%s", cc->key_size, cc->key_string);
			else
				for (i = 0; i < cc->key_size; i++)
					DMEMIT("%02x", cc->key[i]);
		} else
			DMEMIT("-");

		DMEMIT(" %llu %s %llu", (unsigned long long)cc->iv_offset,
				cc->dev->name, (unsigned long long)cc->start);

		num_feature_args += !!ti->num_discard_bios;
		num_feature_args += test_bit(DM_CRYPT_SAME_CPU, &cc->flags);
		num_feature_args += test_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags);
		num_feature_args += cc->sector_size != (1 << SECTOR_SHIFT);
		num_feature_args += test_bit(CRYPT_IV_LARGE_SECTORS, &cc->cipher_flags);
		if (cc->on_disk_tag_size)
			num_feature_args++;
		if (num_feature_args) {
			DMEMIT(" %d", num_feature_args);
			if (ti->num_discard_bios)
				DMEMIT(" allow_discards");
			if (test_bit(DM_CRYPT_SAME_CPU, &cc->flags))
				DMEMIT(" same_cpu_crypt");
			if (test_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags))
				DMEMIT(" submit_from_crypt_cpus");
			if (cc->on_disk_tag_size)
				DMEMIT(" integrity:%u:%s", cc->on_disk_tag_size, cc->cipher_auth);
			if (cc->sector_size != (1 << SECTOR_SHIFT))
				DMEMIT(" sector_size:%d", cc->sector_size);
			if (test_bit(CRYPT_IV_LARGE_SECTORS, &cc->cipher_flags))
				DMEMIT(" iv_large_sectors");
		}

		break;
	default:
		result[0] = '\0';
		break;
	}
}

static void crypt_postsuspend(struct dm_target *ti)
{
	struct crypt_config *cc = ti->private;

	/* suspend 后允许通过 message 接口 set/wipe key。 */
	set_bit(DM_CRYPT_SUSPENDED, &cc->flags);
}

static int crypt_preresume(struct dm_target *ti)
{
	struct crypt_config *cc = ti->private;

	/* resume 前必须确保 key 有效，否则不能重新放行 IO。 */
	if (!test_bit(DM_CRYPT_KEY_VALID, &cc->flags)) {
		DMERR("aborting resume - crypt key is not set.");
		return -EAGAIN;
	}

	return 0;
}

static void crypt_resume(struct dm_target *ti)
{
	struct crypt_config *cc = ti->private;

	/* resume 后恢复正常 IO。 */
	clear_bit(DM_CRYPT_SUSPENDED, &cc->flags);
}

/* Message interface
 *	key set <key>
 *	key wipe
 *
 * dmsetup message 可以在映射已 suspend 时更换或擦除 key。要求 suspend 是为了避免
 * 有 IO 正在使用旧 key。
 */
static int crypt_message(struct dm_target *ti, unsigned argc, char **argv,
			 char *result, unsigned maxlen)
{
	struct crypt_config *cc = ti->private;
	int key_size, ret = -EINVAL;

	if (argc < 2)
		goto error;

	if (!strcasecmp(argv[0], "key")) {
		if (!test_bit(DM_CRYPT_SUSPENDED, &cc->flags)) {
			DMWARN("not suspended during key manipulation.");
			return -EINVAL;
		}
		if (argc == 3 && !strcasecmp(argv[1], "set")) {
			/* The key size may not be changed. */
			key_size = get_key_size(&argv[2]);
			if (key_size < 0 || cc->key_size != key_size) {
				memset(argv[2], '0', strlen(argv[2]));
				return -EINVAL;
			}

			ret = crypt_set_key(cc, argv[2]);
			if (ret)
				return ret;
			if (cc->iv_gen_ops && cc->iv_gen_ops->init)
				ret = cc->iv_gen_ops->init(cc);
			/* wipe the kernel key payload copy */
			if (cc->key_string)
				memset(cc->key, 0, cc->key_size * sizeof(u8));
			return ret;
		}
		if (argc == 2 && !strcasecmp(argv[1], "wipe"))
			return crypt_wipe_key(cc);
	}

error:
	DMWARN("unrecognised message received.");
	return -EINVAL;
}

static int crypt_iterate_devices(struct dm_target *ti,
				 iterate_devices_callout_fn fn, void *data)
{
	struct crypt_config *cc = ti->private;

	/* 告诉 dm core：本 target 覆盖底层设备 cc->dev 上从 cc->start 开始的 ti->len。 */
	return fn(ti, cc->dev, cc->start, ti->len, data);
}

static void crypt_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct crypt_config *cc = ti->private;

	/*
	 * Unfortunate constraint that is required to avoid the potential
	 * for exceeding underlying device's max_segments limits -- due to
	 * crypt_alloc_buffer() possibly allocating pages for the encryption
	 * bio that are not as physically contiguous as the original bio.
	 *
	 * 简单说：写路径 clone bio 的 page 是重新分配的，物理连续性可能比原始 bio 差。
	 * 把 max_segment_size 限制到 PAGE_SIZE，可以避免超过底层设备的 segment 限制。
	 */
	limits->max_segment_size = PAGE_SIZE;

	limits->logical_block_size =
		max_t(unsigned, limits->logical_block_size, cc->sector_size);
	limits->physical_block_size =
		max_t(unsigned, limits->physical_block_size, cc->sector_size);
	limits->io_min = max_t(unsigned, limits->io_min, cc->sector_size);
}

static struct target_type crypt_target = {
	/*
	 * Device Mapper target 注册表。dm_register_target() 后，用户态映射表里写
	 * "crypt" 就会绑定到这一组回调。
	 */
	.name   = "crypt",
	.version = {1, 19, 0},
	.module = THIS_MODULE,
	.ctr    = crypt_ctr,
	.dtr    = crypt_dtr,
	.map    = crypt_map,
	.status = crypt_status,
	.postsuspend = crypt_postsuspend,
	.preresume = crypt_preresume,
	.resume = crypt_resume,
	.message = crypt_message,
	.iterate_devices = crypt_iterate_devices,
	.io_hints = crypt_io_hints,
};

static int __init dm_crypt_init(void)
{
	int r;

	/* 模块加载入口：把 crypt_target 注册到 Device Mapper core。 */
	r = dm_register_target(&crypt_target);
	if (r < 0)
		DMERR("register failed %d", r);

	return r;
}

static void __exit dm_crypt_exit(void)
{
	/* 模块卸载入口：注销 target。仍有映射存在时内核模块引用计数会阻止卸载。 */
	dm_unregister_target(&crypt_target);
}

module_init(dm_crypt_init);
module_exit(dm_crypt_exit);

MODULE_AUTHOR("Jana Saout <jana@saout.de>");
MODULE_DESCRIPTION(DM_NAME " target for transparent encryption / decryption");
MODULE_LICENSE("GPL");
