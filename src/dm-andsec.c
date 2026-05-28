// SPDX-License-Identifier: GPL-2.0
/*
 * 这个文件实现的是 Device Mapper 里的 "andsec" target。Device Mapper 可以把一个
 * “逻辑块设备”映射到一个或多个真实块设备上；当前 dm-andsec 保留原 dm IO 管线，
 * 但不再使用 Crypto API、key、IV 或完整性 tag。
 *
 * 主要流程：
 *   1. dm_andsec_init()：模块加载时注册名为 "andsec" 的 target。
 *   2. andsec_ctr()：创建一条映射时调用，解析 device/start/options，
 *      分配 mempool、bioset、workqueue、写线程等长期资源。
 *   3. andsec_map()：每个 bio 进来时调用。读路径先提交底层读，再进入转换队列；
 *      写路径先复制到 clone bio，再由写线程提交到底层设备。
 *   4. andsec_dtr()：映射销毁时释放 andsec_ctr() 里申请的资源。
 *
 * 当前“加/解密”阶段只做数据复制透传，后续可在 andsec_convert() 中补充自己的逻辑。
 */

#include <linux/atomic.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/device-mapper.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <asm/page.h>

#define DM_MSG_PREFIX "andsec"

#ifndef BIO_MAX_PAGES
/* 老内核没有 BIO_MAX_PAGES，用 BIO_MAX_VECS 表示一个 bio 最多能挂多少段。 */
#define BIO_MAX_PAGES BIO_MAX_VECS
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
/* totalram_pages 在 5.0 前是变量，5.0 后变成函数。 */
#define andsec_totalram_pages() totalram_pages
#define andsec_totalhigh_pages() totalhigh_pages
#else
#define andsec_totalram_pages() totalram_pages()
#define andsec_totalhigh_pages() totalhigh_pages()
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#define andsec_kmap(page) kmap_local_page(page)
#define andsec_kunmap(addr) kunmap_local(addr)
#else
#define andsec_kmap(page) kmap_atomic(page)
#define andsec_kunmap(addr) kunmap_atomic(addr)
#endif

#define MIN_IOS 64
#define DM_ANDSEC_MEMORY_PERCENT 2
#define DM_ANDSEC_MIN_PAGES_PER_CLIENT (BIO_MAX_PAGES * 16)

struct andsec_config;

/*
 * 一次 bio 转换的游标。
 *
 * andsec_convert() 不是把整个 bio 一口气处理完，而是按 bvec 当前可处理长度推进。
 * 当前实现只做 memcpy；后续如果要增加自己的处理逻辑，可以继续复用这里的输入、
 * 输出 bio 和 sector 游标。
 */
struct convert_context {
	/* 输入 bio：写路径通常是原始 bio，读路径通常是刚读回来的原始 bio。 */
	struct bio *bio_in;
	/* 输出 bio：写路径是 clone bio，读路径一般还是原始 bio。 */
	struct bio *bio_out;
	/* 输入/输出 bio 当前处理到的 bvec 位置。 */
	struct bvec_iter iter_in;
	struct bvec_iter iter_out;
	/* 当前正在处理的 512B sector 号，预留给后续自定义逻辑使用。 */
	sector_t sector;
};

/*
 * 保留一份轻量 request mempool。当前 request 只作为转换阶段的预留对象，
 * 不承载 Crypto API 状态；后续接入自己的实现时可以扩展这个结构。
 */
struct andsec_copy_request {
	struct convert_context *ctx;
};

/*
 * 每个原始 bio 对应的一份私有数据。
 *
 * dm core 会按 ti->per_io_data_size 给每个 bio 预留一段内存，andsec_map() 通过
 * dm_per_bio_data() 拿到这里。它连接了“用户原始 bio”、“底层 clone bio”、
 * “转换 work”和“完成计数”，是整个 IO 生命周期的锚点。
 */
struct dm_andsec_io {
	/* 该映射的全局配置，andsec_ctr() 创建。 */
	struct andsec_config *cc;
	/* 上层传进来的原始 bio，最终要调用 bio_endio() 完成它。 */
	struct bio *base_bio;
	/* 挂到 workqueue 上执行读提交或数据转换任务。 */
	struct work_struct work;
	/* 当前 bio 的转换游标。 */
	struct convert_context ctx;
	/* 整个 bio 生命周期内还没完成的子任务数。归零后完成 base_bio。 */
	atomic_t io_pending;
	/* 子任务发现的第一个块层错误，最终写回 base_bio->bi_status。 */
	blk_status_t error;
	/* 该 bio 映射到 dm target 内的起始 sector。 */
	sector_t sector;
	/* 写路径为了按 sector 排序提交到底层设备，会挂到红黑树里。 */
	struct rb_node rb_node;
};

enum andsec_flags {
	DM_ANDSEC_SAME_CPU,   /* 转换尽量限制在同 CPU/较保守的 workqueue。 */
	DM_ANDSEC_NO_OFFLOAD, /* 写 IO 尽量从转换上下文直接提交，不交给写线程。 */
};

/*
 * 一条 dm-andsec 映射的全局配置。
 *
 * andsec_ctr() 创建并填充它，后续每个 bio 都通过 ti->private 找到这份配置。当前
 * 保留原框架里的 mempool、bioset、workqueue 和写线程，但移除了 crypto/key/IV。
 */
struct andsec_config {
	/* 底层真实块设备，以及本 target 在底层设备上的起始 sector。 */
	struct dm_dev *dev;
	sector_t start;

	/* 当前实例已从 page_pool 分配的页数，用于限制所有 dm-andsec 实例的总内存。 */
	struct percpu_counter n_allocated_pages;

	/* io_queue 负责提交底层读 IO；crypt_queue 负责数据转换。 */
	struct workqueue_struct *io_queue;
	struct workqueue_struct *crypt_queue;

	/* 写请求按 sector 排序后由专门 kthread 提交，保留原写线程框架。 */
	spinlock_t write_thread_lock;
	struct task_struct *write_thread;
	struct rb_root write_tree;

	/* 内部转换 sector 大小，默认 512B，可通过 sector_size:<n> 指定。 */
	unsigned short int sector_size;
	unsigned char sector_shift;

	/* 每个原始 bio 需要预留的私有数据大小，交给 dm core 使用。 */
	unsigned int per_bio_data_size;

	/* 运行期选项位。 */
	unsigned long flags;

	/* 预留转换 request、写路径输出 page，以及 clone bio 的对象池。 */
	mempool_t req_pool;
	mempool_t page_pool;
	struct bio_set bs;
	struct mutex bio_alloc_lock;

	bool client_counted;
	bool counter_initialized;
	bool req_pool_initialized;
	bool page_pool_initialized;
	bool bs_initialized;
	bool bio_alloc_lock_initialized;
};

/*
 * bio API 兼容封装。
 *
 * 5.18 开始 bio_alloc_bioset()/bio_alloc_clone() 需要显式传入 bdev/opf；
 * 6.12 开始 dm 提供 dm_submit_bio_remap() 来提交重映射 bio。业务代码统一调用
 * andsec_alloc_bio()/andsec_clone_bio()/andsec_submit_bio()。
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
#define andsec_alloc_bio(io, nr_iovecs, gfp) \
	bio_alloc_bioset((io)->cc->dev->bdev, (nr_iovecs), \
			 (io)->base_bio->bi_opf, (gfp), &(io)->cc->bs)
#define andsec_clone_bio(io, gfp) \
	bio_alloc_clone((io)->cc->dev->bdev, (io)->base_bio, (gfp), \
			&(io)->cc->bs)
#else
#define andsec_alloc_bio(io, nr_iovecs, gfp) \
	bio_alloc_bioset((gfp), (nr_iovecs), &(io)->cc->bs)
#define andsec_clone_bio(io, gfp) \
	bio_clone_fast((io)->base_bio, (gfp), &(io)->cc->bs)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#define andsec_submit_bio(io, clone) \
	dm_submit_bio_remap((io)->base_bio, (clone))
#else
#define andsec_submit_bio(io, clone) submit_bio((clone))
#endif

static DEFINE_SPINLOCK(dm_andsec_clients_lock);
static unsigned int dm_andsec_clients_n;
static volatile unsigned long dm_andsec_pages_per_client;

static void andsec_dtr(struct dm_target *ti);
static void clone_init(struct dm_andsec_io *io, struct bio *clone);
static void kcryptd_queue_crypt(struct dm_andsec_io *io);

static void andsec_calculate_pages_per_client(void)
{
	unsigned long pages = (andsec_totalram_pages() - andsec_totalhigh_pages()) *
			      DM_ANDSEC_MEMORY_PERCENT / 100;

	if (!dm_andsec_clients_n)
		return;

	pages /= dm_andsec_clients_n;
	if (pages < DM_ANDSEC_MIN_PAGES_PER_CLIENT)
		pages = DM_ANDSEC_MIN_PAGES_PER_CLIENT;
	dm_andsec_pages_per_client = pages;
}

/*
 * 函数：andsec_page_alloc
 * 作用：page_pool 的页分配回调，带全局每实例页数限制。
 */
static void *andsec_page_alloc(gfp_t gfp_mask, void *pool_data)
{
	struct andsec_config *cc = pool_data;
	struct page *page;

	if (unlikely(percpu_counter_read_positive(&cc->n_allocated_pages) >=
		     dm_andsec_pages_per_client) &&
	    likely(gfp_mask & __GFP_NORETRY))
		return NULL;

	page = alloc_page(gfp_mask);
	if (likely(page))
		percpu_counter_add(&cc->n_allocated_pages, 1);

	return page;
}

/*
 * 函数：andsec_page_free
 * 作用：page_pool 的页释放回调，释放 page 并减少本实例页计数。
 */
static void andsec_page_free(void *page, void *pool_data)
{
	struct andsec_config *cc = pool_data;

	__free_page(page);
	percpu_counter_sub(&cc->n_allocated_pages, 1);
}

/*
 * 函数：andsec_parse_args
 * 作用：解析 dm-andsec 映射参数。
 *
 * 新格式：
 *   <dev_path> <start> [options...]
 *
 * 兼容旧固定参数格式，便于从原项目迁移：
 *   <cipher> <key> <iv_offset> <dev_path> <start> [num_options options...]
 *
 * 兼容格式里的 cipher/key/iv_offset 只用于定位 dev/start，不参与任何处理。
 */
static int andsec_parse_args(struct dm_target *ti, unsigned int argc, char **argv,
			     const char **dev_path, const char **start_arg,
			     unsigned int *opt_index)
{
	if (argc >= 5) {
		*dev_path = argv[3];
		*start_arg = argv[4];
		*opt_index = 5;
		return 0;
	}

	if (argc >= 2) {
		*dev_path = argv[0];
		*start_arg = argv[1];
		*opt_index = 2;
		return 0;
	}

	ti->error = "Invalid argument count";
	return -EINVAL;
}

/*
 * 函数：andsec_ctr_optional
 * 作用：解析可选 feature 参数。
 *
 * 支持旧表里的 <num_feature_args> <feature...>，也支持新格式直接追加 feature。
 * 与加密强相关的参数在当前透传实现中会被接受但忽略，避免旧表迁移时失败。
 */
static int andsec_ctr_optional(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct andsec_config *cc = ti->private;
	unsigned int i = 0, opt_params = argc;
	unsigned int declared;
	char dummy;

	if (!argc)
		return 0;

	if (sscanf(argv[0], "%u%c", &declared, &dummy) == 1 &&
	    declared <= argc - 1) {
		i = 1;
		opt_params = declared;
	}

	while (opt_params--) {
		const char *opt_string = argv[i++];

		if (!strcasecmp(opt_string, "allow_discards")) {
			ti->num_discard_bios = 1;
		} else if (!strcasecmp(opt_string, "same_cpu_crypt")) {
			set_bit(DM_ANDSEC_SAME_CPU, &cc->flags);
		} else if (!strcasecmp(opt_string, "submit_from_crypt_cpus")) {
			set_bit(DM_ANDSEC_NO_OFFLOAD, &cc->flags);
		} else if (sscanf(opt_string, "sector_size:%hu%c",
				  &cc->sector_size, &dummy) == 1) {
			if (cc->sector_size < (1 << SECTOR_SHIFT) ||
			    cc->sector_size > PAGE_SIZE ||
			    (cc->sector_size & (cc->sector_size - 1))) {
				ti->error = "Invalid feature value for sector_size";
				return -EINVAL;
			}
			if (ti->len & ((cc->sector_size >> SECTOR_SHIFT) - 1)) {
				ti->error = "Device size is not multiple of sector_size feature";
				return -EINVAL;
			}
			cc->sector_shift = __ffs(cc->sector_size) - SECTOR_SHIFT;
		} else if (!strncasecmp(opt_string, "integrity:", strlen("integrity:")) ||
			   !strcasecmp(opt_string, "iv_large_sectors")) {
			/* 当前已移除 integrity/IV 处理；旧表参数只做兼容接收。 */
			continue;
		} else {
			ti->error = "Invalid feature arguments";
			return -EINVAL;
		}
	}

	return 0;
}

/*
 * 函数：andsec_convert_init
 * 作用：初始化一次 bio 数据转换的游标和起始 sector。
 */
static void andsec_convert_init(struct andsec_config *cc,
				struct convert_context *ctx,
				struct bio *bio_out, struct bio *bio_in,
				sector_t sector)
{
	ctx->bio_in = bio_in;
	ctx->bio_out = bio_out;
	if (bio_in)
		ctx->iter_in = bio_in->bi_iter;
	if (bio_out)
		ctx->iter_out = bio_out->bi_iter;
	ctx->sector = sector;
}

/*
 * 函数：andsec_copy_chunk
 * 作用：复制当前 bvec 片段。输入输出相同页和偏移时，读路径等价于 no-op。
 */
static void andsec_copy_chunk(struct bio_vec *bv_in, struct bio_vec *bv_out,
			      unsigned int len)
{
	void *src, *dst;

	if (bv_in->bv_page == bv_out->bv_page &&
	    bv_in->bv_offset == bv_out->bv_offset)
		return;

	src = andsec_kmap(bv_in->bv_page);
	dst = andsec_kmap(bv_out->bv_page);
	memcpy(dst + bv_out->bv_offset, src + bv_in->bv_offset, len);
	andsec_kunmap(dst);
	andsec_kunmap(src);
}

/*
 * 函数：andsec_convert
 * 作用：保留原加/解密 work 的位置，但当前只把输入 bio 数据复制到输出 bio。
 */
static blk_status_t andsec_convert(struct andsec_config *cc,
				   struct convert_context *ctx)
{
	while (ctx->iter_in.bi_size && ctx->iter_out.bi_size) {
		struct andsec_copy_request *req;
		struct bio_vec bv_in = bio_iter_iovec(ctx->bio_in, ctx->iter_in);
		struct bio_vec bv_out = bio_iter_iovec(ctx->bio_out, ctx->iter_out);
		unsigned int len = min_t(unsigned int, bv_in.bv_len, bv_out.bv_len);

		req = mempool_alloc(&cc->req_pool, GFP_NOIO);
		req->ctx = ctx;

		andsec_copy_chunk(&bv_in, &bv_out, len);
		mempool_free(req, &cc->req_pool);

		bio_advance_iter(ctx->bio_in, &ctx->iter_in, len);
		bio_advance_iter(ctx->bio_out, &ctx->iter_out, len);
		ctx->sector += len >> SECTOR_SHIFT;
		cond_resched();
	}

	if (ctx->iter_in.bi_size || ctx->iter_out.bi_size)
		return BLK_STS_IOERR;

	return 0;
}

static void andsec_free_buffer_pages(struct andsec_config *cc, struct bio *clone);

/*
 * 函数：andsec_alloc_buffer
 * 作用：为写路径分配一个新的 clone bio 作为透传输出缓冲。
 *
 * 写入时不直接覆盖上层传来的 page，所以这里保留原框架中的 page_pool 和 bioset。
 */
static struct bio *andsec_alloc_buffer(struct dm_andsec_io *io, unsigned int size)
{
	struct andsec_config *cc = io->cc;
	struct bio *clone;
	unsigned int nr_iovecs = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	gfp_t gfp_mask = GFP_NOWAIT | __GFP_HIGHMEM | __GFP_NORETRY;
	unsigned int i, len, remaining_size;
	struct page *page;

retry:
	if (unlikely(gfp_mask & __GFP_DIRECT_RECLAIM))
		mutex_lock(&cc->bio_alloc_lock);

	clone = andsec_alloc_bio(io, nr_iovecs, GFP_NOIO);
	if (!clone)
		goto out;

	clone_init(io, clone);
	remaining_size = size;

	for (i = 0; i < nr_iovecs; i++) {
		page = mempool_alloc(&cc->page_pool, gfp_mask);
		if (!page) {
			andsec_free_buffer_pages(cc, clone);
			bio_put(clone);
			gfp_mask |= __GFP_DIRECT_RECLAIM;
			goto retry;
		}

		len = min_t(unsigned int, remaining_size, PAGE_SIZE);
		__bio_add_page(clone, page, len, 0);
		remaining_size -= len;
	}

out:
	if (unlikely(gfp_mask & __GFP_DIRECT_RECLAIM))
		mutex_unlock(&cc->bio_alloc_lock);

	return clone;
}

/*
 * 函数：andsec_free_buffer_pages
 * 作用：释放写路径 clone bio 中由 dm-andsec 自己分配的所有 page。
 */
static void andsec_free_buffer_pages(struct andsec_config *cc, struct bio *clone)
{
	struct bio_vec *bv;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
	int iter_all;
#else
	struct bvec_iter_all iter_all;
#endif

	bio_for_each_segment_all(bv, clone, iter_all) {
		BUG_ON(!bv->bv_page);
		mempool_free(bv->bv_page, &cc->page_pool);
	}
}

/*
 * 函数：andsec_io_init
 * 作用：初始化一个原始 bio 对应的 dm_andsec_io 生命周期状态。
 */
static void andsec_io_init(struct dm_andsec_io *io, struct andsec_config *cc,
			   struct bio *bio, sector_t sector)
{
	io->cc = cc;
	io->base_bio = bio;
	io->sector = sector;
	io->error = 0;
	atomic_set(&io->io_pending, 0);
}

static void andsec_inc_pending(struct dm_andsec_io *io)
{
	atomic_inc(&io->io_pending);
}

/*
 * 函数：andsec_dec_pending
 * 作用：减少原始 bio 的未完成子任务计数；最后一个子任务负责完成 bio。
 */
static void andsec_dec_pending(struct dm_andsec_io *io)
{
	struct bio *base_bio = io->base_bio;
	blk_status_t error = io->error;

	if (!atomic_dec_and_test(&io->io_pending))
		return;

	base_bio->bi_status = error;
	bio_endio(base_bio);
}

/*
 * 函数：andsec_endio
 * 作用：底层 clone bio 完成后的回调，负责释放写缓冲、排队读转换或完成原始 bio。
 */
static void andsec_endio(struct bio *clone)
{
	struct dm_andsec_io *io = clone->bi_private;
	struct andsec_config *cc = io->cc;
	unsigned int rw = bio_data_dir(clone);
	blk_status_t error;

	if (rw == WRITE)
		andsec_free_buffer_pages(cc, clone);

	error = clone->bi_status;
	bio_put(clone);

	if (rw == READ && !error) {
		/* 底层已经读回数据，下一步排队到 crypt_queue 做透传转换。 */
		kcryptd_queue_crypt(io);
		return;
	}

	if (unlikely(error))
		io->error = error;

	andsec_dec_pending(io);
}

/*
 * 函数：clone_init
 * 作用：把 clone bio 初始化成提交到底层真实设备的 bio。
 */
static void clone_init(struct dm_andsec_io *io, struct bio *clone)
{
	struct andsec_config *cc = io->cc;

	clone->bi_private = io;
	clone->bi_end_io = andsec_endio;
	bio_set_dev(clone, cc->dev->bdev);
	clone->bi_opf = io->base_bio->bi_opf;
}

/*
 * 函数：kcryptd_io_read
 * 作用：为读路径创建 fast clone，并把读请求提交到底层设备。
 */
static int kcryptd_io_read(struct dm_andsec_io *io, gfp_t gfp)
{
	struct andsec_config *cc = io->cc;
	struct bio *clone;

	clone = andsec_clone_bio(io, gfp);
	if (!clone)
		return 1;

	andsec_inc_pending(io);
	clone_init(io, clone);
	clone->bi_iter.bi_sector = cc->start + io->sector;

	andsec_submit_bio(io, clone);
	return 0;
}

/*
 * 函数：kcryptd_io_read_work
 * 作用：读路径 clone 分配的慢路径 work，用 GFP_NOIO 再尝试一次。
 */
static void kcryptd_io_read_work(struct work_struct *work)
{
	struct dm_andsec_io *io = container_of(work, struct dm_andsec_io, work);

	andsec_inc_pending(io);
	if (kcryptd_io_read(io, GFP_NOIO))
		io->error = BLK_STS_RESOURCE;
	andsec_dec_pending(io);
}

/*
 * 函数：kcryptd_queue_read
 * 作用：把读 IO 提交动作排到 io_queue 中执行。
 */
static void kcryptd_queue_read(struct dm_andsec_io *io)
{
	struct andsec_config *cc = io->cc;

	INIT_WORK(&io->work, kcryptd_io_read_work);
	queue_work(cc->io_queue, &io->work);
}

static void kcryptd_io_write(struct dm_andsec_io *io)
{
	andsec_submit_bio(io, io->ctx.bio_out);
}

#define andsec_io_from_node(node) rb_entry((node), struct dm_andsec_io, rb_node)

/*
 * 函数：dm_andsec_write
 * 作用：后台写线程，按 sector 顺序提交已经复制好的写 clone bio。
 */
static int dm_andsec_write(void *data)
{
	struct andsec_config *cc = data;
	struct dm_andsec_io *io;

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

		blk_start_plug(&plug);
		do {
			io = andsec_io_from_node(rb_first(&write_tree));
			rb_erase(&io->rb_node, &write_tree);
			kcryptd_io_write(io);
		} while (!RB_EMPTY_ROOT(&write_tree));
		blk_finish_plug(&plug);
	}

	return 0;
}

/*
 * 函数：kcryptd_crypt_write_io_submit
 * 作用：写路径转换完成后的提交入口；可直接提交，也可插入写线程排序红黑树。
 */
static void kcryptd_crypt_write_io_submit(struct dm_andsec_io *io)
{
	struct bio *clone = io->ctx.bio_out;
	struct andsec_config *cc = io->cc;
	unsigned long flags;
	sector_t sector;
	struct rb_node **rbp, *parent;

	if (unlikely(io->error)) {
		andsec_free_buffer_pages(cc, clone);
		bio_put(clone);
		andsec_dec_pending(io);
		return;
	}

	BUG_ON(io->ctx.iter_out.bi_size);

	clone->bi_iter.bi_sector = cc->start + io->sector;

	if (test_bit(DM_ANDSEC_NO_OFFLOAD, &cc->flags)) {
		andsec_submit_bio(io, clone);
		return;
	}

	spin_lock_irqsave(&cc->write_thread_lock, flags);
	if (RB_EMPTY_ROOT(&cc->write_tree))
		wake_up_process(cc->write_thread);
	rbp = &cc->write_tree.rb_node;
	parent = NULL;
	sector = io->sector;
	while (*rbp) {
		parent = *rbp;
		if (sector < andsec_io_from_node(parent)->sector)
			rbp = &(*rbp)->rb_left;
		else
			rbp = &(*rbp)->rb_right;
	}
	rb_link_node(&io->rb_node, parent, rbp);
	rb_insert_color(&io->rb_node, &cc->write_tree);
	spin_unlock_irqrestore(&cc->write_thread_lock, flags);
}

/*
 * 函数：kcryptd_crypt_write_convert
 * 作用：写路径的转换 work，把原始 bio 数据复制到 clone bio。
 */
static void kcryptd_crypt_write_convert(struct dm_andsec_io *io)
{
	struct andsec_config *cc = io->cc;
	struct bio *clone;
	blk_status_t r;

	andsec_inc_pending(io);

	clone = andsec_alloc_buffer(io, io->base_bio->bi_iter.bi_size);
	if (unlikely(!clone)) {
		io->error = BLK_STS_IOERR;
		goto dec;
	}

	andsec_convert_init(cc, &io->ctx, clone, io->base_bio, io->sector);

	/* 底层 clone IO 持有一个 pending，直到 andsec_endio()。 */
	andsec_inc_pending(io);
	r = andsec_convert(cc, &io->ctx);
	if (r)
		io->error = r;

	kcryptd_crypt_write_io_submit(io);

dec:
	andsec_dec_pending(io);
}

static void kcryptd_crypt_read_done(struct dm_andsec_io *io)
{
	andsec_dec_pending(io);
}

/*
 * 函数：kcryptd_crypt_read_convert
 * 作用：读路径的转换 work。底层读已把数据放到 base_bio，这里保留转换入口。
 */
static void kcryptd_crypt_read_convert(struct dm_andsec_io *io)
{
	struct andsec_config *cc = io->cc;
	blk_status_t r;

	andsec_inc_pending(io);
	andsec_convert_init(cc, &io->ctx, io->base_bio, io->base_bio, io->sector);

	r = andsec_convert(cc, &io->ctx);
	if (r)
		io->error = r;

	kcryptd_crypt_read_done(io);
	andsec_dec_pending(io);
}

/*
 * 函数：kcryptd_crypt
 * 作用：crypt_queue 的 work 入口，按 bio 方向分派到读转换或写转换。
 */
static void kcryptd_crypt(struct work_struct *work)
{
	struct dm_andsec_io *io = container_of(work, struct dm_andsec_io, work);

	if (bio_data_dir(io->base_bio) == READ)
		kcryptd_crypt_read_convert(io);
	else
		kcryptd_crypt_write_convert(io);
}

/*
 * 函数：kcryptd_queue_crypt
 * 作用：把数据转换 work 投递到 crypt_queue。
 */
static void kcryptd_queue_crypt(struct dm_andsec_io *io)
{
	struct andsec_config *cc = io->cc;

	INIT_WORK(&io->work, kcryptd_crypt);
	queue_work(cc->crypt_queue, &io->work);
}

/*
 * 函数：andsec_remap_bio
 * 作用：把无需数据转换的 bio 直接重映射到底层设备。
 */
static int andsec_remap_bio(struct dm_target *ti, struct bio *bio)
{
	struct andsec_config *cc = ti->private;

	bio_set_dev(bio, cc->dev->bdev);
	if (bio_sectors(bio))
		bio->bi_iter.bi_sector = cc->start +
			dm_target_offset(ti, bio->bi_iter.bi_sector);

	return DM_MAPIO_REMAPPED;
}

/*
 * 函数：andsec_ctr
 * 作用：构造一条 dm-andsec 映射。
 */
static int andsec_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct andsec_config *cc;
	const char *dev_path;
	const char *start_arg;
	unsigned int opt_index;
	unsigned long long tmp;
	char dummy;
	int ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
	const char *devname = dm_table_device_name(ti->table);
#else
	const char *devname = "";
#endif

	ret = andsec_parse_args(ti, argc, argv, &dev_path, &start_arg, &opt_index);
	if (ret)
		return ret;

	cc = kzalloc(sizeof(*cc), GFP_KERNEL);
	if (!cc) {
		ti->error = "Cannot allocate andsec context";
		return -ENOMEM;
	}

	cc->sector_size = (1 << SECTOR_SHIFT);
	cc->sector_shift = 0;
	ti->private = cc;

	spin_lock(&dm_andsec_clients_lock);
	dm_andsec_clients_n++;
	cc->client_counted = true;
	andsec_calculate_pages_per_client();
	spin_unlock(&dm_andsec_clients_lock);

	ret = percpu_counter_init(&cc->n_allocated_pages, 0, GFP_KERNEL);
	if (ret < 0)
		goto bad;
	cc->counter_initialized = true;

	ret = andsec_ctr_optional(ti, argc - opt_index, &argv[opt_index]);
	if (ret)
		goto bad;

	ret = -EINVAL;
	if (sscanf(start_arg, "%llu%c", &tmp, &dummy) != 1 ||
	    tmp != (sector_t)tmp) {
		ti->error = "Invalid device sector";
		goto bad;
	}
	cc->start = tmp;

	ret = dm_get_device(ti, dev_path, dm_table_get_mode(ti->table), &cc->dev);
	if (ret) {
		ti->error = "Device lookup failed";
		goto bad;
	}

	ret = mempool_init_kmalloc_pool(&cc->req_pool, MIN_IOS,
					sizeof(struct andsec_copy_request));
	if (ret) {
		ti->error = "Cannot allocate copy request mempool";
		goto bad;
	}
	cc->req_pool_initialized = true;

	ret = mempool_init(&cc->page_pool, BIO_MAX_PAGES, andsec_page_alloc,
			   andsec_page_free, cc);
	if (ret) {
		ti->error = "Cannot allocate page mempool";
		goto bad;
	}
	cc->page_pool_initialized = true;

	ret = bioset_init(&cc->bs, MIN_IOS, 0, BIOSET_NEED_BVECS);
	if (ret) {
		ti->error = "Cannot allocate bioset";
		goto bad;
	}
	cc->bs_initialized = true;

	mutex_init(&cc->bio_alloc_lock);
	cc->bio_alloc_lock_initialized = true;

	cc->per_bio_data_size = ti->per_io_data_size =
		ALIGN(sizeof(struct dm_andsec_io), ARCH_KMALLOC_MINALIGN);

	cc->io_queue = alloc_workqueue("kandsecd_io/%s", WQ_MEM_RECLAIM, 1,
				       devname);
	if (!cc->io_queue) {
		ti->error = "Couldn't create kandsecd io queue";
		ret = -ENOMEM;
		goto bad;
	}

	if (test_bit(DM_ANDSEC_SAME_CPU, &cc->flags))
		cc->crypt_queue = alloc_workqueue("kandsecd/%s",
			WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 1, devname);
	else
		cc->crypt_queue = alloc_workqueue("kandsecd/%s",
			WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM | WQ_UNBOUND,
			num_online_cpus(), devname);
	if (!cc->crypt_queue) {
		ti->error = "Couldn't create kandsecd queue";
		ret = -ENOMEM;
		goto bad;
	}

	spin_lock_init(&cc->write_thread_lock);
	cc->write_tree = RB_ROOT;

	cc->write_thread = kthread_create(dm_andsec_write, cc,
					  "dmandsec_write/%s", devname);
	if (IS_ERR(cc->write_thread)) {
		ret = PTR_ERR(cc->write_thread);
		cc->write_thread = NULL;
		ti->error = "Couldn't spawn write thread";
		goto bad;
	}
	wake_up_process(cc->write_thread);

	ti->num_flush_bios = 1;
#ifdef DM_ANDSEC_HAVE_LIMIT_SWAP_BIOS
	ti->limit_swap_bios = true;
#endif
#ifdef DM_ANDSEC_HAVE_ACCOUNTS_REMAPPED_IO
	ti->accounts_remapped_io = true;
#endif

	return 0;

bad:
	andsec_dtr(ti);
	return ret;
}

/*
 * 函数：andsec_dtr
 * 作用：销毁 dm-andsec target，释放 andsec_ctr() 创建的所有长期资源。
 */
static void andsec_dtr(struct dm_target *ti)
{
	struct andsec_config *cc = ti->private;

	ti->private = NULL;
	if (!cc)
		return;

	if (cc->write_thread)
		kthread_stop(cc->write_thread);

	if (cc->io_queue)
		destroy_workqueue(cc->io_queue);
	if (cc->crypt_queue)
		destroy_workqueue(cc->crypt_queue);

	if (cc->bs_initialized)
		bioset_exit(&cc->bs);
	if (cc->page_pool_initialized)
		mempool_exit(&cc->page_pool);
	if (cc->req_pool_initialized)
		mempool_exit(&cc->req_pool);

	if (cc->counter_initialized) {
		WARN_ON(percpu_counter_sum(&cc->n_allocated_pages) != 0);
		percpu_counter_destroy(&cc->n_allocated_pages);
	}

	if (cc->dev)
		dm_put_device(ti, cc->dev);

	if (cc->bio_alloc_lock_initialized)
		mutex_destroy(&cc->bio_alloc_lock);

	if (cc->client_counted) {
		spin_lock(&dm_andsec_clients_lock);
		WARN_ON(!dm_andsec_clients_n);
		dm_andsec_clients_n--;
		andsec_calculate_pages_per_client();
		spin_unlock(&dm_andsec_clients_lock);
	}

	kfree(cc);
}

/*
 * 函数：andsec_map
 * 作用：dm-andsec 的 IO 快路径入口，接收每个 bio 并分派到读/写处理流程。
 */
static int andsec_map(struct dm_target *ti, struct bio *bio)
{
	struct dm_andsec_io *io;
	struct andsec_config *cc = ti->private;

	/*
	 * 与 dm-crypt 保持一致：flush/discard 不进入转换队列，直接重映射到底层设备。
	 * flush 的顺序由 device-mapper core 保证；discard 如果需要顺序语义，调用方
	 * 应该自己配合 flush 使用。
	 */
	if (unlikely(bio->bi_opf & REQ_PREFLUSH ||
		     bio_op(bio) == REQ_OP_DISCARD))
		return andsec_remap_bio(ti, bio);

	if (unlikely(bio->bi_iter.bi_size > (BIO_MAX_PAGES << PAGE_SHIFT)) &&
	    bio_data_dir(bio) == WRITE)
		dm_accept_partial_bio(bio,
			((BIO_MAX_PAGES << PAGE_SHIFT) >> SECTOR_SHIFT));

	if (unlikely((bio->bi_iter.bi_sector &
		      ((cc->sector_size >> SECTOR_SHIFT) - 1)) != 0))
		return DM_MAPIO_KILL;

	if (unlikely(bio->bi_iter.bi_size & (cc->sector_size - 1)))
		return DM_MAPIO_KILL;

	io = dm_per_bio_data(bio, cc->per_bio_data_size);
	andsec_io_init(io, cc, bio, dm_target_offset(ti, bio->bi_iter.bi_sector));

	if (bio_data_dir(io->base_bio) == READ) {
		if (kcryptd_io_read(io, GFP_NOWAIT))
			kcryptd_queue_read(io);
	} else {
		kcryptd_queue_crypt(io);
	}

	return DM_MAPIO_SUBMITTED;
}

/*
 * 函数：andsec_status
 * 作用：响应 dmsetup table/status，输出当前 target 的表项或运行状态。
 */
static void andsec_status(struct dm_target *ti, status_type_t type,
			  unsigned int status_flags, char *result, unsigned int maxlen)
{
	struct andsec_config *cc = ti->private;

	switch (type) {
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;
	case STATUSTYPE_TABLE:
		snprintf(result, maxlen, "%s %llu", cc->dev->name,
			 (unsigned long long)cc->start);
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
	struct andsec_config *cc = ti->private;

	return fn(ti, cc->dev, cc->start, ti->len, data);
}

/*
 * 函数：andsec_io_hints
 * 作用：告诉块层/dm core 本 target 希望的 IO 对齐和 segment 限制。
 */
static void andsec_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct andsec_config *cc = ti->private;

	limits->max_segment_size = PAGE_SIZE;
	limits->logical_block_size =
		max_t(unsigned int, limits->logical_block_size, cc->sector_size);
	limits->physical_block_size =
		max_t(unsigned int, limits->physical_block_size, cc->sector_size);
	limits->io_min = max_t(unsigned int, limits->io_min, cc->sector_size);
}

static struct target_type andsec_target = {
	/*
	 * Device Mapper target 注册表。dm_register_target() 后，用户态映射表里写
	 * "andsec" 就会绑定到这一组回调。
	 */
	.name = "andsec",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr = andsec_ctr,
	.dtr = andsec_dtr,
	.map = andsec_map,
	.status = andsec_status,
	.iterate_devices = andsec_iterate_devices,
	.io_hints = andsec_io_hints,
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
	 *   1. 读路径：先 clone 一个底层读，读完成后进入 crypt_queue 做透传转换。
	 *   2. 写路径：先在 crypt_queue 复制到 clone bio，再由写线程提交到底层设备。
	 *   3. 没有数据页的管理请求直接 remap 到底层设备。
	 */
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
	dm_unregister_target(&andsec_target);
}

module_init(dm_andsec_init);
module_exit(dm_andsec_exit);

MODULE_AUTHOR("andsec");
MODULE_DESCRIPTION(DM_NAME " andsec target with passthrough convert pipeline");
MODULE_LICENSE("GPL");
