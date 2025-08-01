/*
 * Copyright (C) 2001 Sistina Software (UK) Limited.
 * Copyright (C) 2004-2008 Red Hat, Inc. All rights reserved.
 *
 * This file is released under the GPL.
 */

#include "dm-core.h"

#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/blkdev.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/atomic.h>
#include <linux/blk-mq.h>
#include <linux/mount.h>
#include <linux/dax.h>
#include <linux/bio.h>
#include <linux/keyslot-manager.h>

#define DM_MSG_PREFIX "table"

#define MAX_DEPTH 16
#define NODE_SIZE L1_CACHE_BYTES
#define KEYS_PER_NODE (NODE_SIZE / sizeof(sector_t))
#define CHILDREN_PER_NODE (KEYS_PER_NODE + 1)

struct dm_table {
	struct mapped_device *md;
	enum dm_queue_mode type;

	/* btree table */
	unsigned int depth;
	unsigned int counts[MAX_DEPTH];	/* in nodes */
	sector_t *index[MAX_DEPTH];

	unsigned int num_targets;
	unsigned int num_allocated;
	sector_t *highs;
	struct dm_target *targets;

	struct target_type *immutable_target_type;

	bool integrity_supported:1;
	bool singleton:1;
	bool all_blk_mq:1;
	unsigned integrity_added:1;

	/*
	 * Indicates the rw permissions for the new logical
	 * device.  This should be a combination of FMODE_READ
	 * and FMODE_WRITE.
	 */
	fmode_t mode;

	/* a list of devices used by this table */
	struct list_head devices;

	/* events get handed up using this callback */
	void (*event_fn)(void *);
	void *event_context;

	struct dm_md_mempools *mempools;

	struct list_head target_callbacks;
};

/*
 * Similar to ceiling(log_size(n))
 */
static unsigned int int_log(unsigned int n, unsigned int base)
{
	int result = 0;

	while (n > 1) {
		n = dm_div_up(n, base);
		result++;
	}

	return result;
}

/*
 * Calculate the index of the child node of the n'th node k'th key.
 */
static inline unsigned int get_child(unsigned int n, unsigned int k)
{
	return (n * CHILDREN_PER_NODE) + k;
}

/*
 * Return the n'th node of level l from table t.
 */
static inline sector_t *get_node(struct dm_table *t,
				 unsigned int l, unsigned int n)
{
	return t->index[l] + (n * KEYS_PER_NODE);
}

/*
 * Return the highest key that you could lookup from the n'th
 * node on level l of the btree.
 */
static sector_t high(struct dm_table *t, unsigned int l, unsigned int n)
{
	for (; l < t->depth - 1; l++)
		n = get_child(n, CHILDREN_PER_NODE - 1);

	if (n >= t->counts[l])
		return (sector_t) - 1;

	return get_node(t, l, n)[KEYS_PER_NODE - 1];
}

/*
 * Fills in a level of the btree based on the highs of the level
 * below it.
 */
static int setup_btree_index(unsigned int l, struct dm_table *t)
{
	unsigned int n, k;
	sector_t *node;

	for (n = 0U; n < t->counts[l]; n++) {
		node = get_node(t, l, n);

		for (k = 0U; k < KEYS_PER_NODE; k++)
			node[k] = high(t, l + 1, get_child(n, k));
	}

	return 0;
}

void *dm_vcalloc(unsigned long nmemb, unsigned long elem_size)
{
	unsigned long size;
	void *addr;

	/*
	 * Check that we're not going to overflow.
	 */
	if (nmemb > (ULONG_MAX / elem_size))
		return NULL;

	size = nmemb * elem_size;
	addr = vzalloc(size);

	return addr;
}
EXPORT_SYMBOL(dm_vcalloc);

/*
 * highs, and targets are managed as dynamic arrays during a
 * table load.
 */
static int alloc_targets(struct dm_table *t, unsigned int num)
{
	sector_t *n_highs;
	struct dm_target *n_targets;

	/*
	 * Allocate both the target array and offset array at once.
	 * Append an empty entry to catch sectors beyond the end of
	 * the device.
	 */
	n_highs = (sector_t *) dm_vcalloc(num + 1, sizeof(struct dm_target) +
					  sizeof(sector_t));
	if (!n_highs)
		return -ENOMEM;

	n_targets = (struct dm_target *) (n_highs + num);

	memset(n_highs, -1, sizeof(*n_highs) * num);
	vfree(t->highs);

	t->num_allocated = num;
	t->highs = n_highs;
	t->targets = n_targets;

	return 0;
}

int dm_table_create(struct dm_table **result, fmode_t mode,
		    unsigned num_targets, struct mapped_device *md)
{
	struct dm_table *t;

	if (num_targets > DM_MAX_TARGETS)
		return -EOVERFLOW;

	t = kzalloc(sizeof(*t), GFP_KERNEL);

	if (!t)
		return -ENOMEM;

	INIT_LIST_HEAD(&t->devices);
	INIT_LIST_HEAD(&t->target_callbacks);

	if (!num_targets)
		num_targets = KEYS_PER_NODE;

	num_targets = dm_round_up(num_targets, KEYS_PER_NODE);

	if (!num_targets) {
		kfree(t);
		return -EOVERFLOW;
	}

	if (alloc_targets(t, num_targets)) {
		kfree(t);
		return -ENOMEM;
	}

	t->type = DM_TYPE_NONE;
	t->mode = mode;
	t->md = md;
	*result = t;
	return 0;
}

static void free_devices(struct list_head *devices, struct mapped_device *md)
{
	struct list_head *tmp, *next;

	list_for_each_safe(tmp, next, devices) {
		struct dm_dev_internal *dd =
		    list_entry(tmp, struct dm_dev_internal, list);
		DMWARN("%s: dm_table_destroy: dm_put_device call missing for %s",
		       dm_device_name(md), dd->dm_dev->name);
		dm_put_table_device(md, dd->dm_dev);
		kfree(dd);
	}
}

void dm_table_destroy(struct dm_table *t)
{
	unsigned int i;

	if (!t)
		return;

	/* free the indexes */
	if (t->depth >= 2)
		vfree(t->index[t->depth - 2]);

	/* free the targets */
	for (i = 0; i < t->num_targets; i++) {
		struct dm_target *tgt = t->targets + i;

		if (tgt->type->dtr)
			tgt->type->dtr(tgt);

		dm_put_target_type(tgt->type);
	}

	vfree(t->highs);

	/* free the device list */
	free_devices(&t->devices, t->md);

	dm_free_md_mempools(t->mempools);

	kfree(t);
}

/*
 * See if we've already got a device in the list.
 */
static struct dm_dev_internal *find_device(struct list_head *l, dev_t dev)
{
	struct dm_dev_internal *dd;

	list_for_each_entry (dd, l, list)
		if (dd->dm_dev->bdev->bd_dev == dev)
			return dd;

	return NULL;
}

/*
 * If possible, this checks an area of a destination device is invalid.
 */
static int device_area_is_invalid(struct dm_target *ti, struct dm_dev *dev,
				  sector_t start, sector_t len, void *data)
{
	struct request_queue *q;
	struct queue_limits *limits = data;
	struct block_device *bdev = dev->bdev;
	sector_t dev_size =
		i_size_read(bdev->bd_inode) >> SECTOR_SHIFT;
	unsigned short logical_block_size_sectors =
		limits->logical_block_size >> SECTOR_SHIFT;
	char b[BDEVNAME_SIZE];

	/*
	 * Some devices exist without request functions,
	 * such as loop devices not yet bound to backing files.
	 * Forbid the use of such devices.
	 */
	q = bdev_get_queue(bdev);
	if (!q || !q->make_request_fn) {
		DMWARN("%s: %s is not yet initialised: "
		       "start=%llu, len=%llu, dev_size=%llu",
		       dm_device_name(ti->table->md), bdevname(bdev, b),
		       (unsigned long long)start,
		       (unsigned long long)len,
		       (unsigned long long)dev_size);
		return 1;
	}

	if (!dev_size)
		return 0;

	if ((start >= dev_size) || (start + len > dev_size)) {
		DMWARN("%s: %s too small for target: "
		       "start=%llu, len=%llu, dev_size=%llu",
		       dm_device_name(ti->table->md), bdevname(bdev, b),
		       (unsigned long long)start,
		       (unsigned long long)len,
		       (unsigned long long)dev_size);
		return 1;
	}

	/*
	 * If the target is mapped to zoned block device(s), check
	 * that the zones are not partially mapped.
	 */
	if (bdev_zoned_model(bdev) != BLK_ZONED_NONE) {
		unsigned int zone_sectors = bdev_zone_sectors(bdev);

		if (start & (zone_sectors - 1)) {
			DMWARN("%s: start=%llu not aligned to h/w zone size %u of %s",
			       dm_device_name(ti->table->md),
			       (unsigned long long)start,
			       zone_sectors, bdevname(bdev, b));
			return 1;
		}

		/*
		 * Note: The last zone of a zoned block device may be smaller
		 * than other zones. So for a target mapping the end of a
		 * zoned block device with such a zone, len would not be zone
		 * aligned. We do not allow such last smaller zone to be part
		 * of the mapping here to ensure that mappings with multiple
		 * devices do not end up with a smaller zone in the middle of
		 * the sector range.
		 */
		if (len & (zone_sectors - 1)) {
			DMWARN("%s: len=%llu not aligned to h/w zone size %u of %s",
			       dm_device_name(ti->table->md),
			       (unsigned long long)len,
			       zone_sectors, bdevname(bdev, b));
			return 1;
		}
	}

	if (logical_block_size_sectors <= 1)
		return 0;

	if (start & (logical_block_size_sectors - 1)) {
		DMWARN("%s: start=%llu not aligned to h/w "
		       "logical block size %u of %s",
		       dm_device_name(ti->table->md),
		       (unsigned long long)start,
		       limits->logical_block_size, bdevname(bdev, b));
		return 1;
	}

	if (len & (logical_block_size_sectors - 1)) {
		DMWARN("%s: len=%llu not aligned to h/w "
		       "logical block size %u of %s",
		       dm_device_name(ti->table->md),
		       (unsigned long long)len,
		       limits->logical_block_size, bdevname(bdev, b));
		return 1;
	}

	return 0;
}

/*
 * This upgrades the mode on an already open dm_dev, being
 * careful to leave things as they were if we fail to reopen the
 * device and not to touch the existing bdev field in case
 * it is accessed concurrently inside dm_table_any_congested().
 */
static int upgrade_mode(struct dm_dev_internal *dd, fmode_t new_mode,
			struct mapped_device *md)
{
	int r;
	struct dm_dev *old_dev, *new_dev;

	old_dev = dd->dm_dev;

	r = dm_get_table_device(md, dd->dm_dev->bdev->bd_dev,
				dd->dm_dev->mode | new_mode, &new_dev);
	if (r)
		return r;

	dd->dm_dev = new_dev;
	dm_put_table_device(md, old_dev);

	return 0;
}

/*
 * Convert the path to a device
 */
dev_t dm_get_dev_t(const char *path)
{
	dev_t dev;
	struct block_device *bdev;

	bdev = lookup_bdev(path);
	if (IS_ERR(bdev))
		dev = name_to_dev_t(path);
	else {
		dev = bdev->bd_dev;
		bdput(bdev);
	}

	return dev;
}
EXPORT_SYMBOL_GPL(dm_get_dev_t);

/*
 * Add a device to the list, or just increment the usage count if
 * it's already present.
 */
int dm_get_device(struct dm_target *ti, const char *path, fmode_t mode,
		  struct dm_dev **result)
{
	int r;
	dev_t dev;
	unsigned int major, minor;
	char dummy;
	struct dm_dev_internal *dd;
	struct dm_table *t = ti->table;

	BUG_ON(!t);

	if (sscanf(path, "%u:%u%c", &major, &minor, &dummy) == 2) {
		/* Extract the major/minor numbers */
		dev = MKDEV(major, minor);
		if (MAJOR(dev) != major || MINOR(dev) != minor)
			return -EOVERFLOW;
	} else {
		dev = dm_get_dev_t(path);
		if (!dev)
			return -ENODEV;
	}

	dd = find_device(&t->devices, dev);
	if (!dd) {
		dd = kmalloc(sizeof(*dd), GFP_KERNEL);
		if (!dd)
			return -ENOMEM;

		if ((r = dm_get_table_device(t->md, dev, mode, &dd->dm_dev))) {
			kfree(dd);
			return r;
		}

		atomic_set(&dd->count, 0);
		list_add(&dd->list, &t->devices);

	} else if (dd->dm_dev->mode != (mode | dd->dm_dev->mode)) {
		r = upgrade_mode(dd, mode, t->md);
		if (r)
			return r;
	}
	atomic_inc(&dd->count);

	*result = dd->dm_dev;
	return 0;
}
EXPORT_SYMBOL(dm_get_device);

static int dm_set_device_limits(struct dm_target *ti, struct dm_dev *dev,
				sector_t start, sector_t len, void *data)
{
	struct queue_limits *limits = data;
	struct block_device *bdev = dev->bdev;
	struct request_queue *q = bdev_get_queue(bdev);
	char b[BDEVNAME_SIZE];

	if (unlikely(!q)) {
		DMWARN("%s: Cannot set limits for nonexistent device %s",
		       dm_device_name(ti->table->md), bdevname(bdev, b));
		return 0;
	}

	if (bdev_stack_limits(limits, bdev, start) < 0)
		DMWARN("%s: adding target device %s caused an alignment inconsistency: "
		       "physical_block_size=%u, logical_block_size=%u, "
		       "alignment_offset=%u, start=%llu",
		       dm_device_name(ti->table->md), bdevname(bdev, b),
		       q->limits.physical_block_size,
		       q->limits.logical_block_size,
		       q->limits.alignment_offset,
		       (unsigned long long) start << SECTOR_SHIFT);

	limits->zoned = blk_queue_zoned_model(q);

	return 0;
}

/*
 * Decrement a device's use count and remove it if necessary.
 */
void dm_put_device(struct dm_target *ti, struct dm_dev *d)
{
	int found = 0;
	struct list_head *devices = &ti->table->devices;
	struct dm_dev_internal *dd;

	list_for_each_entry(dd, devices, list) {
		if (dd->dm_dev == d) {
			found = 1;
			break;
		}
	}
	if (!found) {
		DMWARN("%s: device %s not in table devices list",
		       dm_device_name(ti->table->md), d->name);
		return;
	}
	if (atomic_dec_and_test(&dd->count)) {
		dm_put_table_device(ti->table->md, d);
		list_del(&dd->list);
		kfree(dd);
	}
}
EXPORT_SYMBOL(dm_put_device);

/*
 * Checks to see if the target joins onto the end of the table.
 */
static int adjoin(struct dm_table *table, struct dm_target *ti)
{
	struct dm_target *prev;

	if (!table->num_targets)
		return !ti->begin;

	prev = &table->targets[table->num_targets - 1];
	return (ti->begin == (prev->begin + prev->len));
}

/*
 * Used to dynamically allocate the arg array.
 *
 * We do first allocation with GFP_NOIO because dm-mpath and dm-thin must
 * process messages even if some device is suspended. These messages have a
 * small fixed number of arguments.
 *
 * On the other hand, dm-switch needs to process bulk data using messages and
 * excessive use of GFP_NOIO could cause trouble.
 */
static char **realloc_argv(unsigned *size, char **old_argv)
{
	char **argv;
	unsigned new_size;
	gfp_t gfp;

	if (*size) {
		new_size = *size * 2;
		gfp = GFP_KERNEL;
	} else {
		new_size = 8;
		gfp = GFP_NOIO;
	}
	argv = kmalloc(new_size * sizeof(*argv), gfp);
	if (argv) {
		memcpy(argv, old_argv, *size * sizeof(*argv));
		*size = new_size;
	}

	kfree(old_argv);
	return argv;
}

/*
 * Destructively splits up the argument list to pass to ctr.
 */
int dm_split_args(int *argc, char ***argvp, char *input)
{
	char *start, *end = input, *out, **argv = NULL;
	unsigned array_size = 0;

	*argc = 0;

	if (!input) {
		*argvp = NULL;
		return 0;
	}

	argv = realloc_argv(&array_size, argv);
	if (!argv)
		return -ENOMEM;

	while (1) {
		/* Skip whitespace */
		start = skip_spaces(end);

		if (!*start)
			break;	/* success, we hit the end */

		/* 'out' is used to remove any back-quotes */
		end = out = start;
		while (*end) {
			/* Everything apart from '\0' can be quoted */
			if (*end == '\\' && *(end + 1)) {
				*out++ = *(end + 1);
				end += 2;
				continue;
			}

			if (isspace(*end))
				break;	/* end of token */

			*out++ = *end++;
		}

		/* have we already filled the array ? */
		if ((*argc + 1) > array_size) {
			argv = realloc_argv(&array_size, argv);
			if (!argv)
				return -ENOMEM;
		}

		/* we know this is whitespace */
		if (*end)
			end++;

		/* terminate the string and put it in the array */
		*out = '\0';
		argv[*argc] = start;
		(*argc)++;
	}

	*argvp = argv;
	return 0;
}

/*
 * Impose necessary and sufficient conditions on a devices's table such
 * that any incoming bio which respects its logical_block_size can be
 * processed successfully.  If it falls across the boundary between
 * two or more targets, the size of each piece it gets split into must
 * be compatible with the logical_block_size of the target processing it.
 */
static int validate_hardware_logical_block_alignment(struct dm_table *table,
						 struct queue_limits *limits)
{
	/*
	 * This function uses arithmetic modulo the logical_block_size
	 * (in units of 512-byte sectors).
	 */
	unsigned short device_logical_block_size_sects =
		limits->logical_block_size >> SECTOR_SHIFT;

	/*
	 * Offset of the start of the next table entry, mod logical_block_size.
	 */
	unsigned short next_target_start = 0;

	/*
	 * Given an aligned bio that extends beyond the end of a
	 * target, how many sectors must the next target handle?
	 */
	unsigned short remaining = 0;

	struct dm_target *ti;
	struct queue_limits ti_limits;
	unsigned i;

	/*
	 * Check each entry in the table in turn.
	 */
	for (i = 0; i < dm_table_get_num_targets(table); i++) {
		ti = dm_table_get_target(table, i);

		blk_set_stacking_limits(&ti_limits);

		/* combine all target devices' limits */
		if (ti->type->iterate_devices)
			ti->type->iterate_devices(ti, dm_set_device_limits,
						  &ti_limits);

		/*
		 * If the remaining sectors fall entirely within this
		 * table entry are they compatible with its logical_block_size?
		 */
		if (remaining < ti->len &&
		    remaining & ((ti_limits.logical_block_size >>
				  SECTOR_SHIFT) - 1))
			break;	/* Error */

		next_target_start =
		    (unsigned short) ((next_target_start + ti->len) &
				      (device_logical_block_size_sects - 1));
		remaining = next_target_start ?
		    device_logical_block_size_sects - next_target_start : 0;
	}

	if (remaining) {
		DMWARN("%s: table line %u (start sect %llu len %llu) "
		       "not aligned to h/w logical block size %u",
		       dm_device_name(table->md), i,
		       (unsigned long long) ti->begin,
		       (unsigned long long) ti->len,
		       limits->logical_block_size);
		return -EINVAL;
	}

	return 0;
}

int dm_table_add_target(struct dm_table *t, const char *type,
			sector_t start, sector_t len, char *params)
{
	int r = -EINVAL, argc;
	char **argv;
	struct dm_target *tgt;

	if (t->singleton) {
		DMERR("%s: target type %s must appear alone in table",
		      dm_device_name(t->md), t->targets->type->name);
		return -EINVAL;
	}

	BUG_ON(t->num_targets >= t->num_allocated);

	tgt = t->targets + t->num_targets;
	memset(tgt, 0, sizeof(*tgt));

	if (!len) {
		DMERR("%s: zero-length target", dm_device_name(t->md));
		return -EINVAL;
	}
	if (start + len < start || start + len > LLONG_MAX >> SECTOR_SHIFT) {
		DMERR("%s: too large device", dm_device_name(t->md));
		return -EINVAL;
	}

	tgt->type = dm_get_target_type(type);
	if (!tgt->type) {
		DMERR("%s: %s: unknown target type", dm_device_name(t->md), type);
		return -EINVAL;
	}

	if (dm_target_needs_singleton(tgt->type)) {
		if (t->num_targets) {
			tgt->error = "singleton target type must appear alone in table";
			goto bad;
		}
		t->singleton = true;
	}

	if (dm_target_always_writeable(tgt->type) && !(t->mode & FMODE_WRITE)) {
		tgt->error = "target type may not be included in a read-only table";
		goto bad;
	}

	if (t->immutable_target_type) {
		if (t->immutable_target_type != tgt->type) {
			tgt->error = "immutable target type cannot be mixed with other target types";
			goto bad;
		}
	} else if (dm_target_is_immutable(tgt->type)) {
		if (t->num_targets) {
			tgt->error = "immutable target type cannot be mixed with other target types";
			goto bad;
		}
		t->immutable_target_type = tgt->type;
	}

	if (dm_target_has_integrity(tgt->type))
		t->integrity_added = 1;

	tgt->table = t;
	tgt->begin = start;
	tgt->len = len;
	tgt->error = "Unknown error";

	/*
	 * Does this target adjoin the previous one ?
	 */
	if (!adjoin(t, tgt)) {
		tgt->error = "Gap in table";
		goto bad;
	}

	r = dm_split_args(&argc, &argv, params);
	if (r) {
		tgt->error = "couldn't split parameters (insufficient memory)";
		goto bad;
	}

	r = tgt->type->ctr(tgt, argc, argv);
	kfree(argv);
	if (r)
		goto bad;

	t->highs[t->num_targets++] = tgt->begin + tgt->len - 1;

	if (!tgt->num_discard_bios && tgt->discards_supported)
		DMWARN("%s: %s: ignoring discards_supported because num_discard_bios is zero.",
		       dm_device_name(t->md), type);

	return 0;

 bad:
	DMERR("%s: %s: %s", dm_device_name(t->md), type, tgt->error);
	dm_put_target_type(tgt->type);
	return r;
}

/*
 * Target argument parsing helpers.
 */
static int validate_next_arg(const struct dm_arg *arg,
			     struct dm_arg_set *arg_set,
			     unsigned *value, char **error, unsigned grouped)
{
	const char *arg_str = dm_shift_arg(arg_set);
	char dummy;

	if (!arg_str ||
	    (sscanf(arg_str, "%u%c", value, &dummy) != 1) ||
	    (*value < arg->min) ||
	    (*value > arg->max) ||
	    (grouped && arg_set->argc < *value)) {
		*error = arg->error;
		return -EINVAL;
	}

	return 0;
}

int dm_read_arg(const struct dm_arg *arg, struct dm_arg_set *arg_set,
		unsigned *value, char **error)
{
	return validate_next_arg(arg, arg_set, value, error, 0);
}
EXPORT_SYMBOL(dm_read_arg);

int dm_read_arg_group(const struct dm_arg *arg, struct dm_arg_set *arg_set,
		      unsigned *value, char **error)
{
	return validate_next_arg(arg, arg_set, value, error, 1);
}
EXPORT_SYMBOL(dm_read_arg_group);

const char *dm_shift_arg(struct dm_arg_set *as)
{
	char *r;

	if (as->argc) {
		as->argc--;
		r = *as->argv;
		as->argv++;
		return r;
	}

	return NULL;
}
EXPORT_SYMBOL(dm_shift_arg);

void dm_consume_args(struct dm_arg_set *as, unsigned num_args)
{
	BUG_ON(as->argc < num_args);
	as->argc -= num_args;
	as->argv += num_args;
}
EXPORT_SYMBOL(dm_consume_args);

static bool __table_type_bio_based(enum dm_queue_mode table_type)
{
	return (table_type == DM_TYPE_BIO_BASED ||
		table_type == DM_TYPE_DAX_BIO_BASED);
}

static bool __table_type_request_based(enum dm_queue_mode table_type)
{
	return (table_type == DM_TYPE_REQUEST_BASED ||
		table_type == DM_TYPE_MQ_REQUEST_BASED);
}

void dm_table_set_type(struct dm_table *t, enum dm_queue_mode type)
{
	t->type = type;
}
EXPORT_SYMBOL_GPL(dm_table_set_type);

static int device_not_dax_capable(struct dm_target *ti, struct dm_dev *dev,
			       sector_t start, sector_t len, void *data)
{
	return !bdev_dax_supported(dev->bdev, PAGE_SIZE);
}

static bool dm_table_supports_dax(struct dm_table *t)
{
	struct dm_target *ti;
	unsigned i;

	/* Ensure that all targets support DAX. */
	for (i = 0; i < dm_table_get_num_targets(t); i++) {
		ti = dm_table_get_target(t, i);

		if (!ti->type->direct_access)
			return false;

		if (!ti->type->iterate_devices ||
		    ti->type->iterate_devices(ti, device_not_dax_capable, NULL))
			return false;
	}

	return true;
}

static int dm_table_determine_type(struct dm_table *t)
{
	unsigned i;
	unsigned bio_based = 0, request_based = 0, hybrid = 0;
	unsigned sq_count = 0, mq_count = 0;
	struct dm_target *tgt;
	struct dm_dev_internal *dd;
	struct list_head *devices = dm_table_get_devices(t);
	enum dm_queue_mode live_md_type = dm_get_md_type(t->md);

	if (t->type != DM_TYPE_NONE) {
		/* target already set the table's type */
		if (t->type == DM_TYPE_BIO_BASED)
			return 0;
		BUG_ON(t->type == DM_TYPE_DAX_BIO_BASED);
		goto verify_rq_based;
	}

	for (i = 0; i < t->num_targets; i++) {
		tgt = t->targets + i;
		if (dm_target_hybrid(tgt))
			hybrid = 1;
		else if (dm_target_request_based(tgt))
			request_based = 1;
		else
			bio_based = 1;

		if (bio_based && request_based) {
			DMWARN("Inconsistent table: different target types"
			       " can't be mixed up");
			return -EINVAL;
		}
	}

	if (hybrid && !bio_based && !request_based) {
		/*
		 * The targets can work either way.
		 * Determine the type from the live device.
		 * Default to bio-based if device is new.
		 */
		if (__table_type_request_based(live_md_type))
			request_based = 1;
		else
			bio_based = 1;
	}

	if (bio_based) {
		/* We must use this table as bio-based */
		t->type = DM_TYPE_BIO_BASED;
		if (dm_table_supports_dax(t) ||
		    (list_empty(devices) && live_md_type == DM_TYPE_DAX_BIO_BASED))
			t->type = DM_TYPE_DAX_BIO_BASED;
		return 0;
	}

	BUG_ON(!request_based); /* No targets in this table */

	/*
	 * The only way to establish DM_TYPE_MQ_REQUEST_BASED is by
	 * having a compatible target use dm_table_set_type.
	 */
	t->type = DM_TYPE_REQUEST_BASED;

verify_rq_based:
	/*
	 * Request-based dm supports only tables that have a single target now.
	 * To support multiple targets, request splitting support is needed,
	 * and that needs lots of changes in the block-layer.
	 * (e.g. request completion process for partial completion.)
	 */
	if (t->num_targets > 1) {
		DMWARN("Request-based dm doesn't support multiple targets yet");
		return -EINVAL;
	}

	if (list_empty(devices)) {
		int srcu_idx;
		struct dm_table *live_table = dm_get_live_table(t->md, &srcu_idx);

		/* inherit live table's type and all_blk_mq */
		if (live_table) {
			t->type = live_table->type;
			t->all_blk_mq = live_table->all_blk_mq;
		}
		dm_put_live_table(t->md, srcu_idx);
		return 0;
	}

	/* Non-request-stackable devices can't be used for request-based dm */
	list_for_each_entry(dd, devices, list) {
		struct request_queue *q = bdev_get_queue(dd->dm_dev->bdev);

		if (!blk_queue_stackable(q)) {
			DMERR("table load rejected: including"
			      " non-request-stackable devices");
			return -EINVAL;
		}

		if (q->mq_ops)
			mq_count++;
		else
			sq_count++;
	}
	if (sq_count && mq_count) {
		DMERR("table load rejected: not all devices are blk-mq request-stackable");
		return -EINVAL;
	}
	t->all_blk_mq = mq_count > 0;

	if (t->type == DM_TYPE_MQ_REQUEST_BASED && !t->all_blk_mq) {
		DMERR("table load rejected: all devices are not blk-mq request-stackable");
		return -EINVAL;
	}

	return 0;
}

enum dm_queue_mode dm_table_get_type(struct dm_table *t)
{
	return t->type;
}

struct target_type *dm_table_get_immutable_target_type(struct dm_table *t)
{
	return t->immutable_target_type;
}

struct dm_target *dm_table_get_immutable_target(struct dm_table *t)
{
	/* Immutable target is implicitly a singleton */
	if (t->num_targets > 1 ||
	    !dm_target_is_immutable(t->targets[0].type))
		return NULL;

	return t->targets;
}

struct dm_target *dm_table_get_wildcard_target(struct dm_table *t)
{
	struct dm_target *ti;
	unsigned i;

	for (i = 0; i < dm_table_get_num_targets(t); i++) {
		ti = dm_table_get_target(t, i);
		if (dm_target_is_wildcard(ti->type))
			return ti;
	}

	return NULL;
}

bool dm_table_bio_based(struct dm_table *t)
{
	return __table_type_bio_based(dm_table_get_type(t));
}

bool dm_table_request_based(struct dm_table *t)
{
	return __table_type_request_based(dm_table_get_type(t));
}

bool dm_table_all_blk_mq_devices(struct dm_table *t)
{
	return t->all_blk_mq;
}

static int dm_table_alloc_md_mempools(struct dm_table *t, struct mapped_device *md)
{
	enum dm_queue_mode type = dm_table_get_type(t);
	unsigned per_io_data_size = 0;
	struct dm_target *tgt;
	unsigned i;

	if (unlikely(type == DM_TYPE_NONE)) {
		DMWARN("no table type is set, can't allocate mempools");
		return -EINVAL;
	}

	if (__table_type_bio_based(type))
		for (i = 0; i < t->num_targets; i++) {
			tgt = t->targets + i;
			per_io_data_size = max(per_io_data_size, tgt->per_io_data_size);
		}

	t->mempools = dm_alloc_md_mempools(md, type, t->integrity_supported, per_io_data_size);
	if (!t->mempools)
		return -ENOMEM;

	return 0;
}

void dm_table_free_md_mempools(struct dm_table *t)
{
	dm_free_md_mempools(t->mempools);
	t->mempools = NULL;
}

struct dm_md_mempools *dm_table_get_md_mempools(struct dm_table *t)
{
	return t->mempools;
}

static int setup_indexes(struct dm_table *t)
{
	int i;
	unsigned int total = 0;
	sector_t *indexes;

	/* allocate the space for *all* the indexes */
	for (i = t->depth - 2; i >= 0; i--) {
		t->counts[i] = dm_div_up(t->counts[i + 1], CHILDREN_PER_NODE);
		total += t->counts[i];
	}

	indexes = (sector_t *) dm_vcalloc(total, (unsigned long) NODE_SIZE);
	if (!indexes)
		return -ENOMEM;

	/* set up internal nodes, bottom-up */
	for (i = t->depth - 2; i >= 0; i--) {
		t->index[i] = indexes;
		indexes += (KEYS_PER_NODE * t->counts[i]);
		setup_btree_index(i, t);
	}

	return 0;
}

/*
 * Builds the btree to index the map.
 */
static int dm_table_build_index(struct dm_table *t)
{
	int r = 0;
	unsigned int leaf_nodes;

	/* how many indexes will the btree have ? */
	leaf_nodes = dm_div_up(t->num_targets, KEYS_PER_NODE);
	t->depth = 1 + int_log(leaf_nodes, CHILDREN_PER_NODE);

	/* leaf layer has already been set up */
	t->counts[t->depth - 1] = leaf_nodes;
	t->index[t->depth - 1] = t->highs;

	if (t->depth >= 2)
		r = setup_indexes(t);

	return r;
}

static bool integrity_profile_exists(struct gendisk *disk)
{
	return !!blk_get_integrity(disk);
}

/*
 * Get a disk whose integrity profile reflects the table's profile.
 * Returns NULL if integrity support was inconsistent or unavailable.
 */
static struct gendisk * dm_table_get_integrity_disk(struct dm_table *t)
{
	struct list_head *devices = dm_table_get_devices(t);
	struct dm_dev_internal *dd = NULL;
	struct gendisk *prev_disk = NULL, *template_disk = NULL;
	unsigned i;

	for (i = 0; i < dm_table_get_num_targets(t); i++) {
		struct dm_target *ti = dm_table_get_target(t, i);
		if (!dm_target_passes_integrity(ti->type))
			goto no_integrity;
	}

	list_for_each_entry(dd, devices, list) {
		template_disk = dd->dm_dev->bdev->bd_disk;
		if (!integrity_profile_exists(template_disk))
			goto no_integrity;
		else if (prev_disk &&
			 blk_integrity_compare(prev_disk, template_disk) < 0)
			goto no_integrity;
		prev_disk = template_disk;
	}

	return template_disk;

no_integrity:
	if (prev_disk)
		DMWARN("%s: integrity not set: %s and %s profile mismatch",
		       dm_device_name(t->md),
		       prev_disk->disk_name,
		       template_disk->disk_name);
	return NULL;
}

/*
 * Register the mapped device for blk_integrity support if the
 * underlying devices have an integrity profile.  But all devices may
 * not have matching profiles (checking all devices isn't reliable
 * during table load because this table may use other DM device(s) which
 * must be resumed before they will have an initialized integity
 * profile).  Consequently, stacked DM devices force a 2 stage integrity
 * profile validation: First pass during table load, final pass during
 * resume.
 */
static int dm_table_register_integrity(struct dm_table *t)
{
	struct mapped_device *md = t->md;
	struct gendisk *template_disk = NULL;

	/* If target handles integrity itself do not register it here. */
	if (t->integrity_added)
		return 0;

	template_disk = dm_table_get_integrity_disk(t);
	if (!template_disk)
		return 0;

	if (!integrity_profile_exists(dm_disk(md))) {
		t->integrity_supported = true;
		/*
		 * Register integrity profile during table load; we can do
		 * this because the final profile must match during resume.
		 */
		blk_integrity_register(dm_disk(md),
				       blk_get_integrity(template_disk));
		return 0;
	}

	/*
	 * If DM device already has an initialized integrity
	 * profile the new profile should not conflict.
	 */
	if (blk_integrity_compare(dm_disk(md), template_disk) < 0) {
		DMWARN("%s: conflict with existing integrity profile: "
		       "%s profile mismatch",
		       dm_device_name(t->md),
		       template_disk->disk_name);
		return 1;
	}

	/* Preserve existing integrity profile */
	t->integrity_supported = true;
	return 0;
}

/*
 * Prepares the table for use by building the indices,
 * setting the type, and allocating mempools.
 */
int dm_table_complete(struct dm_table *t)
{
	int r;

	r = dm_table_determine_type(t);
	if (r) {
		DMERR("unable to determine table type");
		return r;
	}

	r = dm_table_build_index(t);
	if (r) {
		DMERR("unable to build btrees");
		return r;
	}

	r = dm_table_register_integrity(t);
	if (r) {
		DMERR("could not register integrity profile.");
		return r;
	}

	r = dm_table_alloc_md_mempools(t, t->md);
	if (r)
		DMERR("unable to allocate mempools");

	return r;
}

static DEFINE_MUTEX(_event_lock);
void dm_table_event_callback(struct dm_table *t,
			     void (*fn)(void *), void *context)
{
	mutex_lock(&_event_lock);
	t->event_fn = fn;
	t->event_context = context;
	mutex_unlock(&_event_lock);
}

void dm_table_event(struct dm_table *t)
{
	mutex_lock(&_event_lock);
	if (t->event_fn)
		t->event_fn(t->event_context);
	mutex_unlock(&_event_lock);
}
EXPORT_SYMBOL(dm_table_event);

inline sector_t dm_table_get_size(struct dm_table *t)
{
	return t->num_targets ? (t->highs[t->num_targets - 1] + 1) : 0;
}
EXPORT_SYMBOL(dm_table_get_size);

struct dm_target *dm_table_get_target(struct dm_table *t, unsigned int index)
{
	if (index >= t->num_targets)
		return NULL;

	return t->targets + index;
}

/*
 * Search the btree for the correct target.
 *
 * Caller should check returned pointer with dm_target_is_valid()
 * to trap I/O beyond end of device.
 */
struct dm_target *dm_table_find_target(struct dm_table *t, sector_t sector)
{
	unsigned int l, n = 0, k = 0;
	sector_t *node;

	if (unlikely(sector >= dm_table_get_size(t)))
		return &t->targets[t->num_targets];

	for (l = 0; l < t->depth; l++) {
		n = get_child(n, k);
		node = get_node(t, l, n);

		for (k = 0; k < KEYS_PER_NODE; k++)
			if (node[k] >= sector)
				break;
	}

	return &t->targets[(KEYS_PER_NODE * n) + k];
}

/*
 * type->iterate_devices() should be called when the sanity check needs to
 * iterate and check all underlying data devices. iterate_devices() will
 * iterate all underlying data devices until it encounters a non-zero return
 * code, returned by whether the input iterate_devices_callout_fn, or
 * iterate_devices() itself internally.
 *
 * For some target type (e.g. dm-stripe), one call of iterate_devices() may
 * iterate multiple underlying devices internally, in which case a non-zero
 * return code returned by iterate_devices_callout_fn will stop the iteration
 * in advance.
 *
 * Cases requiring _any_ underlying device supporting some kind of attribute,
 * should use the iteration structure like dm_table_any_dev_attr(), or call
 * it directly. @func should handle semantics of positive examples, e.g.
 * capable of something.
 *
 * Cases requiring _all_ underlying devices supporting some kind of attribute,
 * should use the iteration structure like dm_table_supports_nowait() or
 * dm_table_supports_discards(). Or introduce dm_table_all_devs_attr() that
 * uses an @anti_func that handle semantics of counter examples, e.g. not
 * capable of something. So: return !dm_table_any_dev_attr(t, anti_func, data);
 */
static bool dm_table_any_dev_attr(struct dm_table *t,
				  iterate_devices_callout_fn func, void *data)
{
	struct dm_target *ti;
	unsigned int i;

	for (i = 0; i < dm_table_get_num_targets(t); i++) {
		ti = dm_table_get_target(t, i);

		if (ti->type->iterate_devices &&
		    ti->type->iterate_devices(ti, func, data))
			return true;
        }

	return false;
}

static int count_device(struct dm_target *ti, struct dm_dev *dev,
			sector_t start, sector_t len, void *data)
{
	unsigned *num_devices = data;

	(*num_devices)++;

	return 0;
}

/*
 * Check whether a table has no data devices attached using each
 * target's iterate_devices method.
 * Returns false if the result is unknown because a target doesn't
 * support iterate_devices.
 */
bool dm_table_has_no_data_devices(struct dm_table *table)
{
	struct dm_target *ti;
	unsigned i, num_devices;

	for (i = 0; i < dm_table_get_num_targets(table); i++) {
		ti = dm_table_get_target(table, i);

		if (!ti->type->iterate_devices)
			return false;

		num_devices = 0;
		ti->type->iterate_devices(ti, count_device, &num_devices);
		if (num_devices)
			return false;
	}

	return true;
}

static int device_not_zoned_model(struct dm_target *ti, struct dm_dev *dev,
				  sector_t start, sector_t len, void *data)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);
	enum blk_zoned_model *zoned_model = data;

	return !q || blk_queue_zoned_model(q) != *zoned_model;
}

static bool dm_table_supports_zoned_model(struct dm_table *t,
					  enum blk_zoned_model zoned_model)
{
	struct dm_target *ti;
	unsigned i;

	for (i = 0; i < dm_table_get_num_targets(t); i++) {
		ti = dm_table_get_target(t, i);

		if (zoned_model == BLK_ZONED_HM &&
		    !dm_target_supports_zoned_hm(ti->type))
			return false;

		if (!ti->type->iterate_devices ||
		    ti->type->iterate_devices(ti, device_not_zoned_model, &zoned_model))
			return false;
	}

	return true;
}

static int device_not_matches_zone_sectors(struct dm_target *ti, struct dm_dev *dev,
					   sector_t start, sector_t len, void *data)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);
	unsigned int *zone_sectors = data;

	return !q || blk_queue_zone_sectors(q) != *zone_sectors;
}

static int validate_hardware_zoned_model(struct dm_table *table,
					 enum blk_zoned_model zoned_model,
					 unsigned int zone_sectors)
{
	if (zoned_model == BLK_ZONED_NONE)
		return 0;

	if (!dm_table_supports_zoned_model(table, zoned_model)) {
		DMERR("%s: zoned model is not consistent across all devices",
		      dm_device_name(table->md));
		return -EINVAL;
	}

	/* Check zone size validity and compatibility */
	if (!zone_sectors || !is_power_of_2(zone_sectors))
		return -EINVAL;

	if (dm_table_any_dev_attr(table, device_not_matches_zone_sectors, &zone_sectors)) {
		DMERR("%s: zone sectors is not consistent across all devices",
		      dm_device_name(table->md));
		return -EINVAL;
	}

	return 0;
}

/*
 * Establish the new table's queue_limits and validate them.
 */
int dm_calculate_queue_limits(struct dm_table *table,
			      struct queue_limits *limits)
{
	struct dm_target *ti;
	struct queue_limits ti_limits;
	unsigned i;
	enum blk_zoned_model zoned_model = BLK_ZONED_NONE;
	unsigned int zone_sectors = 0;

	blk_set_stacking_limits(limits);

	for (i = 0; i < dm_table_get_num_targets(table); i++) {
		blk_set_stacking_limits(&ti_limits);

		ti = dm_table_get_target(table, i);

		if (!ti->type->iterate_devices)
			goto combine_limits;

		/*
		 * Combine queue limits of all the devices this target uses.
		 */
		ti->type->iterate_devices(ti, dm_set_device_limits,
					  &ti_limits);

		if (zoned_model == BLK_ZONED_NONE && ti_limits.zoned != BLK_ZONED_NONE) {
			/*
			 * After stacking all limits, validate all devices
			 * in table support this zoned model and zone sectors.
			 */
			zoned_model = ti_limits.zoned;
			zone_sectors = ti_limits.chunk_sectors;
		}

		/* Set I/O hints portion of queue limits */
		if (ti->type->io_hints)
			ti->type->io_hints(ti, &ti_limits);

		/*
		 * Check each device area is consistent with the target's
		 * overall queue limits.
		 */
		if (ti->type->iterate_devices(ti, device_area_is_invalid,
					      &ti_limits))
			return -EINVAL;

combine_limits:
		/*
		 * Merge this target's queue limits into the overall limits
		 * for the table.
		 */
		if (blk_stack_limits(limits, &ti_limits, 0) < 0)
			DMWARN("%s: adding target device "
			       "(start sect %llu len %llu) "
			       "caused an alignment inconsistency",
			       dm_device_name(table->md),
			       (unsigned long long) ti->begin,
			       (unsigned long long) ti->len);

		/*
		 * FIXME: this should likely be moved to blk_stack_limits(), would
		 * also eliminate limits->zoned stacking hack in dm_set_device_limits()
		 */
		if (limits->zoned == BLK_ZONED_NONE && ti_limits.zoned != BLK_ZONED_NONE) {
			/*
			 * By default, the stacked limits zoned model is set to
			 * BLK_ZONED_NONE in blk_set_stacking_limits(). Update
			 * this model using the first target model reported
			 * that is not BLK_ZONED_NONE. This will be either the
			 * first target device zoned model or the model reported
			 * by the target .io_hints.
			 */
			limits->zoned = ti_limits.zoned;
		}
	}

	/*
	 * Verify that the zoned model and zone sectors, as determined before
	 * any .io_hints override, are the same across all devices in the table.
	 * - this is especially relevant if .io_hints is emulating a disk-managed
	 *   zoned model (aka BLK_ZONED_NONE) on host-managed zoned block devices.
	 * BUT...
	 */
	if (limits->zoned != BLK_ZONED_NONE) {
		/*
		 * ...IF the above limits stacking determined a zoned model
		 * validate that all of the table's devices conform to it.
		 */
		zoned_model = limits->zoned;
		zone_sectors = limits->chunk_sectors;
	}
	if (validate_hardware_zoned_model(table, zoned_model, zone_sectors))
		return -EINVAL;

	return validate_hardware_logical_block_alignment(table, limits);
}

/*
 * Verify that all devices have an integrity profile that matches the
 * DM device's registered integrity profile.  If the profiles don't
 * match then unregister the DM device's integrity profile.
 */
static void dm_table_verify_integrity(struct dm_table *t)
{
	struct gendisk *template_disk = NULL;

	if (t->integrity_added)
		return;

	if (t->integrity_supported) {
		/*
		 * Verify that the original integrity profile
		 * matches all the devices in this table.
		 */
		template_disk = dm_table_get_integrity_disk(t);
		if (template_disk &&
		    blk_integrity_compare(dm_disk(t->md), template_disk) >= 0)
			return;
	}

	if (integrity_profile_exists(dm_disk(t->md))) {
		DMWARN("%s: unable to establish an integrity profile",
		       dm_device_name(t->md));
		blk_integrity_unregister(dm_disk(t->md));
	}
}

#ifdef CONFIG_BLK_INLINE_ENCRYPTION
static int device_intersect_crypto_modes(struct dm_target *ti,
					 struct dm_dev *dev, sector_t start,
					 sector_t len, void *data)
{
	struct keyslot_manager *parent = data;
	struct keyslot_manager *child = bdev_get_queue(dev->bdev)->ksm;

	keyslot_manager_intersect_modes(parent, child);
	return 0;
}

/*
 * Update the inline crypto modes supported by 'q->ksm' to be the intersection
 * of the modes supported by all targets in the table.
 *
 * For any mode to be supported at all, all targets must have explicitly
 * declared that they can pass through inline crypto support.  For a particular
 * mode to be supported, all underlying devices must also support it.
 *
 * Assume that 'q->ksm' initially declares all modes to be supported.
 */
static void dm_calculate_supported_crypto_modes(struct dm_table *t,
						struct request_queue *q)
{
	struct dm_target *ti;
	unsigned int i;

	for (i = 0; i < dm_table_get_num_targets(t); i++) {
		ti = dm_table_get_target(t, i);

		if (!ti->may_passthrough_inline_crypto) {
			keyslot_manager_intersect_modes(q->ksm, NULL);
			return;
		}
		if (!ti->type->iterate_devices)
			continue;
		ti->type->iterate_devices(ti, device_intersect_crypto_modes,
					  q->ksm);
	}
}
#else /* CONFIG_BLK_INLINE_ENCRYPTION */
static inline void dm_calculate_supported_crypto_modes(struct dm_table *t,
						       struct request_queue *q)
{
}
#endif /* !CONFIG_BLK_INLINE_ENCRYPTION */

static int device_flush_capable(struct dm_target *ti, struct dm_dev *dev,
				sector_t start, sector_t len, void *data)
{
	unsigned long flush = (unsigned long) data;
	struct request_queue *q = bdev_get_queue(dev->bdev);

	return q && (q->queue_flags & flush);
}

static bool dm_table_supports_flush(struct dm_table *t, unsigned long flush)
{
	struct dm_target *ti;
	unsigned i;

	/*
	 * Require at least one underlying device to support flushes.
	 * t->devices includes internal dm devices such as mirror logs
	 * so we need to use iterate_devices here, which targets
	 * supporting flushes must provide.
	 */
	for (i = 0; i < dm_table_get_num_targets(t); i++) {
		ti = dm_table_get_target(t, i);

		if (!ti->num_flush_bios)
			continue;

		if (ti->flush_supported)
			return true;

		if (ti->type->iterate_devices &&
		    ti->type->iterate_devices(ti, device_flush_capable, (void *) flush))
			return true;
	}

	return false;
}

static int device_dax_write_cache_enabled(struct dm_target *ti,
					  struct dm_dev *dev, sector_t start,
					  sector_t len, void *data)
{
	struct dax_device *dax_dev = dev->dax_dev;

	if (!dax_dev)
		return false;

	if (dax_write_cache_enabled(dax_dev))
		return true;
	return false;
}

static int device_is_rotational(struct dm_target *ti, struct dm_dev *dev,
				sector_t start, sector_t len, void *data)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);

	return q && !blk_queue_nonrot(q);
}

static int device_is_not_random(struct dm_target *ti, struct dm_dev *dev,
			     sector_t start, sector_t len, void *data)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);

	return q && !blk_queue_add_random(q);
}

static int queue_no_sg_merge(struct dm_target *ti, struct dm_dev *dev,
			     sector_t start, sector_t len, void *data)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);

	return q && test_bit(QUEUE_FLAG_NO_SG_MERGE, &q->queue_flags);
}

static int device_not_write_same_capable(struct dm_target *ti, struct dm_dev *dev,
					 sector_t start, sector_t len, void *data)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);

	return q && !q->limits.max_write_same_sectors;
}

static bool dm_table_supports_write_same(struct dm_table *t)
{
	struct dm_target *ti;
	unsigned i;

	for (i = 0; i < dm_table_get_num_targets(t); i++) {
		ti = dm_table_get_target(t, i);

		if (!ti->num_write_same_bios)
			return false;

		if (!ti->type->iterate_devices ||
		    ti->type->iterate_devices(ti, device_not_write_same_capable, NULL))
			return false;
	}

	return true;
}

static int device_not_write_zeroes_capable(struct dm_target *ti, struct dm_dev *dev,
					   sector_t start, sector_t len, void *data)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);

	return q && !q->limits.max_write_zeroes_sectors;
}

static bool dm_table_supports_write_zeroes(struct dm_table *t)
{
	struct dm_target *ti;
	unsigned i = 0;

	while (i < dm_table_get_num_targets(t)) {
		ti = dm_table_get_target(t, i++);

		if (!ti->num_write_zeroes_bios)
			return false;

		if (!ti->type->iterate_devices ||
		    ti->type->iterate_devices(ti, device_not_write_zeroes_capable, NULL))
			return false;
	}

	return true;
}

static int device_not_discard_capable(struct dm_target *ti, struct dm_dev *dev,
				      sector_t start, sector_t len, void *data)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);

	return q && !blk_queue_discard(q);
}

static bool dm_table_supports_discards(struct dm_table *t)
{
	struct dm_target *ti;
	unsigned i;

	for (i = 0; i < dm_table_get_num_targets(t); i++) {
		ti = dm_table_get_target(t, i);

		if (!ti->num_discard_bios)
			return false;

		/*
		 * Either the target provides discard support (as implied by setting
		 * 'discards_supported') or it relies on _all_ data devices having
		 * discard support.
		 */
		if (!ti->discards_supported &&
		    (!ti->type->iterate_devices ||
		     ti->type->iterate_devices(ti, device_not_discard_capable, NULL)))
			return false;
	}

	return true;
}

static int device_requires_stable_pages(struct dm_target *ti,
					struct dm_dev *dev, sector_t start,
					sector_t len, void *data)
{
	struct request_queue *q = bdev_get_queue(dev->bdev);

	return q && bdi_cap_stable_pages_required(q->backing_dev_info);
}

void dm_table_set_restrictions(struct dm_table *t, struct request_queue *q,
			       struct queue_limits *limits)
{
	bool wc = false, fua = false;

	/*
	 * Copy table's limits to the DM device's request_queue
	 */
	q->limits = *limits;

	if (!dm_table_supports_discards(t))
		queue_flag_clear_unlocked(QUEUE_FLAG_DISCARD, q);
	else
		queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, q);

	if (dm_table_supports_flush(t, (1UL << QUEUE_FLAG_WC))) {
		wc = true;
		if (dm_table_supports_flush(t, (1UL << QUEUE_FLAG_FUA)))
			fua = true;
	}
	blk_queue_write_cache(q, wc, fua);

	if (dm_table_supports_dax(t))
		queue_flag_set_unlocked(QUEUE_FLAG_DAX, q);
	else
		queue_flag_clear_unlocked(QUEUE_FLAG_DAX, q);

	if (dm_table_any_dev_attr(t, device_dax_write_cache_enabled, NULL))
		dax_write_cache(t->md->dax_dev, true);

	/* Ensure that all underlying devices are non-rotational. */
	if (dm_table_any_dev_attr(t, device_is_rotational, NULL))
		queue_flag_clear_unlocked(QUEUE_FLAG_NONROT, q);
	else
		queue_flag_set_unlocked(QUEUE_FLAG_NONROT, q);

	if (!dm_table_supports_write_same(t))
		q->limits.max_write_same_sectors = 0;
	if (!dm_table_supports_write_zeroes(t))
		q->limits.max_write_zeroes_sectors = 0;

	if (dm_table_any_dev_attr(t, queue_no_sg_merge, NULL))
		queue_flag_set_unlocked(QUEUE_FLAG_NO_SG_MERGE, q);
	else
		queue_flag_clear_unlocked(QUEUE_FLAG_NO_SG_MERGE, q);

	dm_table_verify_integrity(t);

	dm_calculate_supported_crypto_modes(t, q);

	/*
	 * Some devices don't use blk_integrity but still want stable pages
	 * because they do their own checksumming.
	 * If any underlying device requires stable pages, a table must require
	 * them as well.  Only targets that support iterate_devices are considered:
	 * don't want error, zero, etc to require stable pages.
	 */
	if (dm_table_any_dev_attr(t, device_requires_stable_pages, NULL))
		q->backing_dev_info->capabilities |= BDI_CAP_STABLE_WRITES;
	else
		q->backing_dev_info->capabilities &= ~BDI_CAP_STABLE_WRITES;

	/*
	 * Determine whether or not this queue's I/O timings contribute
	 * to the entropy pool, Only request-based targets use this.
	 * Clear QUEUE_FLAG_ADD_RANDOM if any underlying device does not
	 * have it set.
	 */
	if (blk_queue_add_random(q) &&
	    dm_table_any_dev_attr(t, device_is_not_random, NULL))
		queue_flag_clear_unlocked(QUEUE_FLAG_ADD_RANDOM, q);

	/*
	 * QUEUE_FLAG_STACKABLE must be set after all queue settings are
	 * visible to other CPUs because, once the flag is set, incoming bios
	 * are processed by request-based dm, which refers to the queue
	 * settings.
	 * Until the flag set, bios are passed to bio-based dm and queued to
	 * md->deferred where queue settings are not needed yet.
	 * Those bios are passed to request-based dm at the resume time.
	 */
	smp_mb();
	if (dm_table_request_based(t))
		queue_flag_set_unlocked(QUEUE_FLAG_STACKABLE, q);

	/* io_pages is used for readahead */
	q->backing_dev_info->io_pages = limits->max_sectors >> (PAGE_SHIFT - 9);
}

unsigned int dm_table_get_num_targets(struct dm_table *t)
{
	return t->num_targets;
}

struct list_head *dm_table_get_devices(struct dm_table *t)
{
	return &t->devices;
}

fmode_t dm_table_get_mode(struct dm_table *t)
{
	return t->mode;
}
EXPORT_SYMBOL(dm_table_get_mode);

enum suspend_mode {
	PRESUSPEND,
	PRESUSPEND_UNDO,
	POSTSUSPEND,
};

static void suspend_targets(struct dm_table *t, enum suspend_mode mode)
{
	int i = t->num_targets;
	struct dm_target *ti = t->targets;

	lockdep_assert_held(&t->md->suspend_lock);

	while (i--) {
		switch (mode) {
		case PRESUSPEND:
			if (ti->type->presuspend)
				ti->type->presuspend(ti);
			break;
		case PRESUSPEND_UNDO:
			if (ti->type->presuspend_undo)
				ti->type->presuspend_undo(ti);
			break;
		case POSTSUSPEND:
			if (ti->type->postsuspend)
				ti->type->postsuspend(ti);
			break;
		}
		ti++;
	}
}

void dm_table_presuspend_targets(struct dm_table *t)
{
	if (!t)
		return;

	suspend_targets(t, PRESUSPEND);
}

void dm_table_presuspend_undo_targets(struct dm_table *t)
{
	if (!t)
		return;

	suspend_targets(t, PRESUSPEND_UNDO);
}

void dm_table_postsuspend_targets(struct dm_table *t)
{
	if (!t)
		return;

	suspend_targets(t, POSTSUSPEND);
}

int dm_table_resume_targets(struct dm_table *t)
{
	int i, r = 0;

	lockdep_assert_held(&t->md->suspend_lock);

	for (i = 0; i < t->num_targets; i++) {
		struct dm_target *ti = t->targets + i;

		if (!ti->type->preresume)
			continue;

		r = ti->type->preresume(ti);
		if (r) {
			DMERR("%s: %s: preresume failed, error = %d",
			      dm_device_name(t->md), ti->type->name, r);
			return r;
		}
	}

	for (i = 0; i < t->num_targets; i++) {
		struct dm_target *ti = t->targets + i;

		if (ti->type->resume)
			ti->type->resume(ti);
	}

	return 0;
}

void dm_table_add_target_callbacks(struct dm_table *t, struct dm_target_callbacks *cb)
{
	list_add(&cb->list, &t->target_callbacks);
}
EXPORT_SYMBOL_GPL(dm_table_add_target_callbacks);

int dm_table_any_congested(struct dm_table *t, int bdi_bits)
{
	struct dm_dev_internal *dd;
	struct list_head *devices = dm_table_get_devices(t);
	struct dm_target_callbacks *cb;
	int r = 0;

	list_for_each_entry(dd, devices, list) {
		struct request_queue *q = bdev_get_queue(dd->dm_dev->bdev);
		char b[BDEVNAME_SIZE];

		if (likely(q))
			r |= bdi_congested(q->backing_dev_info, bdi_bits);
		else
			DMWARN_LIMIT("%s: any_congested: nonexistent device %s",
				     dm_device_name(t->md),
				     bdevname(dd->dm_dev->bdev, b));
	}

	list_for_each_entry(cb, &t->target_callbacks, list)
		if (cb->congested_fn)
			r |= cb->congested_fn(cb, bdi_bits);

	return r;
}

struct mapped_device *dm_table_get_md(struct dm_table *t)
{
	return t->md;
}
EXPORT_SYMBOL(dm_table_get_md);

void dm_table_run_md_queue_async(struct dm_table *t)
{
	struct mapped_device *md;
	struct request_queue *queue;
	unsigned long flags;

	if (!dm_table_request_based(t))
		return;

	md = dm_table_get_md(t);
	queue = dm_get_md_queue(md);
	if (queue) {
		if (queue->mq_ops)
			blk_mq_run_hw_queues(queue, true);
		else {
			spin_lock_irqsave(queue->queue_lock, flags);
			blk_run_queue_async(queue);
			spin_unlock_irqrestore(queue->queue_lock, flags);
		}
	}
}
EXPORT_SYMBOL(dm_table_run_md_queue_async);

