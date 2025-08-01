/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_DMA_MAPPING_H
#define _LINUX_DMA_MAPPING_H

#include <linux/sizes.h>
#include <linux/string.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/dma-debug.h>
#include <linux/dma-direction.h>
#include <linux/scatterlist.h>
#include <linux/bug.h>
#include <linux/mem_encrypt.h>

/**
 * List of possible attributes associated with a DMA mapping. The semantics
 * of each attribute should be defined in Documentation/DMA-attributes.txt.
 *
 * DMA_ATTR_WRITE_BARRIER: DMA to a memory region with this attribute
 * forces all pending DMA writes to complete.
 */
#define DMA_ATTR_WRITE_BARRIER		(1UL << 0)
/*
 * DMA_ATTR_WEAK_ORDERING: Specifies that reads and writes to the mapping
 * may be weakly ordered, that is that reads and writes may pass each other.
 */
#define DMA_ATTR_WEAK_ORDERING		(1UL << 1)
/*
 * DMA_ATTR_WRITE_COMBINE: Specifies that writes to the mapping may be
 * buffered to improve performance.
 */
#define DMA_ATTR_WRITE_COMBINE		(1UL << 2)
/*
 * DMA_ATTR_NON_CONSISTENT: Lets the platform to choose to return either
 * consistent or non-consistent memory as it sees fit.
 */
#define DMA_ATTR_NON_CONSISTENT		(1UL << 3)
/*
 * DMA_ATTR_NO_KERNEL_MAPPING: Lets the platform to avoid creating a kernel
 * virtual mapping for the allocated buffer.
 */
#define DMA_ATTR_NO_KERNEL_MAPPING	(1UL << 4)
/*
 * DMA_ATTR_SKIP_CPU_SYNC: Allows platform code to skip synchronization of
 * the CPU cache for the given buffer assuming that it has been already
 * transferred to 'device' domain.
 */
#define DMA_ATTR_SKIP_CPU_SYNC		(1UL << 5)
/*
 * DMA_ATTR_FORCE_CONTIGUOUS: Forces contiguous allocation of the buffer
 * in physical memory.
 */
#define DMA_ATTR_FORCE_CONTIGUOUS	(1UL << 6)
/*
 * DMA_ATTR_ALLOC_SINGLE_PAGES: This is a hint to the DMA-mapping subsystem
 * that it's probably not worth the time to try to allocate memory to in a way
 * that gives better TLB efficiency.
 */
#define DMA_ATTR_ALLOC_SINGLE_PAGES	(1UL << 7)
/*
 * DMA_ATTR_NO_WARN: This tells the DMA-mapping subsystem to suppress
 * allocation failure reports (similarly to __GFP_NOWARN).
 */
#define DMA_ATTR_NO_WARN	(1UL << 8)
/*
 * DMA_ATTR_STRONGLY_ORDERED: Specifies that accesses to the mapping must
 * not be buffered, reordered, merged with other accesses, or unaligned.
 * No speculative access may occur in this mapping.
 */
#define DMA_ATTR_STRONGLY_ORDERED	(1UL << 9)
/*
 * DMA_ATTR_SKIP_ZEROING: Do not zero mapping.
 */
#define DMA_ATTR_SKIP_ZEROING		(1UL << 10)
/*
 * DMA_ATTR_NO_DELAYED_UNMAP: Used by msm specific lazy mapping to indicate
 * that the mapping can be freed on unmap, rather than when the ion_buffer
 * is freed.
 */
#define DMA_ATTR_NO_DELAYED_UNMAP	(1UL << 11)
/*
 * DMA_ATTR_EXEC_MAPPING: The mapping has executable permissions.
 */
#define DMA_ATTR_EXEC_MAPPING		(1UL << 12)
/*
 * DMA_ATTR_IOMMU_USE_UPSTREAM_HINT: Normally an smmu will override any bus
 * attributes (i.e cacheablilty) provided by the client device. Some hardware
 * may be designed to use the original attributes instead.
 */
#define DMA_ATTR_IOMMU_USE_UPSTREAM_HINT	(1UL << 13)
/*
 * When passed to a DMA map call the DMA_ATTR_FORCE_COHERENT DMA
 * attribute can be used to force a buffer to be mapped as IO coherent.
 */
#define DMA_ATTR_FORCE_COHERENT			(1UL << 14)
/*
 * When passed to a DMA map call the DMA_ATTR_FORCE_NON_COHERENT DMA
 * attribute can be used to force a buffer to not be mapped as IO
 * coherent.
 */
#define DMA_ATTR_FORCE_NON_COHERENT		(1UL << 15)
/*
 * DMA_ATTR_DELAYED_UNMAP: Used by ION, it will ensure that mappings are not
 * removed on unmap but instead are removed when the ion_buffer is freed.
 */
#define DMA_ATTR_DELAYED_UNMAP		(1UL << 16)

/*
 * DMA_ATTR_PRIVILEGED: used to indicate that the buffer is fully
 * accessible at an elevated privilege level (and ideally inaccessible or
 * at least read-only at lesser-privileged levels).
 */
#define DMA_ATTR_PRIVILEGED		(1UL << 17)

/*
 * DMA_ATTR_IOMMU_USE_LLC_NWA: Overrides the bus attributes to use the System
 * Cache(LLC) with allocation policy as Inner Non-Cacheable, Outer Cacheable:
 * Write-Back, Read-Allocate, No Write-Allocate policy.
 */
#define DMA_ATTR_IOMMU_USE_LLC_NWA	(1UL << 18)

#define DMA_ERROR_CODE       (~(dma_addr_t)0)

/*
 * A dma_addr_t can hold any valid DMA or bus address for the platform.
 * It can be given to a device to use as a DMA source or target.  A CPU cannot
 * reference a dma_addr_t directly because there may be translation between
 * its physical address space and the bus address space.
 */
struct dma_map_ops {
	void* (*alloc)(struct device *dev, size_t size,
				dma_addr_t *dma_handle, gfp_t gfp,
				unsigned long attrs);
	void (*free)(struct device *dev, size_t size,
			      void *vaddr, dma_addr_t dma_handle,
			      unsigned long attrs);
	int (*mmap)(struct device *, struct vm_area_struct *,
			  void *, dma_addr_t, size_t,
			  unsigned long attrs);

	int (*get_sgtable)(struct device *dev, struct sg_table *sgt, void *,
			   dma_addr_t, size_t, unsigned long attrs);

	dma_addr_t (*map_page)(struct device *dev, struct page *page,
			       unsigned long offset, size_t size,
			       enum dma_data_direction dir,
			       unsigned long attrs);
	void (*unmap_page)(struct device *dev, dma_addr_t dma_handle,
			   size_t size, enum dma_data_direction dir,
			   unsigned long attrs);
	/*
	 * map_sg returns 0 on error and a value > 0 on success.
	 * It should never return a value < 0.
	 */
	int (*map_sg)(struct device *dev, struct scatterlist *sg,
		      int nents, enum dma_data_direction dir,
		      unsigned long attrs);
	void (*unmap_sg)(struct device *dev,
			 struct scatterlist *sg, int nents,
			 enum dma_data_direction dir,
			 unsigned long attrs);
	dma_addr_t (*map_resource)(struct device *dev, phys_addr_t phys_addr,
			       size_t size, enum dma_data_direction dir,
			       unsigned long attrs);
	void (*unmap_resource)(struct device *dev, dma_addr_t dma_handle,
			   size_t size, enum dma_data_direction dir,
			   unsigned long attrs);
	void (*sync_single_for_cpu)(struct device *dev,
				    dma_addr_t dma_handle, size_t size,
				    enum dma_data_direction dir);
	void (*sync_single_for_device)(struct device *dev,
				       dma_addr_t dma_handle, size_t size,
				       enum dma_data_direction dir);
	void (*sync_sg_for_cpu)(struct device *dev,
				struct scatterlist *sg, int nents,
				enum dma_data_direction dir);
	void (*sync_sg_for_device)(struct device *dev,
				   struct scatterlist *sg, int nents,
				   enum dma_data_direction dir);
	int (*mapping_error)(struct device *dev, dma_addr_t dma_addr);
	int (*dma_supported)(struct device *dev, u64 mask);
	int (*set_dma_mask)(struct device *dev, u64 mask);
	void *(*remap)(struct device *dev, void *cpu_addr, dma_addr_t handle,
			size_t size, unsigned long attrs);
	void (*unremap)(struct device *dev, void *remapped_address,
			size_t size);
#ifdef ARCH_HAS_DMA_GET_REQUIRED_MASK
	u64 (*get_required_mask)(struct device *dev);
#endif
	int is_phys;
};

extern const struct dma_map_ops dma_noop_ops;
extern const struct dma_map_ops dma_virt_ops;

#define DMA_BIT_MASK(n)	(((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))

#define DMA_MASK_NONE	0x0ULL

static inline int valid_dma_direction(int dma_direction)
{
	return ((dma_direction == DMA_BIDIRECTIONAL) ||
		(dma_direction == DMA_TO_DEVICE) ||
		(dma_direction == DMA_FROM_DEVICE));
}

static inline int is_device_dma_capable(struct device *dev)
{
	return dev->dma_mask != NULL && *dev->dma_mask != DMA_MASK_NONE;
}

#ifdef CONFIG_HAVE_GENERIC_DMA_COHERENT
/*
 * These three functions are only for dma allocator.
 * Don't use them in device drivers.
 */
int dma_alloc_from_dev_coherent(struct device *dev, ssize_t size,
				       dma_addr_t *dma_handle, void **ret);
int dma_release_from_dev_coherent(struct device *dev, int order, void *vaddr);

int dma_mmap_from_dev_coherent(struct device *dev, struct vm_area_struct *vma,
			    void *cpu_addr, size_t size, int *ret);

void *dma_alloc_from_global_coherent(ssize_t size, dma_addr_t *dma_handle);
int dma_release_from_global_coherent(int order, void *vaddr);
int dma_mmap_from_global_coherent(struct vm_area_struct *vma, void *cpu_addr,
				  size_t size, int *ret);

#else
#define dma_alloc_from_dev_coherent(dev, size, handle, ret) (0)
#define dma_release_from_dev_coherent(dev, order, vaddr) (0)
#define dma_mmap_from_dev_coherent(dev, vma, vaddr, order, ret) (0)

static inline void *dma_alloc_from_global_coherent(ssize_t size,
						   dma_addr_t *dma_handle)
{
	return NULL;
}

static inline int dma_release_from_global_coherent(int order, void *vaddr)
{
	return 0;
}

static inline int dma_mmap_from_global_coherent(struct vm_area_struct *vma,
						void *cpu_addr, size_t size,
						int *ret)
{
	return 0;
}
#endif /* CONFIG_HAVE_GENERIC_DMA_COHERENT */

#ifdef CONFIG_HAS_DMA
#include <asm/dma-mapping.h>
static inline const struct dma_map_ops *get_dma_ops(struct device *dev)
{
	if (dev && dev->dma_ops)
		return dev->dma_ops;
	return get_arch_dma_ops(dev ? dev->bus : NULL);
}

static inline void set_dma_ops(struct device *dev,
			       const struct dma_map_ops *dma_ops)
{
	dev->dma_ops = dma_ops;
}
#else
/*
 * Define the dma api to allow compilation but not linking of
 * dma dependent code.  Code that depends on the dma-mapping
 * API needs to set 'depends on HAS_DMA' in its Kconfig
 */
extern const struct dma_map_ops bad_dma_ops;
static inline const struct dma_map_ops *get_dma_ops(struct device *dev)
{
	return &bad_dma_ops;
}
#endif

static inline dma_addr_t dma_map_single_attrs(struct device *dev, void *ptr,
					      size_t size,
					      enum dma_data_direction dir,
					      unsigned long attrs)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);
	dma_addr_t addr;

	BUG_ON(!valid_dma_direction(dir));
	addr = ops->map_page(dev, virt_to_page(ptr),
			     offset_in_page(ptr), size,
			     dir, attrs);
	debug_dma_map_page(dev, virt_to_page(ptr),
			   offset_in_page(ptr), size,
			   dir, addr, true);
	return addr;
}

static inline void dma_unmap_single_attrs(struct device *dev, dma_addr_t addr,
					  size_t size,
					  enum dma_data_direction dir,
					  unsigned long attrs)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->unmap_page)
		ops->unmap_page(dev, addr, size, dir, attrs);
	debug_dma_unmap_page(dev, addr, size, dir, true);
}

/*
 * dma_maps_sg_attrs returns 0 on error and > 0 on success.
 * It should never return a value < 0.
 */
static inline int dma_map_sg_attrs(struct device *dev, struct scatterlist *sg,
				   int nents, enum dma_data_direction dir,
				   unsigned long attrs)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);
	int ents;

	BUG_ON(!valid_dma_direction(dir));
	ents = ops->map_sg(dev, sg, nents, dir, attrs);
	BUG_ON(ents < 0);
	debug_dma_map_sg(dev, sg, nents, ents, dir);

	return ents;
}

static inline void dma_unmap_sg_attrs(struct device *dev, struct scatterlist *sg,
				      int nents, enum dma_data_direction dir,
				      unsigned long attrs)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!valid_dma_direction(dir));
	debug_dma_unmap_sg(dev, sg, nents, dir);
	if (ops->unmap_sg)
		ops->unmap_sg(dev, sg, nents, dir, attrs);
}

static inline dma_addr_t dma_map_page_attrs(struct device *dev,
					    struct page *page,
					    size_t offset, size_t size,
					    enum dma_data_direction dir,
					    unsigned long attrs)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);
	dma_addr_t addr;

	BUG_ON(!valid_dma_direction(dir));
	addr = ops->map_page(dev, page, offset, size, dir, attrs);
	debug_dma_map_page(dev, page, offset, size, dir, addr, false);

	return addr;
}

static inline void dma_unmap_page_attrs(struct device *dev,
					dma_addr_t addr, size_t size,
					enum dma_data_direction dir,
					unsigned long attrs)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->unmap_page)
		ops->unmap_page(dev, addr, size, dir, attrs);
	debug_dma_unmap_page(dev, addr, size, dir, false);
}

static inline dma_addr_t dma_map_resource(struct device *dev,
					  phys_addr_t phys_addr,
					  size_t size,
					  enum dma_data_direction dir,
					  unsigned long attrs)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);
	dma_addr_t addr;

	BUG_ON(!valid_dma_direction(dir));

	/* Don't allow RAM to be mapped */
	BUG_ON(pfn_valid(PHYS_PFN(phys_addr)));

	addr = phys_addr;
	if (ops->map_resource)
		addr = ops->map_resource(dev, phys_addr, size, dir, attrs);

	debug_dma_map_resource(dev, phys_addr, size, dir, addr);

	return addr;
}

static inline void dma_unmap_resource(struct device *dev, dma_addr_t addr,
				      size_t size, enum dma_data_direction dir,
				      unsigned long attrs)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->unmap_resource)
		ops->unmap_resource(dev, addr, size, dir, attrs);
	debug_dma_unmap_resource(dev, addr, size, dir);
}

static inline void dma_sync_single_for_cpu(struct device *dev, dma_addr_t addr,
					   size_t size,
					   enum dma_data_direction dir)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->sync_single_for_cpu)
		ops->sync_single_for_cpu(dev, addr, size, dir);
	debug_dma_sync_single_for_cpu(dev, addr, size, dir);
}

static inline void dma_sync_single_for_device(struct device *dev,
					      dma_addr_t addr, size_t size,
					      enum dma_data_direction dir)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->sync_single_for_device)
		ops->sync_single_for_device(dev, addr, size, dir);
	debug_dma_sync_single_for_device(dev, addr, size, dir);
}

static inline void dma_sync_single_range_for_cpu(struct device *dev,
						 dma_addr_t addr,
						 unsigned long offset,
						 size_t size,
						 enum dma_data_direction dir)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->sync_single_for_cpu)
		ops->sync_single_for_cpu(dev, addr + offset, size, dir);
	debug_dma_sync_single_range_for_cpu(dev, addr, offset, size, dir);
}

static inline void dma_sync_single_range_for_device(struct device *dev,
						    dma_addr_t addr,
						    unsigned long offset,
						    size_t size,
						    enum dma_data_direction dir)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->sync_single_for_device)
		ops->sync_single_for_device(dev, addr + offset, size, dir);
	debug_dma_sync_single_range_for_device(dev, addr, offset, size, dir);
}

static inline void
dma_sync_sg_for_cpu(struct device *dev, struct scatterlist *sg,
		    int nelems, enum dma_data_direction dir)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->sync_sg_for_cpu)
		ops->sync_sg_for_cpu(dev, sg, nelems, dir);
	debug_dma_sync_sg_for_cpu(dev, sg, nelems, dir);
}

static inline void
dma_sync_sg_for_device(struct device *dev, struct scatterlist *sg,
		       int nelems, enum dma_data_direction dir)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!valid_dma_direction(dir));
	if (ops->sync_sg_for_device)
		ops->sync_sg_for_device(dev, sg, nelems, dir);
	debug_dma_sync_sg_for_device(dev, sg, nelems, dir);

}

#define dma_map_single(d, a, s, r) dma_map_single_attrs(d, a, s, r, 0)
#define dma_unmap_single(d, a, s, r) dma_unmap_single_attrs(d, a, s, r, 0)
#define dma_map_sg(d, s, n, r) dma_map_sg_attrs(d, s, n, r, 0)
#define dma_unmap_sg(d, s, n, r) dma_unmap_sg_attrs(d, s, n, r, 0)
#define dma_map_page(d, p, o, s, r) dma_map_page_attrs(d, p, o, s, r, 0)
#define dma_unmap_page(d, a, s, r) dma_unmap_page_attrs(d, a, s, r, 0)

extern int dma_common_mmap(struct device *dev, struct vm_area_struct *vma,
			   void *cpu_addr, dma_addr_t dma_addr, size_t size);

void *dma_common_contiguous_remap(struct page *page, size_t size,
			unsigned long vm_flags,
			pgprot_t prot, const void *caller);

void *dma_common_pages_remap(struct page **pages, size_t size,
			unsigned long vm_flags, pgprot_t prot,
			const void *caller);
void dma_common_free_remap(void *cpu_addr, size_t size, unsigned long vm_flags,
			   bool nowarn);

/**
 * dma_mmap_attrs - map a coherent DMA allocation into user space
 * @dev: valid struct device pointer, or NULL for ISA and EISA-like devices
 * @vma: vm_area_struct describing requested user mapping
 * @cpu_addr: kernel CPU-view address returned from dma_alloc_attrs
 * @handle: device-view address returned from dma_alloc_attrs
 * @size: size of memory originally requested in dma_alloc_attrs
 * @attrs: attributes of mapping properties requested in dma_alloc_attrs
 *
 * Map a coherent DMA buffer previously allocated by dma_alloc_attrs
 * into user space.  The coherent DMA buffer must not be freed by the
 * driver until the user space mapping has been released.
 */
static inline int
dma_mmap_attrs(struct device *dev, struct vm_area_struct *vma, void *cpu_addr,
	       dma_addr_t dma_addr, size_t size, unsigned long attrs)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);
	BUG_ON(!ops);
	if (ops->mmap)
		return ops->mmap(dev, vma, cpu_addr, dma_addr, size, attrs);
	return dma_common_mmap(dev, vma, cpu_addr, dma_addr, size);
}

#define dma_mmap_coherent(d, v, c, h, s) dma_mmap_attrs(d, v, c, h, s, 0)

int
dma_common_get_sgtable(struct device *dev, struct sg_table *sgt,
		       void *cpu_addr, dma_addr_t dma_addr, size_t size);

static inline int
dma_get_sgtable_attrs(struct device *dev, struct sg_table *sgt, void *cpu_addr,
		      dma_addr_t dma_addr, size_t size,
		      unsigned long attrs)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);
	BUG_ON(!ops);
	if (ops->get_sgtable)
		return ops->get_sgtable(dev, sgt, cpu_addr, dma_addr, size,
					attrs);
	return dma_common_get_sgtable(dev, sgt, cpu_addr, dma_addr, size);
}

#define dma_get_sgtable(d, t, v, h, s) dma_get_sgtable_attrs(d, t, v, h, s, 0)

#ifndef arch_dma_alloc_attrs
#define arch_dma_alloc_attrs(dev, flag)	(true)
#endif

static inline void *dma_alloc_attrs(struct device *dev, size_t size,
				       dma_addr_t *dma_handle, gfp_t flag,
				       unsigned long attrs)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);
	void *cpu_addr;

	BUG_ON(!ops);

	if (dma_alloc_from_dev_coherent(dev, size, dma_handle, &cpu_addr))
		return cpu_addr;

	if (!arch_dma_alloc_attrs(&dev, &flag))
		return NULL;
	if (!ops->alloc)
		return NULL;

	cpu_addr = ops->alloc(dev, size, dma_handle, flag, attrs);
	debug_dma_alloc_coherent(dev, size, *dma_handle, cpu_addr);
	return cpu_addr;
}

static inline void dma_free_attrs(struct device *dev, size_t size,
				     void *cpu_addr, dma_addr_t dma_handle,
				     unsigned long attrs)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);

	BUG_ON(!ops);
	WARN_ON(irqs_disabled());

	if (dma_release_from_dev_coherent(dev, get_order(size), cpu_addr))
		return;

	if (!ops->free || !cpu_addr)
		return;

	debug_dma_free_coherent(dev, size, cpu_addr, dma_handle);
	ops->free(dev, size, cpu_addr, dma_handle, attrs);
}

static inline void *dma_alloc_coherent(struct device *dev, size_t size,
		dma_addr_t *dma_handle, gfp_t flag)
{
	return dma_alloc_attrs(dev, size, dma_handle, flag, 0);
}

static inline void dma_free_coherent(struct device *dev, size_t size,
		void *cpu_addr, dma_addr_t dma_handle)
{
	return dma_free_attrs(dev, size, cpu_addr, dma_handle, 0);
}

static inline int dma_mapping_error(struct device *dev, dma_addr_t dma_addr)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);

	debug_dma_mapping_error(dev, dma_addr);
	if (ops->mapping_error)
		return ops->mapping_error(dev, dma_addr);
	return 0;
}

static inline void dma_check_mask(struct device *dev, u64 mask)
{
	if (sme_active() && (mask < (((u64)sme_get_me_mask() << 1) - 1)))
		dev_warn(dev, "SME is active, device will require DMA bounce buffers\n");
}

static inline int dma_supported(struct device *dev, u64 mask)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);

	if (!ops)
		return 0;
	if (!ops->dma_supported)
		return 1;
	return ops->dma_supported(dev, mask);
}

#ifndef HAVE_ARCH_DMA_SET_MASK
static inline int dma_set_mask(struct device *dev, u64 mask)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);

	if (ops->set_dma_mask)
		return ops->set_dma_mask(dev, mask);

	if (!dev->dma_mask || !dma_supported(dev, mask))
		return -EIO;

	dma_check_mask(dev, mask);

	*dev->dma_mask = mask;
	return 0;
}
#endif
static inline void *dma_remap(struct device *dev, void *cpu_addr,
		dma_addr_t dma_handle, size_t size, unsigned long attrs)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);

	if (!ops->remap) {
		WARN_ONCE(1, "Remap function not implemented for %pS\n",
				ops->remap);
		return NULL;
	}

	return ops->remap(dev, cpu_addr, dma_handle, size, attrs);
}


static inline void dma_unremap(struct device *dev, void *remapped_addr,
				size_t size)
{
	const struct dma_map_ops *ops = get_dma_ops(dev);

	if (!ops->unremap) {
		WARN_ONCE(1, "unremap function not implemented for %pS\n",
				ops->unremap);
		return;
	}

	return ops->unremap(dev, remapped_addr, size);
}


static inline u64 dma_get_mask(struct device *dev)
{
	if (dev && dev->dma_mask && *dev->dma_mask)
		return *dev->dma_mask;
	return DMA_BIT_MASK(32);
}

#ifdef CONFIG_ARCH_HAS_DMA_SET_COHERENT_MASK
int dma_set_coherent_mask(struct device *dev, u64 mask);
#else
static inline int dma_set_coherent_mask(struct device *dev, u64 mask)
{
	if (!dma_supported(dev, mask))
		return -EIO;

	dma_check_mask(dev, mask);

	dev->coherent_dma_mask = mask;
	return 0;
}
#endif

/*
 * Set both the DMA mask and the coherent DMA mask to the same thing.
 * Note that we don't check the return value from dma_set_coherent_mask()
 * as the DMA API guarantees that the coherent DMA mask can be set to
 * the same or smaller than the streaming DMA mask.
 */
static inline int dma_set_mask_and_coherent(struct device *dev, u64 mask)
{
	int rc = dma_set_mask(dev, mask);
	if (rc == 0)
		dma_set_coherent_mask(dev, mask);
	return rc;
}

/*
 * Similar to the above, except it deals with the case where the device
 * does not have dev->dma_mask appropriately setup.
 */
static inline int dma_coerce_mask_and_coherent(struct device *dev, u64 mask)
{
	dev->dma_mask = &dev->coherent_dma_mask;
	return dma_set_mask_and_coherent(dev, mask);
}

extern u64 dma_get_required_mask(struct device *dev);

#ifndef arch_setup_dma_ops
static inline void arch_setup_dma_ops(struct device *dev, u64 dma_base,
				      u64 size, const struct iommu_ops *iommu,
				      bool coherent) { }
#endif

#ifndef arch_teardown_dma_ops
static inline void arch_teardown_dma_ops(struct device *dev) { }
#endif

static inline unsigned int dma_get_max_seg_size(struct device *dev)
{
	if (dev->dma_parms && dev->dma_parms->max_segment_size)
		return dev->dma_parms->max_segment_size;
	return SZ_64K;
}

static inline int dma_set_max_seg_size(struct device *dev, unsigned int size)
{
	if (dev->dma_parms) {
		dev->dma_parms->max_segment_size = size;
		return 0;
	}
	return -EIO;
}

static inline unsigned long dma_get_seg_boundary(struct device *dev)
{
	if (dev->dma_parms && dev->dma_parms->segment_boundary_mask)
		return dev->dma_parms->segment_boundary_mask;
	return DMA_BIT_MASK(32);
}

static inline int dma_set_seg_boundary(struct device *dev, unsigned long mask)
{
	if (dev->dma_parms) {
		dev->dma_parms->segment_boundary_mask = mask;
		return 0;
	}
	return -EIO;
}

#ifndef dma_max_pfn
static inline unsigned long dma_max_pfn(struct device *dev)
{
	return *dev->dma_mask >> PAGE_SHIFT;
}
#endif

static inline void *dma_zalloc_coherent(struct device *dev, size_t size,
					dma_addr_t *dma_handle, gfp_t flag)
{
	void *ret = dma_alloc_coherent(dev, size, dma_handle,
				       flag | __GFP_ZERO);
	return ret;
}

static inline int dma_get_cache_alignment(void)
{
#ifdef ARCH_DMA_MINALIGN
	return ARCH_DMA_MINALIGN;
#endif
	return 1;
}

/* flags for the coherent memory api */
#define DMA_MEMORY_EXCLUSIVE		0x01

#ifdef CONFIG_HAVE_GENERIC_DMA_COHERENT
int dma_declare_coherent_memory(struct device *dev, phys_addr_t phys_addr,
				dma_addr_t device_addr, size_t size, int flags);
void dma_release_declared_memory(struct device *dev);
void *dma_mark_declared_memory_occupied(struct device *dev,
					dma_addr_t device_addr, size_t size);
dma_addr_t dma_get_device_base(struct device *dev,
			       struct dma_coherent_mem *mem);
unsigned long dma_get_size(struct dma_coherent_mem *mem);

#else
static inline int
dma_declare_coherent_memory(struct device *dev, phys_addr_t phys_addr,
			    dma_addr_t device_addr, size_t size, int flags)
{
	return -ENOSYS;
}

static inline void
dma_release_declared_memory(struct device *dev)
{
}

static inline void *
dma_mark_declared_memory_occupied(struct device *dev,
				  dma_addr_t device_addr, size_t size)
{
	return ERR_PTR(-EBUSY);
}
static inline dma_addr_t
dma_get_device_base(struct device *dev, struct dma_coherent_mem *mem)
{
	return 0;
}

static inline unsigned long dma_get_size(struct dma_coherent_mem *mem)
{
	return 0;
}

#endif /* CONFIG_HAVE_GENERIC_DMA_COHERENT */

#ifdef CONFIG_HAS_DMA
int dma_configure(struct device *dev);
void dma_deconfigure(struct device *dev);
#else
static inline int dma_configure(struct device *dev)
{
	return 0;
}

static inline void dma_deconfigure(struct device *dev) {}
#endif

/*
 * Managed DMA API
 */
extern void *dmam_alloc_coherent(struct device *dev, size_t size,
				 dma_addr_t *dma_handle, gfp_t gfp);
extern void dmam_free_coherent(struct device *dev, size_t size, void *vaddr,
			       dma_addr_t dma_handle);
extern void *dmam_alloc_attrs(struct device *dev, size_t size,
			      dma_addr_t *dma_handle, gfp_t gfp,
			      unsigned long attrs);
#ifdef CONFIG_HAVE_GENERIC_DMA_COHERENT
extern int dmam_declare_coherent_memory(struct device *dev,
					phys_addr_t phys_addr,
					dma_addr_t device_addr, size_t size,
					int flags);
extern void dmam_release_declared_memory(struct device *dev);
#else /* CONFIG_HAVE_GENERIC_DMA_COHERENT */
static inline int dmam_declare_coherent_memory(struct device *dev,
				phys_addr_t phys_addr, dma_addr_t device_addr,
				size_t size, gfp_t gfp)
{
	return 0;
}

static inline void dmam_release_declared_memory(struct device *dev)
{
}
#endif /* CONFIG_HAVE_GENERIC_DMA_COHERENT */

static inline void *dma_alloc_wc(struct device *dev, size_t size,
				 dma_addr_t *dma_addr, gfp_t gfp)
{
	return dma_alloc_attrs(dev, size, dma_addr, gfp,
			       DMA_ATTR_WRITE_COMBINE);
}
#ifndef dma_alloc_writecombine
#define dma_alloc_writecombine dma_alloc_wc
#endif

static inline void dma_free_wc(struct device *dev, size_t size,
			       void *cpu_addr, dma_addr_t dma_addr)
{
	return dma_free_attrs(dev, size, cpu_addr, dma_addr,
			      DMA_ATTR_WRITE_COMBINE);
}
#ifndef dma_free_writecombine
#define dma_free_writecombine dma_free_wc
#endif

static inline int dma_mmap_wc(struct device *dev,
			      struct vm_area_struct *vma,
			      void *cpu_addr, dma_addr_t dma_addr,
			      size_t size)
{
	return dma_mmap_attrs(dev, vma, cpu_addr, dma_addr, size,
			      DMA_ATTR_WRITE_COMBINE);
}
#ifndef dma_mmap_writecombine
#define dma_mmap_writecombine dma_mmap_wc
#endif

static inline void *dma_alloc_nonconsistent(struct device *dev, size_t size,
					dma_addr_t *dma_handle, gfp_t flag)
{
	unsigned long attrs = DMA_ATTR_NON_CONSISTENT;

	return dma_alloc_attrs(dev, size, dma_handle, flag, attrs);
}

static inline void dma_free_nonconsistent(struct device *dev, size_t size,
					void *cpu_addr, dma_addr_t dma_handle)
{
	unsigned long attrs = DMA_ATTR_NON_CONSISTENT;

	return dma_free_attrs(dev, size, cpu_addr, dma_handle, attrs);
}

static inline int dma_mmap_nonconsistent(struct device *dev,
		struct vm_area_struct *vma, void *cpu_addr,
		dma_addr_t dma_addr, size_t size)
{
	unsigned long attrs = DMA_ATTR_NON_CONSISTENT;

	return dma_mmap_attrs(dev, vma, cpu_addr, dma_addr, size, attrs);
}

#if defined(CONFIG_NEED_DMA_MAP_STATE) || defined(CONFIG_DMA_API_DEBUG)
#define DEFINE_DMA_UNMAP_ADDR(ADDR_NAME)        dma_addr_t ADDR_NAME
#define DEFINE_DMA_UNMAP_LEN(LEN_NAME)          __u32 LEN_NAME
#define dma_unmap_addr(PTR, ADDR_NAME)           ((PTR)->ADDR_NAME)
#define dma_unmap_addr_set(PTR, ADDR_NAME, VAL)  (((PTR)->ADDR_NAME) = (VAL))
#define dma_unmap_len(PTR, LEN_NAME)             ((PTR)->LEN_NAME)
#define dma_unmap_len_set(PTR, LEN_NAME, VAL)    (((PTR)->LEN_NAME) = (VAL))
#else
#define DEFINE_DMA_UNMAP_ADDR(ADDR_NAME)
#define DEFINE_DMA_UNMAP_LEN(LEN_NAME)
#define dma_unmap_addr(PTR, ADDR_NAME)           \
	({ typeof(PTR) __p __maybe_unused = PTR; 0; })
#define dma_unmap_addr_set(PTR, ADDR_NAME, VAL)  \
	do { typeof(PTR) __p __maybe_unused = PTR; } while (0)
#define dma_unmap_len(PTR, LEN_NAME)             \
	({ typeof(PTR) __p __maybe_unused = PTR; 0; })
#define dma_unmap_len_set(PTR, LEN_NAME, VAL)    \
	do { typeof(PTR) __p __maybe_unused = PTR; } while (0)
#endif

#endif
