#include <linux/fs.h>
#include "dedup.h"
#include "nova.h"
#include <linux/random.h>

#define FP_NOT_FOUND -1

inline bool cmp_fp_strong(struct nova_fp_strong *dst, struct nova_fp_strong *src) {
    return (dst->u64s[0] == src->u64s[0] && dst->u64s[1] == src->u64s[1] 
            && dst->u64s[2] == src->u64s[2] && dst->u64s[3] == src->u64s[3] );
}

int nova_alloc_block_write(struct super_block *sb,const char *data_buffer, unsigned long *blocknr)
{
    int allocated = 0;
    void *kmem;
	INIT_TIMING(memcpy_time);
    INIT_TIMING(block_alloc_write_time);

    NOVA_START_TIMING(nv_dedup_alloc_write_t, block_alloc_write_time);
    allocated = nova_new_data_block(sb, blocknr ,ALLOC_NO_INIT);

	nova_dbg_verbose("%s: alloc %d blocks @ %lu\n", __func__,
					allocated, *blocknr);

	if (allocated < 0) {
        nova_dbg("%s alloc blocks failed %d\n", __func__,
					allocated);
        goto out;
	}

    kmem = nova_get_block(sb,nova_get_block_off(sb, *blocknr, NOVA_BLOCK_TYPE_4K));
    
    NOVA_START_TIMING(memcpy_w_nvmm_t, memcpy_time);
	nova_memunlock_range(sb, kmem , PAGE_SIZE);
	memcpy_to_pmem_nocache(kmem , data_buffer, PAGE_SIZE);
	nova_memlock_range(sb, kmem , PAGE_SIZE);
	NOVA_END_TIMING(memcpy_w_nvmm_t, memcpy_time);

    NOVA_END_TIMING(nv_dedup_alloc_write_t, block_alloc_write_time);
out:
    return allocated;
}

struct nova_hentry *nova_alloc_hentry(struct super_block *sb)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct nova_hentry *hentry;

    hentry = kmem_cache_zalloc(sbi->nova_hentry_cachep, GFP_ATOMIC);
    if(unlikely(!hentry))
        return NULL;
    INIT_HLIST_NODE(&hentry->node);
    return hentry;
}



struct nova_hentry *nova_find_in_weak_hlist(struct super_block *sb, struct hlist_head *hlist, struct nova_fp_weak *fp_weak)
{
    struct nova_hentry *hentry;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct nova_pmm_entry *pentries, *pentry;

    pentries = nova_get_block(sb, nova_get_block_off(sb, sbi->metadata_start, NOVA_BLOCK_TYPE_4K));
    hlist_for_each_entry(hentry, hlist, node) {
        pentry = pentries + hentry->entrynr;
        if(pentry->fp_weak.u32 == fp_weak->u32)
            return hentry;
    }

    return NULL;
}

struct nova_hentry *nova_find_in_strong_hlist(struct super_block *sb, struct hlist_head *hlist, struct nova_fp_strong *fp_strong)
{
    struct nova_hentry *hentry;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct nova_pmm_entry *pentries, *pentry;

    pentries = nova_get_block(sb, nova_get_block_off(sb, sbi->metadata_start, NOVA_BLOCK_TYPE_4K));
    hlist_for_each_entry(hentry, hlist, node) {
        pentry = pentries + hentry->entrynr;
        if(cmp_fp_strong(&pentry->fp_strong, fp_strong))
            return hentry;
    }

    return NULL;
}


int nova_dedup_str_fin(struct super_block *sb, const char* data_buffer,unsigned long *blocknr) 
{
    /**
     *  Str_Fin method calculates a single strong fingerprint for data 
     */

    /**
     * we alter the Str_Fin method to calculate both weak and strong fingerprints for a chunk
     *  at a high duplication ratio so that no weak fingerprint is missed with Str_Fin.
     */

    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct nova_fp_weak fp_weak;
    struct nova_fp_strong fp_strong = {0} ;
    struct nova_fp_strong entry_fp_strong = {0} ;
    struct nova_pmm_entry *pentries, *pentry;
    u32 weak_idx;
    u64 strong_idx;
    struct nova_hentry *weak_find_hentry, *strong_find_hentry;
    struct nova_hentry *strong_hentry, *weak_hentry;
    entrynr_t alloc_entry,strong_find_entry;
    char *kmem;
    int allocated = 0;
    // void *kmem;
    INIT_TIMING(weak_fp_calc_time);
    INIT_TIMING(strong_fp_calc_time);
    INIT_TIMING(hash_table_time);
    INIT_TIMING(upsert_entry_time);

    pentries = nova_get_block(sb, nova_get_block_off(sb, sbi->metadata_start, NOVA_BLOCK_TYPE_4K));

    NOVA_START_TIMING(weak_fp_calc_t, weak_fp_calc_time);
    nova_fp_weak_calc(&sbi->nova_fp_weak_ctx, data_buffer,&fp_weak);
    NOVA_END_TIMING(weak_fp_calc_t, weak_fp_calc_time);

    NOVA_START_TIMING(strong_fp_calc_t, strong_fp_calc_time);
    nova_fp_strong_calc(&sbi->nova_fp_strong_ctx, data_buffer, &fp_strong);
    NOVA_END_TIMING(strong_fp_calc_t, strong_fp_calc_time);

    weak_idx = (fp_weak.u32 & ((1 << sbi->num_entries_bits) - 1));
	spin_lock(sbi->weak_hash_table_locks + weak_idx % HASH_TABLE_LOCK_NUM);
    NOVA_START_TIMING(hash_table_t, hash_table_time);
    weak_find_hentry = nova_find_in_weak_hlist(sb, &sbi->weak_hash_table[weak_idx], &fp_weak);
    NOVA_END_TIMING(hash_table_t, hash_table_time);
    
    strong_idx = (fp_strong.u64s[0] & ((1 << sbi->num_entries_bits) - 1));
	spin_lock(sbi->strong_hash_table_locks + strong_idx % HASH_TABLE_LOCK_NUM);
    NOVA_START_TIMING(hash_table_t, hash_table_time);
    strong_find_hentry = nova_find_in_strong_hlist(sb, &sbi->strong_hash_table[strong_idx], &fp_strong);
    NOVA_END_TIMING(hash_table_t, hash_table_time);

    if( strong_find_hentry ) {
        NOVA_START_TIMING(upsert_entry_t, upsert_entry_time);
        pentry = pentries + strong_find_hentry->entrynr;
        ++pentry->refcount;
        pentry->fp_weak = fp_weak;
        pentry->flag = FP_STRONG_FLAG;
        ++sbi->dup_block;
        *blocknr = pentry->blocknr;
        allocated = 1;
        strong_find_entry = strong_find_hentry->entrynr;
        NOVA_END_TIMING(upsert_entry_t, upsert_entry_time);
    }else {
        /* handle the situation */
        if (weak_find_hentry) {
            pentry = pentries + weak_find_hentry->entrynr;
            kmem = nova_get_block(sb, nova_get_block_off(sb, pentry->blocknr, NOVA_BLOCK_TYPE_4K));
            nova_fp_strong_calc(&sbi->nova_fp_strong_ctx, kmem, &entry_fp_strong);
            if (cmp_fp_strong(&entry_fp_strong, &fp_strong)) {
                NOVA_START_TIMING(upsert_entry_t, upsert_entry_time);
                pentry->fp_strong = entry_fp_strong;
                ++pentry->refcount;
                pentry->flag = FP_STRONG_FLAG;
                ++sbi->dup_block;
                *blocknr = pentry->blocknr;
                allocated = 1;
                NOVA_END_TIMING(upsert_entry_t, upsert_entry_time);
                strong_hentry = nova_alloc_hentry(sb);
                strong_hentry->entrynr = weak_find_hentry->entrynr;
                hlist_add_head(&strong_hentry->node, &sbi->strong_hash_table[strong_idx]);
                strong_find_entry = weak_find_hentry->entrynr;
            }
            else {
                alloc_entry = nova_alloc_entry(sb);
                allocated = nova_alloc_block_write(sb,data_buffer,blocknr);
                if(allocated < 0) 
                    goto out;
                
                NOVA_START_TIMING(upsert_entry_t, upsert_entry_time);
                pentry = pentries + alloc_entry;
                pentry->flag = FP_STRONG_FLAG;
                pentry->blocknr = *blocknr;
                pentry->fp_strong = fp_strong;
                pentry->fp_weak = fp_weak;
                pentry->refcount = 1;
                NOVA_END_TIMING(upsert_entry_t, upsert_entry_time);

                strong_hentry = nova_alloc_hentry(sb);
                strong_hentry->entrynr = alloc_entry;
                hlist_add_head(&strong_hentry->node, &sbi->strong_hash_table[strong_idx]);
                sbi->blocknr_to_entry[*blocknr] = alloc_entry;
                strong_find_entry = alloc_entry;
            }
        }
        else {
            alloc_entry = nova_alloc_entry(sb);
            allocated = nova_alloc_block_write(sb,data_buffer,blocknr);
            if(allocated < 0) 
                goto out;
            
            NOVA_START_TIMING(upsert_entry_t, upsert_entry_time);
            pentry = pentries + alloc_entry;
            pentry->flag = FP_STRONG_FLAG;
            pentry->blocknr = *blocknr;
            pentry->fp_strong = fp_strong;
            pentry->fp_weak = fp_weak;
            pentry->refcount = 1;
            NOVA_END_TIMING(upsert_entry_t, upsert_entry_time);

            strong_hentry = nova_alloc_hentry(sb);
            strong_hentry->entrynr = alloc_entry;
            hlist_add_head(&strong_hentry->node, &sbi->strong_hash_table[strong_idx]);
            sbi->blocknr_to_entry[*blocknr] = alloc_entry;
            strong_find_entry = alloc_entry;
        }
    }

    NOVA_START_TIMING(upsert_entry_t, upsert_entry_time);
    nova_flush_buffer(pentry, sizeof(*pentry), true);
    NOVA_END_TIMING(upsert_entry_t, upsert_entry_time);

    if(!weak_find_hentry) {
        weak_hentry = nova_alloc_hentry(sb);
        weak_hentry->entrynr = strong_find_entry;
        hlist_add_head(&weak_hentry->node, &sbi->weak_hash_table[weak_idx]);
    }

out:
	spin_unlock(sbi->weak_hash_table_locks + weak_idx % HASH_TABLE_LOCK_NUM);
	spin_unlock(sbi->strong_hash_table_locks + strong_idx % HASH_TABLE_LOCK_NUM);
    return allocated;
}

int nova_dedup_weak_str_fin(struct super_block *sb, const char* data_buffer, unsigned long *blocknr) 
{
    /**
     * w_s_Fin method calculates a weak fingerprint for a data chunk
     *  and uses a strong fingerprint to 
     * check data that are not surely identified by comparing weak fingerprinting. 
     */
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct nova_fp_weak fp_weak;
    struct nova_fp_strong fp_strong = {0}, entry_fp_strong = {0};
    struct nova_pmm_entry *pentries, *weak_entry, *strong_entry, *pentry;
    struct nova_hentry *weak_hentry, *strong_hentry;
    u32 weak_idx;
    u64 strong_idx;
    struct nova_hentry *weak_find_hentry, *strong_find_hentry;
    entrynr_t alloc_entry;
    int allocated = 0;
    void *kmem;
    bool flush_entry = false;
    INIT_TIMING(weak_fp_calc_time);
    INIT_TIMING(strong_fp_calc_time);
    INIT_TIMING(hash_table_time);
    INIT_TIMING(upsert_entry_time);

    pentries = nova_get_block(sb, nova_get_block_off(sb, sbi->metadata_start, NOVA_BLOCK_TYPE_4K));

    NOVA_START_TIMING(weak_fp_calc_t, weak_fp_calc_time);
    nova_fp_weak_calc(&sbi->nova_fp_weak_ctx, data_buffer,&fp_weak);
    NOVA_END_TIMING(weak_fp_calc_t, weak_fp_calc_time);

    weak_idx = (fp_weak.u32 & ((1 << sbi->num_entries_bits) - 1));
	spin_lock(sbi->weak_hash_table_locks + weak_idx % HASH_TABLE_LOCK_NUM);
    NOVA_START_TIMING(hash_table_t, hash_table_time);
    weak_find_hentry = nova_find_in_weak_hlist(sb, &sbi->weak_hash_table[weak_idx], &fp_weak);
    NOVA_END_TIMING(hash_table_t, hash_table_time);

    if(weak_find_hentry) {
        /**
         * If a newlyarrived chunk has the same weak fingerprint as a stored chunk
         *  NV-Dedup calculates the strong fingerprint of both chunks for further comparison. 
         * Then, NV-Dedup updates the entry of the stored chunk by adding the strong fingerprint.
         */
        weak_entry = pentries + weak_find_hentry->entrynr;
        if(weak_entry->flag == FP_STRONG_FLAG) {
             /**
            *  The sixth field is a 1 B flag to indicate 
            *  whether the strong fingerprint is valid or not.
            *  from NV-Dedup
            */
           // if the strong fingerprint is valid
           // assign it to entry_fp_strong

           entry_fp_strong = weak_entry->fp_strong;
        }
        else if(weak_entry->flag == FP_WEAK_FLAG){
            kmem = nova_get_block(sb, nova_get_block_off(sb, weak_entry->blocknr, NOVA_BLOCK_TYPE_4K));
            NOVA_START_TIMING(strong_fp_calc_t, strong_fp_calc_time);
            nova_fp_strong_calc(&sbi->nova_fp_strong_ctx, kmem, &entry_fp_strong);
            NOVA_END_TIMING(strong_fp_calc_t, strong_fp_calc_time);
            
            NOVA_START_TIMING(upsert_entry_t, upsert_entry_time);
            weak_entry->flag = FP_STRONG_FLAG;
            weak_entry->fp_strong = entry_fp_strong;
            flush_entry = true;
            NOVA_END_TIMING(upsert_entry_t, upsert_entry_time);
            
            strong_hentry = nova_alloc_hentry(sb);
            strong_hentry->entrynr = weak_find_hentry->entrynr;
            strong_idx = (entry_fp_strong.u64s[0] & ((1 << sbi->num_entries_bits) - 1));
	        spin_lock(sbi->strong_hash_table_locks + strong_idx % HASH_TABLE_LOCK_NUM);
            hlist_add_head(&strong_hentry->node, &sbi->strong_hash_table[strong_idx]);
	        spin_unlock(sbi->strong_hash_table_locks + strong_idx % HASH_TABLE_LOCK_NUM);
        }

        NOVA_START_TIMING(strong_fp_calc_t, strong_fp_calc_time);
        nova_fp_strong_calc(&sbi->nova_fp_strong_ctx, data_buffer, &fp_strong);
        NOVA_END_TIMING(strong_fp_calc_t, strong_fp_calc_time);

        if(cmp_fp_strong(&fp_strong, &entry_fp_strong)) {
            *blocknr = weak_entry->blocknr;
            NOVA_START_TIMING(upsert_entry_t, upsert_entry_time);
            ++weak_entry->refcount;
            flush_entry = true;
            ++sbi->dup_block;
            NOVA_END_TIMING(upsert_entry_t, upsert_entry_time);
            allocated = 1;
        } 
        else {
            strong_idx = (fp_strong.u64s[0] & ((1 << sbi->num_entries_bits) - 1));
	        spin_lock(sbi->strong_hash_table_locks + strong_idx % HASH_TABLE_LOCK_NUM);
            NOVA_START_TIMING(hash_table_t, hash_table_time);
            strong_find_hentry = nova_find_in_strong_hlist(sb, &sbi->strong_hash_table[strong_idx], &fp_strong);
            NOVA_END_TIMING(hash_table_t, hash_table_time);
            
            if(strong_find_hentry) {
                // if the corresponding strong fingerprint is found
                // add the refcount and return
                NOVA_START_TIMING(upsert_entry_t, upsert_entry_time);
                strong_entry = pentries + strong_find_hentry->entrynr;
                ++strong_entry->refcount;
                nova_flush_buffer(strong_entry,sizeof(*strong_entry),true);
                NOVA_END_TIMING(upsert_entry_t, upsert_entry_time);
                *blocknr = strong_entry->blocknr;
                allocated = 1;
                ++sbi->dup_block;
            } else {
                // if the corresponding strong fingerprint is not found
                // alloc a new entry and write
                // add the strong fingerprint to strong fingerprint hash table
                alloc_entry = nova_alloc_entry(sb);
                allocated = nova_alloc_block_write(sb,data_buffer,blocknr);
                if(allocated < 0) {
	                spin_unlock(sbi->strong_hash_table_locks + strong_idx % HASH_TABLE_LOCK_NUM);
                    goto out;
                }
                
                NOVA_START_TIMING(upsert_entry_t, upsert_entry_time);
                pentry = pentries + alloc_entry;
                pentry->flag = FP_STRONG_FLAG;
                pentry->fp_weak = fp_weak;
                pentry->fp_strong = fp_strong;
                pentry->blocknr = *blocknr;
                pentry->refcount = 1;
                nova_flush_buffer(pentry, sizeof(*pentry), true);
                NOVA_END_TIMING(upsert_entry_t, upsert_entry_time);
                strong_hentry = nova_alloc_hentry(sb);
                strong_hentry->entrynr = alloc_entry;
                hlist_add_head(&strong_hentry->node, &sbi->strong_hash_table[strong_idx]);
                sbi->blocknr_to_entry[*blocknr] = alloc_entry;
            }
	        spin_unlock(sbi->strong_hash_table_locks + strong_idx % HASH_TABLE_LOCK_NUM);
        }

        NOVA_START_TIMING(upsert_entry_t, upsert_entry_time);
        if(flush_entry) nova_flush_buffer(weak_entry, sizeof(*weak_entry), true);
        NOVA_END_TIMING(upsert_entry_t, upsert_entry_time);
    }
    else {
        /**
         * If the weak fingerprint is not found in the metadata table, 
         * NV-Dedup will deem the chunk to be non-existent 
         * and the calculation of strong fingerprint needs not be done for the chunk
         */

        alloc_entry = nova_alloc_entry(sb);

        allocated = nova_alloc_block_write(sb,data_buffer,blocknr);
        if(allocated < 0 )
            goto out;
        
        NOVA_START_TIMING(upsert_entry_t, upsert_entry_time);
        pentry = pentries + alloc_entry;
        memset_nt(pentry, 0, sizeof(*pentry));
        pentry->flag = FP_WEAK_FLAG;
        pentry->fp_weak = fp_weak;
        pentry->blocknr = *blocknr;
        pentry->refcount = 1;
        nova_flush_buffer(pentry, sizeof(*pentry),true);
        NOVA_END_TIMING(upsert_entry_t, upsert_entry_time);

        weak_hentry = nova_alloc_hentry(sb);
        weak_hentry->entrynr = alloc_entry;
        hlist_add_head(&weak_hentry->node, &sbi->weak_hash_table[weak_idx]);
        sbi->blocknr_to_entry[*blocknr] = alloc_entry;
    }

out:
	spin_unlock(sbi->weak_hash_table_locks + weak_idx % HASH_TABLE_LOCK_NUM);
    return allocated;
}

int nova_dedup_non_fin(struct super_block *sb, const char* data_buffer, unsigned long* blocknr)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    struct nova_pmm_entry *pentries, *pentry;
    entrynr_t alloc_entry;
    int allocated = 0;
    INIT_TIMING(time);

    alloc_entry = nova_alloc_entry(sb);
    allocated = nova_alloc_block_write(sb, data_buffer,blocknr);
    if(allocated < 0)
        goto out;
    
    NOVA_START_TIMING(upsert_entry_t, time);
    pentries = nova_get_block(sb, nova_get_block_off(sb, sbi->metadata_start,NOVA_BLOCK_TYPE_4K));
    pentry = pentries + alloc_entry;
    memset_nt(pentry, 0, sizeof(*pentry));
    pentry->blocknr = *blocknr;
    pentry->flag = NON_FIN_FLAG;
    pentry->refcount = 1;
    nova_flush_buffer(pentry, sizeof(*pentry), true);
    sbi->blocknr_to_entry[*blocknr] = alloc_entry;
    NOVA_END_TIMING(upsert_entry_t, time);

out:
    return allocated;
}

int nova_dedup_new_write(struct super_block *sb,const char* data_buffer, unsigned long *blocknr)
{
    struct nova_sb_info *sbi = NOVA_SB(sb);
    u32 dup_block = 0;
    u32 dup_mode = 0;
    unsigned long randomNum;
    int allocated;
    INIT_TIMING(calc_t);

    ++sbi->cur_block;
    if(sbi->cur_block >= SAMPLE_BLOCK) {
        if(sbi->dedup_mode == NON_FIN) {
            wakeup_calc_non_fin(sb);
        }
        dup_block = sbi->dup_block;
        if(dup_block > STR_FIN_THRESH) {
            sbi->dedup_mode = STR_FIN;
        }else if(dup_block > NON_FIN_THRESH) {
            sbi->dedup_mode = WEAK_STR_FIN;
        }else {
            get_random_bytes(&randomNum, sizeof(unsigned long));
            if(randomNum & 1) {
                sbi->dedup_mode = NON_FIN;
            }
            else {
                sbi->dedup_mode = WEAK_STR_FIN;
            }
        }
        sbi->cur_block = 0;
        sbi->dup_block = 0;
    }

    dup_mode = sbi->dedup_mode;
    if(dup_mode & NON_FIN) {
        NOVA_START_TIMING(non_fin_calc_t, calc_t);
        allocated = nova_dedup_non_fin(sb, data_buffer, blocknr);
        NOVA_END_TIMING(non_fin_calc_t, calc_t);
        goto out;
    }else if(dup_mode & WEAK_STR_FIN) {
        NOVA_START_TIMING(ws_fin_calc_t, calc_t);
        allocated = nova_dedup_weak_str_fin(sb, data_buffer, blocknr);
        NOVA_END_TIMING(ws_fin_calc_t, calc_t);
        goto out;
    }else if(dup_mode & STR_FIN) {
        NOVA_START_TIMING(str_fin_calc_t, calc_t);
        allocated = nova_dedup_str_fin(sb, data_buffer, blocknr);
        NOVA_END_TIMING(str_fin_calc_t, calc_t);
        goto out;
    }else {
        return -ESRCH;
    }
out:
    return allocated;
}