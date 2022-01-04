#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>



#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>






/*
 * Assuming the following P4 table:
 *
 * bit<8> field1;
 * bit<32> field2;
 * bit<16> field3;
 *
 * p4table {
 *
 * key = {
 *     field1: exact;
 *     field2: ternary;
 *     field3: lpm;
 * }
 *
 * actions = {
 *     actionA
 *     actionB
 * }
 *
 * }
 */

#define MAX_TUPLES 100 // should be 2^8 + 2^8 as we have one ternary field and one lpm field
#define MAX_TABLE_ENTRIES 100 // custom value

struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
    __u32 inner_id;
    __u32 inner_idx;
};

#define bpf_debug_printk(fmt, ...)                               \
  ({                                                             \
      char ____fmt[] = fmt;                                      \
      bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
  })

#define BITMASK_CLEAR(x,y) ((x) &= ((y)))

struct tuple_mask {
    // we store 56 bits (8 + 32 + 16) as byte array
    __u8 mask1[1];
    __u8 mask2[2];
    __u8 pad[1];
    __u8 mask3[4];
};

struct tuple_mask_value {
    __u32 tuple_id;
    struct tuple_mask next_tuple_mask;
    __u8 has_next;
};

struct tuple_key {
    __u8 field1;
    __u8 pad;
    __u16 field2;
    __u32 field3;
};

struct tuple_value {
    __u32 action;
    __u32 priority;
};

struct bpf_elf_map SEC("maps") masks_tbl = {
        .type = BPF_MAP_TYPE_HASH,
        .size_key = sizeof(struct tuple_mask),
        .size_value = sizeof(struct tuple_mask_value),
        .max_elem = MAX_TUPLES,
        .pinning = 2,
        .id = 5,
};

struct bpf_elf_map SEC("maps") tuple_0 = {
        .type = BPF_MAP_TYPE_HASH,
        .size_key = sizeof(struct tuple_key),
        .size_value = sizeof(struct tuple_value),
        .max_elem = MAX_TUPLES,
        .pinning = 2,
        .id = MAX_TUPLES-1,
        .inner_idx = MAX_TUPLES-1,
};

struct bpf_elf_map SEC("maps") tuples_map = {
        .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
        .size_key = sizeof(__u32),
        .size_value = sizeof(__u32),
        .max_elem = MAX_TUPLES,
        .flags = 0,
        .inner_id = MAX_TUPLES-1,
        .pinning = 2,
};





static __always_inline void * ternary_lookup(struct tuple_key *key, __u32 iterations)
{   

    __u64 start = bpf_ktime_get_ns();
    struct tuple_value *entry = NULL;
    struct tuple_mask zero_key = {0};
    
    struct tuple_mask_value *elem = bpf_map_lookup_elem(&masks_tbl, &zero_key);
    if (!elem) { 
        return NULL;
    }
    struct tuple_mask next_id = elem->next_tuple_mask;
    
    
 
    #pragma clang loop unroll(disable)
    for (int i = 0; i < MAX_TUPLES; i++) {
        struct tuple_mask_value *elem = bpf_map_lookup_elem(&masks_tbl, &next_id);
        if (!elem) {
            bpf_debug_printk("no elem 2 \n");
            return NULL;
        }
        struct tuple_key k = {};
        struct tuple_key test_key = {};
        #pragma clang loop unroll(disable)
        for (int i = 0; i < iterations; i++) {
            __u32 *tmp = ((__u32 *) &k);
            __u32 *mask = ((__u32 *) &next_id); //take the address of next_id and treat it as it were the address of __u32
          #pragma clang loop unroll(disable)
            for (int j = 0; j< sizeof(struct tuple_mask)/4; j++){
                 
                 bpf_debug_printk("masking next 4 bytes of: %llx with mask %llx",  *(((__u32 *) key) +j), mask[j]);
                 tmp[j] = ((__u32 *) key)[j] & mask[j];
            }
       
        }

        __u32 tuple_id = elem->tuple_id;
        bpf_debug_printk("Looking up tuple %d in tuples map", tuple_id);

        struct bpf_elf_map *tuple = bpf_map_lookup_elem(&tuples_map, &tuple_id);
        if (!tuple) {
            bpf_debug_printk(" tuple not found in tuples_map");
            return NULL;
        }
        bpf_debug_printk(" tuple found in tuples_map");
        bpf_debug_printk("Looking up key %llx %llx %llx", k.field1, k.field2, k.field3);
        void *data = bpf_map_lookup_elem(tuple, &k);
        if (!data) {
            bpf_debug_printk("entry not found");
           
           
        }
        else{
            bpf_debug_printk("Found entry");
            struct tuple_value * tuple_entry = (struct tuple_value *) data;
            if (entry == NULL || tuple_entry->priority > entry->priority) {
                entry = tuple_entry;
            }

        }
        
        if (elem->has_next == 0) {
                break;
        }
        next_id = elem->next_tuple_mask;
    }
    __u64 end = bpf_ktime_get_ns();
    bpf_debug_printk("Classified in %u", end - start);
    return entry;
}

SEC("xdp-ingress")
int xdp_ingress(struct xdp_md *ctx)
{
    
    return XDP_PASS;
}

SEC("tc-ingress")
int tc_ingress(struct __sk_buff *skb)
{   
    /*
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = (struct ethhdr *)(data);
  
    struct iphdr  *ip   = (struct iphdr*) skb->data + sizeof(eth);
    if ((void *)(eth + 1) > data_end){
        return TC_ACT_SHOT;
        
    }
    */  
   /*
    struct tuple_key key = {
            .field1 = 0x1,
            .field2 = 0xFF,
            .field3 = 0x1,
    };
   
    struct tuple_value * val = ternary_lookup(&key, 1);
    if (val)
    {
        bpf_debug_printk("Entry 1 found!\n");
    }
    else
    {
        bpf_debug_printk("Entry 1 not found!\n");
    }
  */
    struct tuple_key default_key = {
            .field1 = 0xDE,
            .pad =0,
            .field2 = 0xCEAB,
            .field3 = 0xCCAABB01,
            
    };
    

    /*struct tuple_value * val_default = ternary_lookup(&default_key, 1);
    if (val_default)
    {
        bpf_debug_printk("Entry default found!\n");
    }
    else
    {
        bpf_debug_printk("Entry default not found!\n");
    }
   */


  
    
    struct tuple_key key1 = {
            .field1 = 0x0,
            .pad = 0,
            .field2 = 0x11,
            .field3 = 0xc0a80401,
    };
    struct tuple_value * val2 = ternary_lookup(&key1, 1);
    if (val2)
    {
        bpf_debug_printk("Entry 2 found!\n");
    }
    else
    {
        bpf_debug_printk("Entry 2 not found!\n");
    }
    /*
    struct tuple_key key2 = {
            .field1 = 0x1,
            .field2 = 0xCC,
            .field3 = 0x1,
    };
    struct tuple_value * val3 = ternary_lookup(&key2, 1);
    if (val3)
    {
        bpf_debug_printk("Entry 3 found!\n");
    }
    else
    {
        bpf_debug_printk("Entry 3 not found!\n");
    }
    */
    return TC_ACT_OK;
}

SEC("tc-egress")
int tc_egress(struct __sk_buff *ctx)
{
    return TC_ACT_OK;
}

static char _license[] SEC("license") = "GPL";