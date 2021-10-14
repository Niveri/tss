#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

static struct bpf_program *progs[1];
static struct bpf_link *links[1];

static const char *TC_GLOBAL = "/sys/fs/bpf/tc/globals";
static const char *BPF_MASK_TBL_MAP_NAME = "masks_tbl";
static const char *BPF_TUPLES_MAP_NAME = "tuples_map";



#define MAX_TUPLES 100 // 
#define MAX_TABLE_ENTRIES 100 // 
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
    __u16 field2;
    __u32 field3;
};

struct tuple_value {
    __u32 action;
    __u32 priority;
};

int get_BPF_prog_by_name(const char *map_name){
    char pinned_file_name[256];
    memset(pinned_file_name, 0 ,sizeof(pinned_file_name));
    snprintf(pinned_file_name, sizeof(pinned_file_name), "%s/%s", TC_GLOBAL, map_name);
    int devmap_fd = bpf_obj_get(pinned_file_name);
    if (devmap_fd < 0){
        return -1;
    }
    else{
        return devmap_fd;
    }


}
int check_in_masks(struct tuple_key *rule_to_check, struct tuple_value * value_to_check){
    __u32 val;
    __u32 val1;
    struct tuple_mask zero_key = {0};
   
    int mask = bpf_map_lookup_elem(get_BPF_prog_by_name(BPF_MASK_TBL_MAP_NAME), &zero_key, &val); 
    if (mask<0) { 
        printf("no mask 1\n");
        return -1;
    }
    int mask2 = bpf_map_lookup_elem(get_BPF_prog_by_name(BPF_MASK_TBL_MAP_NAME), rule_to_check, &val1);
    
    if(mask2<0){
        printf("no mask2\n");
        return -1;
    }

    return mask2;
}
int CreateTuple(struct tuple_key * key_to_add, struct tuple_value *value_to_add){
    const char *map_name = "tuple_2";
    struct bpf_create_map_attr attr = {
            .key_size = sizeof(struct tuple_key),
            .value_size = sizeof(struct tuple_value),
            .max_entries = MAX_TUPLES,
            .map_type = BPF_MAP_TYPE_HASH,
            .name = map_name,
            .inner_map_fd = MAX_TUPLES-2,

        };
    
    int map_fd = bpf_create_map_xattr(&attr);
    if (map_fd<0){
        printf("failed to create Tuple\n");
        return -1;
    }
      
    bpf_obj_pin(map_fd, "/sys/fs/bpf/tc/globals/tuple_2"); //do usuniecia
   
    printf("New Tuple created with fd = %d\n", map_fd);

    if(bpf_map_update_elem(map_fd, key_to_add, value_to_add, BPF_ANY)<0){
        printf("failed to create Tuple with this id\n");
        return -1;
    }
    printf("Tuple created\n");
    __u32 outer_key = attr.inner_map_fd;
    if(bpf_map_update_elem(get_BPF_prog_by_name(BPF_TUPLES_MAP_NAME), &outer_key, &map_fd, 0) <0){
         printf("failed inserting to tuples map\n");
    } //0 = flags
    printf("added to tuples map\n");


    return map_fd;
}
void InsertRule(struct tuple_key *new_rule, struct tuple_value *new_rule_value){
    int val = check_in_masks(new_rule, new_rule_value);
    if(val == -1){
        printf("creating new Tuple\n");
        int new_Tuple = CreateTuple(new_rule, new_rule_value);
        
    }
   else{
       printf("rule exist\n");
     
   }


}
void DeleteRule(struct tuple_key *new_rule, struct tuple_value *new_rule_value ){
    int val = check_in_masks(new_rule, new_rule_value);
    if(val == -1){
        printf("Rule does not exist\n");  
    }
    else {
        printf("Removing Rule\n"); //TODO
    }
}
int main (int argc, char **argv){
 
    struct tuple_key key = {
            .field1 = 0x1,
            .field2 = 0xFF,
            .field3 = 0xFC,
    };
   struct tuple_value value = {
            .action = 0x0,
            .priority = 0x1,
   };
   if (strcmp(argv[1], "add")==0){
       InsertRule(&key, &value);
   }
   else if (strcmp(argv[1], "delete")==0){
       DeleteRule(&key, &value);
   }

 printf("done  \n");
}
