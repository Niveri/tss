#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <errno.h>
#include <stdlib.h>


static const char *TC_GLOBAL = "/sys/fs/bpf/tc/globals";
static const char *BPF_MASK_TBL_MAP_NAME = "masks_tbl";
static const char *BPF_TUPLES_MAP_NAME = "tuples_map";



#define MAX_TUPLES 100 // 
#define MAX_TABLE_ENTRIES 100 // 
struct tuple_mask {
    // we store 56 bits (8 + 16 + 32) as byte array
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
        printf("tuples map not found \n");
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
int countTuplesInMap(int map){
    int counter = 0;
    int res;
    __u32 key, next_key, value, key1;
    //przeglada wszystkie 100 kluczy jak sie zadaklaruje maksymalna ilosc? niedobrze
    
    while (bpf_map_get_next_key(map, &key, &next_key)==0){
        
        res = bpf_map_lookup_elem(map, &key, &value);
        if(res>=0){
            printf("got key %d\n", key);
            counter ++;
        }
        else{
           // printf("not found\n");
        }
        key = next_key;

    }  
    return counter;
}
void AddMaskPointer(struct tuple_mask *mask_to_add){
    int res;
    int masks_table = get_BPF_prog_by_name(BPF_MASK_TBL_MAP_NAME);
    struct tuple_mask key = {-1}, prev_key={-1};
    struct tuple_mask_value value, new_mask_pointer;

    printf("looking for last key in tuple masks\n");


    while(bpf_map_get_next_key(masks_table, &prev_key, &key)==0){
        printf("next_key_found\n");
        res =bpf_map_lookup_elem(masks_table, &key, &value);
        if (res>=0){
            printf("next_elem_found\n");
            if (value.has_next == 0){
                struct tuple_mask next_key;
                printf("no next value \n" );             
                new_mask_pointer.next_tuple_mask = *mask_to_add;
                new_mask_pointer.tuple_id = value.tuple_id;
                printf("updating tuple id: %d\n", new_mask_pointer.tuple_id);
                new_mask_pointer.has_next = 1;
                bpf_map_update_elem(masks_table, &key, &new_mask_pointer ,0); 
                break;
            }

        }
        prev_key = key;
    }
    
}
//adding a new mask to masks_tbl, it does not have pointer to next mask
void CreateMask(struct tuple_mask *mask_to_add, int tuple_id){
    int masks_table = get_BPF_prog_by_name(BPF_MASK_TBL_MAP_NAME);
    struct tuple_mask_value new_tuple_mask_value = { 
        .tuple_id = tuple_id,
        .next_tuple_mask = 0x0,
        .has_next = 0x0,
    };
    AddMaskPointer(mask_to_add);
    bpf_map_update_elem(masks_table, mask_to_add, &new_tuple_mask_value, 0);
    
}
int CreateTuple(struct tuple_key * key_to_add, struct tuple_value *value_to_add){
    //const char *map_name = "tuple_3";
    char map_name[264];
    int tuples_map = get_BPF_prog_by_name(BPF_TUPLES_MAP_NAME);
    int number_of_tuples = countTuplesInMap(tuples_map);
    snprintf(map_name, sizeof(map_name), "tuple_%d", number_of_tuples);
    int err;
    //TO DO 
    //find number of tuples count tuples_map inner maps?
    // it does not see key 99?? 0-98 only why
    
    struct bpf_create_map_attr attr = {
            .key_size = sizeof(struct tuple_key),
            .value_size = sizeof(struct tuple_value),
            .max_entries = MAX_TUPLES,
            .map_type = BPF_MAP_TYPE_HASH,
            .name = map_name,
            .inner_map_fd = 98-number_of_tuples,

        };
    
    int map_fd = bpf_create_map_xattr(&attr);
    if (map_fd<0){
        err = errno;
        fprintf(stderr, "failed to create Tuple: %s\n", strerror(err));
        return err;
    }
      
   // bpf_obj_pin(map_fd, "/sys/fs/bpf/tc/globals/tuple_2"); //to delete
   
    printf("New Tuple created with fd = %d\n", map_fd);
   
    __u32 key1;
    if(bpf_map_update_elem(map_fd, key_to_add, value_to_add, BPF_ANY)<0){
        printf("failed to create Tuple with this id\n");
        return -1;
    }
    printf("Tuple created\n");
    __u32 outer_key = attr.inner_map_fd;
    
    if(bpf_map_update_elem(tuples_map, &outer_key, &map_fd, 0) <0){
         printf("failed inserting to tuples map\n");
    } //0 = flags
    printf("added to tuples map\n");
    //zrobic funkcje
    struct tuple_mask temp_mask;
    temp_mask.mask1[0] = key_to_add->field1;
    temp_mask.mask2[0] = ((key_to_add->field2) >> 8) & 0xFF;
    temp_mask.mask2[1] = ((key_to_add->field2) >> 0) & 0xFF;
    temp_mask.pad[0] = 0;
    temp_mask.mask3[0] = ((key_to_add->field3) >> 24) & 0xFF;
    temp_mask.mask3[1] = ((key_to_add->field3) >> 16) & 0xFF;
    temp_mask.mask3[2] = ((key_to_add->field3) >> 0) & 0xFF;

    CreateMask(&temp_mask, attr.inner_map_fd); //key to mask!

    return map_fd;
}

void InsertRule(struct tuple_key *new_rule, struct tuple_value *new_rule_value){
    int val = check_in_masks(new_rule, new_rule_value);
    if(val == -1){
        printf("creating new Tuple\n");
        int new_Tuple = CreateTuple(new_rule, new_rule_value);
        
        
    }
   else{
       printf("mask exist\n");
       
       
     
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
 
    struct tuple_key default_key = {
            .field1 = 0x1,
            .field2 = 0xFF,
            .field3 = 0xFC,
    };
   struct tuple_value default_value = {
            .action = 0x0,
            .priority = 0x1,
   };
   if (strcmp(argv[1], "add")==0){
        if (!argv[2] || !argv[3] || !argv[4]) {
            printf("adding default rule\n");
            InsertRule(&default_key, &default_value);
        }
   
    
        printf("%s\n", argv[2]); 
        printf("%s\n", argv[6]); 
        printf("adding key %ld %ld %ld\n", strtol(argv[3], NULL, 16), strtol(argv[4], NULL, 16), strtol(argv[5], NULL, 16));
           struct tuple_key key = {
               .field1 = strtol(argv[3], NULL, 16),
               .field2 = strtol(argv[4], NULL, 16),
               .field3 = strtol(argv[5], NULL, 16),
           };
           struct tuple_value value = {
               .action = strtol(argv[7], NULL, 16),
               .priority = strtol(argv[8], NULL, 16)
           };
           InsertRule(&key, &value);
    }
    
       
   else if (strcmp(argv[1], "delete")==0){
       DeleteRule(&default_key, &default_value);
   }
    else{
           printf("failed\n");
           return -1;
       }

 printf("done  \n");
}
