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
    __u8 field1; //diffserv
    __u16 field2; //protocol
    __u32 field3; //source
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
int check_in_masks(struct tuple_mask *mask_to_check){
    struct tuple_mask_value val1;
    struct tuple_mask zero_key = {0};

    int mask2 = bpf_map_lookup_elem(get_BPF_prog_by_name(BPF_MASK_TBL_MAP_NAME), mask_to_check, &val1);
    printf("mask 2 %d \n", mask2);
    if(mask2<0){
        printf("no mask2\n");
        return -1;
    }
    
    return val1.tuple_id;
}
int countTuplesInMap(int map){
    int counter = 0;
    int res;
    __u32 key, next_key, value, key1;
    //przeglada wszystkie 100 kluczy jak sie zadaklaruje maksymalna ilosc? 
    
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
/*
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
    
}*/

void AddMaskPointer(struct tuple_mask *new_mask, struct tuple_mask_value *new_mask_value){
    printf("add pointer\n");
    int masks_table = get_BPF_prog_by_name(BPF_MASK_TBL_MAP_NAME);
    struct tuple_mask zero_key = {0};
    struct tuple_mask_value value;
    int find_zero = bpf_map_lookup_elem(masks_table, &zero_key, &value);
    if(find_zero>=0){
        new_mask_value->next_tuple_mask = value.next_tuple_mask;
        new_mask_value->has_next = value.has_next;
        bpf_map_update_elem(masks_table, new_mask, new_mask_value, 0);
        value.next_tuple_mask = *new_mask;   
        printf("has next = %d\n", value.has_next);    
        value.has_next = 0x1; // niepotrzebnie wykonywane za kazdym razem? wystarczylo by raz kiedy zostanie dodany drugi element
       //
        bpf_map_update_elem(masks_table, &zero_key, &value, 0);

    }
}

//adding a new mask to masks_tbl, it does not have pointer to next mask
void CreateMask(struct tuple_mask *new_mask, int tuple_id){
    int masks_table = get_BPF_prog_by_name(BPF_MASK_TBL_MAP_NAME);
    struct tuple_mask_value new_mask_value = { 
        .tuple_id = tuple_id,
        .next_tuple_mask = 0x0,
        .has_next = 0x0, 
    };
    AddMaskPointer(new_mask, &new_mask_value);  
}
int CreateTuple(struct tuple_key * key_to_add, struct tuple_value *value_to_add, struct tuple_mask *mask_to_add){
    char map_name[264];
    int tuples_map = get_BPF_prog_by_name(BPF_TUPLES_MAP_NAME);
    int number_of_tuples = countTuplesInMap(tuples_map);
    snprintf(map_name, sizeof(map_name), "tuple_%d", number_of_tuples);
    int err;
   
    struct bpf_create_map_attr attr = {
            .key_size = sizeof(struct tuple_key),
            .value_size = sizeof(struct tuple_value),
            .max_entries = MAX_TUPLES,
            .map_type = BPF_MAP_TYPE_HASH,
            .name = map_name,
            .inner_map_fd = 98-number_of_tuples,
            .map_flags = 0,

        };
    
    int map_fd = bpf_create_map_xattr(&attr);
    if (map_fd<0){
        err = errno;
        fprintf(stderr, "failed to create Tuple: %s\n", strerror(err));
        return err;
    } 
   // bpf_obj_pin(map_fd, "/sys/fs/bpf/tc/globals/tuple_2"); //pin map
    
    printf("New Tuple created with fd = %d\n", map_fd);
    //key_to_add & 0xff00ffffffffffff;
    printf("size: %d \n", attr.key_size);
    
    if(bpf_map_update_elem(map_fd, key_to_add, value_to_add, BPF_NOEXIST)<0){
        printf("failed to create Tuple with this id\n");
        return -1;
    }
    printf("Tuple created\n");
    __u32 outer_key = attr.inner_map_fd;
    
    if(bpf_map_update_elem(tuples_map, &outer_key, &map_fd, 0) <0){
         printf("failed inserting to tuples map\n");
    } 
    printf("added to tuples map\n");
    CreateMask(mask_to_add, attr.inner_map_fd);

   
    return map_fd;
}


void AddToTuple(struct tuple_key * new_rule, struct tuple_value *new_rule_value, int tuple_id){
    printf("adding tuple to existing tuple map\n");
    __u32 inner_map_id;
    bpf_map_lookup_elem(get_BPF_prog_by_name(BPF_TUPLES_MAP_NAME), &tuple_id, &inner_map_id);
    int inner_map_fd = bpf_map_get_fd_by_id(inner_map_id);
    if(bpf_map_update_elem(inner_map_fd, new_rule, new_rule_value, 0)<0){
        printf("failed to add to Tuple");
    }
}

void InsertRule(struct tuple_key *new_rule, struct tuple_value *new_rule_value, struct tuple_mask *new_mask){
    int val = check_in_masks(new_mask);
    if(val < 0){
        printf("creating new Tuple\n");
        int new_Tuple = CreateTuple(new_rule, new_rule_value, new_mask);     
    }
   else{
       printf("mask exist\n");
       AddToTuple(new_rule, new_rule_value, val);
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

   struct tuple_mask default_mask = {
       .mask1[0] = 0x0,
       .mask2[0] = 0xff,
       .mask2[1] = 0xff,
       .pad =0,
       .mask3[0] = 0xff,
       .mask3[1] = 0xff,
       .mask3[2] = 0xff,
       .mask3[3] = 0xff
    };
  
   if (strcmp(argv[1], "add")==0){
        if (!argv[2] || !argv[3] || !argv[4]) {
            printf("adding default rule\n");
            InsertRule(&default_key, &default_value, &default_mask);
        }
        else {    
        printf("adding key %lx %lx %lx\n", strtol(argv[3], NULL, 0), strtoul(argv[4], NULL, 0), strtol(argv[5], NULL, 0));
        printf("with mask %ld %ld %ld\n", strtol(argv[10], NULL, 16), strtol(argv[11], NULL, 16), strtol(argv[12], NULL, 16));
        

           struct tuple_key key = {
               .field1 = strtol(argv[3], NULL, 16),
               .field2 = strtol(argv[4], NULL, 16),
               .field3 = strtol(argv[5], NULL, 16)
           };
           struct tuple_value value = {
               .action = strtoul(argv[7], NULL, 0),
               .priority = strtoul(argv[8], NULL, 0)
           };
           struct tuple_mask mask = {
                .mask1[0] = strtol(argv[10], NULL, 16),
                .mask2[0] = (strtol(argv[11], NULL, 16) >> 8),
                .mask2[1] = (strtol(argv[11], NULL, 16) >> 0),
                .pad[0] = 0, //in this tuple_mask format prob to delete
                .mask3[0] = (strtol(argv[12], NULL, 16) >> 24),
                .mask3[1] = (strtol(argv[12], NULL, 16)) >> 16,
                .mask3[2] = (strtol(argv[12], NULL, 16)) >> 8,
                .mask3[3] = (strtol(argv[12], NULL, 16)) >> 0
           };
           InsertRule(&key, &value, &mask);
   }
    }
    
       
   else if (strcmp(argv[1], "delete")==0){
     //  DeleteRule(&default_key, &default_value);
   }
    else{
           printf("failed\n");
           return -1;
       }

 printf("done  \n");
}
