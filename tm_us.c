#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <errno.h>
#include <stdlib.h>


static const char *TC_GLOBAL = "/sys/fs/bpf/tc/globals";
static const char *BPF_MASK_TBL_MAP_NAME = "masks_tbl";
static const char *BPF_TUPLES_MAP_NAME = "tuples_map";
static const char *BPF_RULES_MAP_NAME = "rules_map";


#define MAX_TUPLES 100 // 
#define MAX_TABLE_ENTRIES 100 // 
#define MAX_NUM_COLLISIONS 10 //
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
    __u8 pad;
    __u16 field2; //protocol
    __u32 field3; //source
};

struct tuple_value {
    __u32 action;
    __u32 priority;
};
struct rules_map_key {
    struct tuple_key rule_key;
    struct tuple_mask rule_mask;
    struct tuple_value rule_value;
};
int get_BPF_prog_by_name(const char *map_name){
    char pinned_file_name[256];
    memset(pinned_file_name, 0 ,sizeof(pinned_file_name));
    snprintf(pinned_file_name, sizeof(pinned_file_name), "%s/%s", TC_GLOBAL, map_name);
    int devmap_fd = bpf_obj_get(pinned_file_name);
    if (devmap_fd < 0){
        printf("map not found \n");
        return -1;
    }
    else{
        return devmap_fd;
    }
}
int countTuplesInMap(int map){
    int counter = 0;
    int res;
    __u32 key =-1, prev_key =-1, value, key1;
    //przeglada wszystkie 100 kluczy jak sie zadaklaruje maksymalna ilosc? 
    
    while (bpf_map_get_next_key(map, &prev_key, &key)==0){
        
        res = bpf_map_lookup_elem(map, &key, &value);
        if(res>=0){
            printf("got key %d\n", key);
            counter ++;
        }
        else{
            //printf("not found\n");
        }
        prev_key = key;

    }  
    return counter;
}

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
        bpf_map_update_elem(masks_table, &zero_key, &value, 0);

    }
}
//adding a new mask to masks_tbl, it does not have pointer to next mask
void CreateMask(struct tuple_mask *new_mask, int tuple_id){
    printf("creating mask\n");
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
            .inner_map_fd = 99-number_of_tuples,

        };
    
    int map_fd = bpf_create_map_xattr(&attr);
    if (map_fd<0){
        err = errno;
        fprintf(stderr, "failed to create Tuple: %s\n", strerror(err));
        return err;
    } 

    
    printf("New Tuple created with fd = %d\n", map_fd);
    
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


bool CanInsert(struct tuple_mask *origin_tuple_mask, struct tuple_mask *new_tuple_mask)
{
    printf("checking if new mask > origin\n");
    if((origin_tuple_mask->mask1[0]==0) & (origin_tuple_mask->mask2[0]==0) &  (origin_tuple_mask->mask3[0]==0)
        &(origin_tuple_mask->mask2[1] == 0) &(origin_tuple_mask->mask3[1]== 0) &(origin_tuple_mask->mask3[2] ==0)){
        return false;
    } // toDo lepsze rozwiązanie, chodzi o to aby ignorowało maskę o kluczu 0 w masks_tbl
	if((origin_tuple_mask->mask1 > new_tuple_mask->mask1) |
        (origin_tuple_mask->mask2 > new_tuple_mask->mask2) |
        (origin_tuple_mask->mask3 > new_tuple_mask->mask3)){
        return false;					
    }
    return true;
}

int CreateRulesMap(struct tuple_key *tuple_key, struct tuple_mask *new_rule_tuple_mask,
                struct tuple_value *tuple_value, struct tuple_key *key_from_tuple ){
    struct bpf_create_map_attr attr = {
            .key_size = sizeof(struct rules_map_key),
            .value_size = sizeof(struct tuple_key),
            .max_entries = MAX_TUPLES,
            .map_type = BPF_MAP_TYPE_HASH,
            .name = "rules_map",
            .inner_map_fd = 4,

        };
    int err;
    int map_fd = bpf_create_map_xattr(&attr);
    if (map_fd<0){
        err = errno;
        fprintf(stderr, "failed to create Rules map: %s\n", strerror(err));
        return err;
    } 
   
    printf("New Rules map created with fd = %d\n", map_fd);
    struct rules_map_key rules_map_key;
    
    rules_map_key.rule_key = *tuple_key;
    rules_map_key.rule_mask = *new_rule_tuple_mask;
    rules_map_key.rule_value = *tuple_value;
    if(bpf_map_update_elem(map_fd, &rules_map_key, key_from_tuple, BPF_NOEXIST)<0){
        printf("failed to create Rules map with this id\n");
        return -1;
    }
    bpf_obj_pin(map_fd, "/sys/fs/bpf/tc/globals/rules_map");
    printf("Rules map created\n"); 
    return map_fd;         

} 
    
//work if table sorted based on priority
bool CheckTuples(struct tuple_mask *new_mask, struct tuple_mask *matching_mask){
    printf("checking for similar tuple\n");
    struct tuple_mask current_mask = {0};
    struct tuple_mask_value value;
    int temp;
    struct tuple_mask key = {-1}, prev_key = {-1}, key1;
    int masks_table = get_BPF_prog_by_name(BPF_MASK_TBL_MAP_NAME);
    while (bpf_map_get_next_key(masks_table, &prev_key, &key)==0){
        temp = bpf_map_lookup_elem(masks_table, &key, &value);
        if(temp>=0){
            if (CanInsert(&key, new_mask)){
                printf("can insert to tuple %d\n", value.tuple_id);
                //struct tuple_mask found_mask = key;
                *matching_mask = key;
                return true;
            }    
        }
        prev_key = key;

    }  
    return false;
}
struct tuple_key maskRule(struct tuple_key *rule_key, struct tuple_mask *tuple_mask){
    printf("masking rule\n");
    struct tuple_key masked_key;
    __u32 *tmp = ((__u32 *) &masked_key);
    printf("mask 1 = %llx \n", tuple_mask->mask3[1]);
    printf("key 1 = %llx \n", rule_key->field1);
    __u32 *mask = ((__u32 *) tuple_mask); //take the mask and treat it as it were the address of __u32
    for (int j = 0; j< sizeof(struct tuple_mask)/4; j++){    
            printf("masking next next 4 bytes of: %llx with mask %llx\n",  *(((__u32 *) rule_key) +j), mask[j]);
            tmp[j] = ((__u32 *) rule_key)[j] & mask[j];
    }
    printf("Looking up key %llx %llx %llx \n", masked_key.field1, masked_key.field2, masked_key.field3); 
    
    return masked_key;
} 
int getTupleByID(int tuple_id){
     __u32 inner_map_id;
    bpf_map_lookup_elem(get_BPF_prog_by_name(BPF_TUPLES_MAP_NAME), &tuple_id, &inner_map_id);
    int inner_map_fd = bpf_map_get_fd_by_id(inner_map_id);
    return inner_map_fd;
}
//this one will override existing key if its gonna be the same
void addToTuple(struct tuple_key * new_rule, struct tuple_value *new_rule_value, int tuple_id){
    printf("adding rule to existing tuple\n");
    int inner_map_fd = getTupleByID(tuple_id);
    printf("tuple id : %d\n", tuple_id);
    if(bpf_map_update_elem(inner_map_fd, new_rule, new_rule_value, 0)<0){
        printf("failed to add to Tuple\n");
    }
}
bool compareTupleKeys(struct tuple_key *first_key, struct tuple_key *second_key){
    printf(" key1 field1 = %x \n", first_key->field1);
    printf(" key1 field2 = %x \n", first_key->field2);
    printf(" key1 field3 = %x \n", first_key->field3);
    printf(" key2 field1 = %x \n", second_key->field1);
    printf(" key2 field2 = %x \n", second_key->field2);
    printf(" key2 field3 = %x \n", second_key->field3);
    if((first_key->field1 == second_key->field1) &
        (first_key->field2 == second_key->field2) &
        (first_key->field3 == second_key->field3)){
        return true;					
    }
    return false;
}
int collisionsNumber(struct tuple_key *key_from_tuple){
	int temp;
	int collisions =0;
	struct rules_map_key key={-1},prev_key = {-1};
    struct tuple_key value;
    printf("pointer value = %p\n", &value);
    struct tuple_key temp_key;
    int rules_table = get_BPF_prog_by_name(BPF_RULES_MAP_NAME);
	while(bpf_map_get_next_key(rules_table, &prev_key, &key)==0){
		temp = bpf_map_lookup_elem(rules_table, &key, &value);
       

		if (temp>=0){
            printf("element found \n");

			if (compareTupleKeys(key_from_tuple, &value)){
                printf("collision found\n");
				collisions ++;
                }
     
            }
        
        prev_key = key;
    }
    return collisions;
}


void addToRulesTable(struct tuple_key * new_rule, struct tuple_value *new_rule_value, struct tuple_mask *rule_mask, struct tuple_mask *matching_tuple_mask){
    printf("adding rule to rules table\n");
    
    struct tuple_key masked_key = maskRule(new_rule, matching_tuple_mask);
    if (get_BPF_prog_by_name("rules_map")<0){
        printf("create rules map\n");
        int rules_map = CreateRulesMap(new_rule, rule_mask, new_rule_value, &masked_key);
    }
    struct rules_map_key rules_map_key;
    rules_map_key.rule_key = *new_rule;
    rules_map_key.rule_mask = *rule_mask;
    rules_map_key.rule_value = *new_rule_value;
    int rules_map_prog = get_BPF_prog_by_name("rules_map");
    if(bpf_map_update_elem(rules_map_prog, &rules_map_key, &masked_key, 0)<0){
        printf("failed to add to Rules Table");
    }
    
}

void InsertRule(struct tuple_key *new_rule, struct tuple_value *new_rule_value, struct tuple_mask *new_mask){
    printf("tuple merge insert\n");
    struct tuple_mask matching_tuple_mask;
    bool tuple_found = CheckTuples(new_mask, &matching_tuple_mask);
    struct tuple_mask_value value;
    printf("mask 1 = %llx \n", new_mask->mask1[0]);
    printf("key 1 = %llx \n", matching_tuple_mask.mask1[0]);
    
    if (tuple_found){
        printf("can insert to existing tuple\n");
        struct tuple_key masked_key = maskRule(new_rule, &matching_tuple_mask);
        if(bpf_map_lookup_elem(get_BPF_prog_by_name(BPF_MASK_TBL_MAP_NAME), &matching_tuple_mask, &value) == 0){
            addToTuple(&masked_key, new_rule_value, value.tuple_id);
            addToRulesTable(new_rule, new_rule_value, new_mask, &matching_tuple_mask);
            int collision_number = collisionsNumber(&masked_key);
            printf("collision number = %d\n", collision_number);
            if(collision_number = MAX_NUM_COLLISIONS){
                printf("collsion number reached");
            }
             
        }
        else printf("error mask not found\n ");
    }
    else {
    struct tuple_key masked_key = maskRule(new_rule, new_mask);
       int newTuple = CreateTuple(&masked_key, new_rule_value, new_mask);
       addToRulesTable(new_rule, new_rule_value, new_mask, new_mask);
    }

}

int main (int argc, char **argv){
 
    struct tuple_key default_key = {
            .field1 = 0x1,
            .field2 = 0xFF,
            .field3 = 0xFC,
            .pad = 0,
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
            //InsertRule(&default_key, &default_value, &default_mask);
        }
        else {    
        printf("adding key %lx %lx %lx\n", strtol(argv[3], NULL, 0), strtoul(argv[4], NULL, 0), strtol(argv[5], NULL, 0));
        printf("with mask %ld %ld %ld\n", strtol(argv[10], NULL, 16), strtol(argv[11], NULL, 16), strtol(argv[12], NULL, 16));
        

           struct tuple_key key = {
               .field1 = strtol(argv[3], NULL, 16),
               .field2 = strtol(argv[4], NULL, 16),
               .field3 = strtol(argv[5], NULL, 16),
               .pad = 0,
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
                .mask3[0] = (strtol(argv[12], NULL, 16) >> 0),
                .mask3[1] = (strtol(argv[12], NULL, 16) >> 8),
                .mask3[2] = (strtol(argv[12], NULL, 16) >> 16),
                .mask3[3] = (strtol(argv[12], NULL, 16) >> 24)
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
