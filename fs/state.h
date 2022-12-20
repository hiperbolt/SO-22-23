#ifndef STATE_H
#define STATE_H

#include "config.h"
#include "operations.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pthread.h>


/**
 * Directory entry
 * 
 */
typedef struct {
    char d_name[MAX_FILE_NAME];
    int d_inumber;
    pthread_mutex_t d_mutex;
} dir_entry_t;


typedef enum { T_FILE, T_DIRECTORY , T_SYMLINK} inode_type;
typedef enum { ON_INODE, ON_DISK } symlink_location;

#define MAX_INODE_SYMLINK_SIZE 16 // 4 + 8 + 4 , padding is not guaranteed

/**
 * Inode
 * 
 * Defined this way to allow for symlinks to be efficiently stored on the inode itself.
 * Inode size is 40 + inode_type enum bytes.
 * 
 * 
 */
typedef struct{
    inode_type i_node_type;
    symlink_location i_symlink_location;
    union {
        struct {
            int i_hardlinks;
            size_t i_size;
            int i_data_block;
        };
        char i_symlink[MAX_INODE_SYMLINK_SIZE];
    };
} inode_t;



typedef enum { FREE = 0, TAKEN = 1 } allocation_state_t;

/**
 * Open file entry (in open file table)
 * 
 */
typedef struct {
    int of_inumber;
    size_t of_offset;
    pthread_mutex_t open_file_mutex;
} open_file_entry_t;


int state_init(tfs_params);
int state_destroy(void);

pthread_rwlock_t * get_inode_table_rwlock(void);
pthread_rwlock_t * get_open_file_table_rwlock(void);
pthread_rwlock_t * get_dir_entries_table_rwlock(void);
pthread_mutex_t * get_inode_mutexes_table(void);
pthread_mutex_t * get_open_file_entry_mutexes(void);

size_t state_block_size(void);

int inode_create(inode_type n_type);
void inode_delete(int inumber);
inode_t *inode_get(int inumber);

int clear_dir_entry(inode_t *inode, char const *sub_name);
int add_dir_entry(inode_t *inode, char const *sub_name, int sub_inumber);
int find_in_dir(inode_t const *inode, char const *sub_name);

int data_block_alloc(void);
void data_block_free(int block_number);
void *data_block_get(int block_number);

int add_to_open_file_table(int inumber, size_t offset);
void remove_from_open_file_table(int fhandle);
open_file_entry_t *get_open_file_entry(int fhandle);

int inode_set_symlink(int inumber, char const *symlink);
char *inode_get_symlink(int inumber);

inode_type get_inode_type(inode_t *inode);
size_t get_inode_size(inode_t * inode);
void set_inode_size(inode_t * inode, size_t size);
int get_inode_data_block(inode_t * inode);
void set_inode_data_block(inode_t * inode, int block);
int get_inode_hardlinks(inode_t * inode);
void set_inode_hardlinks(inode_t * inode, int hardlinks);
void increment_inode_hardlinks(inode_t * inode);
void decrement_inode_hardlinks(inode_t * inode);
int get_open_file_inumber(open_file_entry_t *open_file_entry);
size_t get_open_file_offset(open_file_entry_t *entry);
void set_open_file_offset(open_file_entry_t *entry, size_t offset);
void increment_open_file_offset(open_file_entry_t *entry, size_t increment);


#endif // STATE_H
