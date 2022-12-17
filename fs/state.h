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
 * dir_entry_mutex is used to protect the directory entry itself from concurrent access.
 */
typedef struct {
    char d_name[MAX_FILE_NAME];
    int d_inumber;
    pthread_mutex_t d_mutex;
} dir_entry_t;


typedef enum { T_FILE, T_DIRECTORY , T_SYMLINK} inode_type;

/**
 * Inode
 * 
 * Defined this way to allow for symlinks to be efficiently stored on the inode itself.
 * Inode size is 40 + inode_type enum bytes.
 * 
 * inode_mutex is used to protect the inode from concurrent access.
 * 
 */
typedef struct{
    inode_type i_node_type;
    pthread_mutex_t i_mutex;
    union {
        struct {
            int i_hardlinks;
            size_t i_size;
            int i_data_block;
        };
        char i_symlink[MAX_FILE_NAME];
    };
} inode_t;



typedef enum { FREE = 0, TAKEN = 1 } allocation_state_t;

/**
 * Open file entry (in open file table)
 * 
 * open_file_mutex is used to protect the open file entry from concurrent access.
 */
typedef struct {
    int of_inumber;
    size_t of_offset;
    pthread_mutex_t open_file_mutex;
} open_file_entry_t;


int state_init(tfs_params);
int state_destroy(void);

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

#endif // STATE_H
