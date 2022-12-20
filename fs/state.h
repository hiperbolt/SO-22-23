#ifndef STATE_H
#define STATE_H

#include "config.h"
#include "operations.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

/**
 * TécnicoFS Structures
 * 
 * Note: Each of these is going to have a corresponding vector of locks,
 * to account for the fact that in a real FS the locks would be
 * store in memory, and not on disk.
 * 
 */


/**
 * Directory entry
 * 
 */
typedef struct {
    char d_name[MAX_FILE_NAME];
    int d_inumber;
} dir_entry_t;

typedef enum { T_FILE, T_DIRECTORY, T_SYMLINK } inode_type;
typedef enum { ON_INODE, ON_BLOCK } symlink_loc;

/**
 * Inode
 * 
 * Note: the union is used to save space, as a file and a symbolic link
 * have different data structures. i_symlink_loc indicates where the symlink
 * is stored; if it is ON_INODE, then i_symlink is used, otherwise i_data_block
 * is used. This allows us to save space, as a symlink is usually short.
 * 
 */
#define MAX_INODE_SYMLINK_SIZE 16 // Accounting for padding we should actually have 24 bytes, but we'll use the guaranteed 16 to be safe.

typedef struct {
    inode_type i_node_type;
    symlink_loc i_symlink_loc;
    union {
            struct {
                int i_hardlinks;
                size_t i_size;
                int i_data_block;
            };
            char i_symlink[MAX_INODE_SYMLINK_SIZE]; // if symlink is short
        };
} inode_t;

typedef enum { FREE = 0, TAKEN = 1 } allocation_state_t;

/**
 * Open file entry (in open file table)
 */
typedef struct {
    int of_inumber;
    size_t of_offset;
} open_file_entry_t;

int state_init(tfs_params);
int state_destroy(void);

size_t state_block_size(void);

int inode_create(inode_type n_type);
int inode_fill_symlink(int inumber, const char *target);
char *inode_get_symlink_target(inode_t *inode);
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

int get_inode_data_block(const inode_t *inode);
void set_inode_data_block(inode_t *inode, int data_block);
size_t get_inode_size(const inode_t *inode);
void set_inode_size(inode_t *inode, size_t size);
int get_inode_type(const inode_t *inode);
int get_open_file_inumber(const open_file_entry_t *file);
size_t get_open_file_offset(const open_file_entry_t *file);
void set_open_file_offset(open_file_entry_t *file, size_t offset);
void increment_inode_hardlinks(inode_t *inode);
void decrement_inode_hardlinks(inode_t *inode);
int get_inode_hardlinks(const inode_t *inode);

#endif // STATE_H
