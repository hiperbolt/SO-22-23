#include "operations.h"
#include "config.h"
#include "state.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "betterassert.h"

extern pthread_rwlock_t inode_table_rwlock;
extern pthread_rwlock_t open_file_table_rwlock;
extern pthread_rwlock_t dir_entries_table_rwlock;

extern pthread_mutex_t * inode_mutexes_table;
extern pthread_mutex_t * open_file_entry_mutexes;


tfs_params tfs_default_params() {
    tfs_params params = {
        .max_inode_count = 64,
        .max_block_count = 1024,
        .max_open_files_count = 16,
        .block_size = 1024,
    };
    return params;
}

int tfs_init(tfs_params const *params_ptr) {
    tfs_params params;
    if (params_ptr != NULL) {
        params = *params_ptr;
    } else {
        params = tfs_default_params();
    }

    if (state_init(params) != 0) {
        return -1;
    }

    // create root inode
    int root = inode_create(T_DIRECTORY);
    if (root != ROOT_DIR_INUM) {
        return -1;
    }
    return 0;
}

int tfs_destroy() {
    if (state_destroy() != 0) {
        return -1;
    }
    return 0;
}

static bool valid_pathname(char const *name) {
    return name != NULL && strlen(name) > 1 && name[0] == '/';
}

/**
 * Looks for a file.
 *
 * Note: as a simplification, only a plain directory space (root directory only)
 * is supported.
 *
 * Input:
 *   - name: absolute path name
 *   - root_inode: the root directory inode
 * Returns the inumber of the file, -1 if unsuccessful.
 */
static int tfs_lookup(char const *name, inode_t const *root_inode) {
    ALWAYS_ASSERT(root_inode != NULL, "tfs_lookup: root inode must exist");

    if (!valid_pathname(name)) {
        return -1;
    }

    // skip the initial '/' character
    name++;

    return find_in_dir(root_inode, name);
}

int tfs_open(char const *name, tfs_file_mode_t mode) {
    // Checks if the path name is valid
    if (!valid_pathname(name)) {
        return -1;
    }

    inode_t *root_dir_inode = inode_get(ROOT_DIR_INUM);
    ALWAYS_ASSERT(root_dir_inode != NULL,
                  "tfs_open: root dir inode must exist");
    int inum = tfs_lookup(name, root_dir_inode);
    size_t offset;

    if (inum >= 0) {
        // The file already exists
        inode_t *inode = inode_get(inum);
        ALWAYS_ASSERT(inode != NULL,
                      "tfs_open: directory files must have an inode");

        // If the file is a symlink, we need to follow it until we find a T_FILE inode
        // This is a very problematic area concurrency-wise. Should be refactored eventually.
        pthread_mutex_lock(&inode_mutexes_table[inum]);
        inode_type type = get_inode_type(inode);
        pthread_mutex_unlock(&inode_mutexes_table[inum]);
        while (type == T_SYMLINK){
            pthread_mutex_lock(&inode_mutexes_table[inum]);
            char * symlink = inode_get_symlink(inum);
            pthread_mutex_unlock(&inode_mutexes_table[inum]);
            inum = tfs_lookup(symlink, root_dir_inode);
            if (inum < 0){
                return -1;
            }
            inode = inode_get(inum);
            ALWAYS_ASSERT(inode != NULL,
                          "tfs_open: symlink files must have an inode");
             pthread_mutex_lock(&inode_mutexes_table[inum]);             
            type = get_inode_type(inode);
            pthread_mutex_unlock(&inode_mutexes_table[inum]);
        }

        // Truncate (if requested)
        if (mode & TFS_O_TRUNC) {
            pthread_mutex_lock(&inode_mutexes_table[inum]);
            if (get_inode_size(inode) > 0) {
                data_block_free(get_inode_data_block(inode));
                set_inode_size(inode, 0);
            }
            pthread_mutex_unlock(&inode_mutexes_table[inum]);
        }
        // Determine initial offset
        if (mode & TFS_O_APPEND) {
            pthread_mutex_lock(&inode_mutexes_table[inum]);
            offset = get_inode_size(inode);
            pthread_mutex_unlock(&inode_mutexes_table[inum]);
        } else {
            offset = 0;
        }
    } else if (mode & TFS_O_CREAT) {
        // The file does not exist; the mode specified that it should be created
        // Create inode
        inum = inode_create(T_FILE);
        if (inum == -1) {
            return -1; // no space in inode table
        }

        // Add entry in the root directory
        if (add_dir_entry(root_dir_inode, name + 1, inum) == -1) {
            inode_delete(inum);
            return -1; // no space in directory
        }

        offset = 0;
    } else {
        return -1;
    }

    // Finally, add entry to the open file table and return the corresponding
    // handle
    return add_to_open_file_table(inum, offset);

    // Note: for simplification, if file was created with TFS_O_CREAT and there
    // is an error adding an entry to the open file table, the file is not
    // opened but it remains created
}

/**
 * Creates a symbolic link from target to source
 * 
 * 
 * @param target 
 * @param link_name 
 * @return int 
 */
int tfs_sym_link(char const *source_file, char const *target_file) {
    // Check if both paths are valid
    if (!valid_pathname(target_file) || !valid_pathname(source_file)) {
        return -1;
    }

    // Make sure the root dir inode exists, and get it.
    inode_t *root_dir_inode = inode_get(ROOT_DIR_INUM);
    ALWAYS_ASSERT(root_dir_inode != NULL,
                "tfs_open: root dir inode must exist");

    // Check if the target file doesn't already exist
    int target_inum = tfs_lookup(target_file, root_dir_inode);
    if (target_inum >= 0) {
        return -1;
    }

    // Check the source file exists
    int source_inum = tfs_lookup(source_file, root_dir_inode);
    if (source_inum < 0) {
        return -1;
    }

    // We're going to create a new inode for the symlink
    int inum = inode_create(T_SYMLINK);
    if (inum == -1) {
        return -1; // no space in inode table
    }

    // Copy the source file name into the symlink
    pthread_mutex_lock(&inode_mutexes_table[inum]);
    if(inode_set_symlink(inum, source_file) == -1) {
        pthread_mutex_unlock(&inode_mutexes_table[inum]);
        return -1;
    }
    pthread_mutex_unlock(&inode_mutexes_table[inum]);
    
    // Add entry in the root directory
    if (add_dir_entry(root_dir_inode, target_file + 1, inum) == -1) {
        inode_delete(inum);
        return -1; // no space in directory
    }

    return 0;
}

/**
 * Creates a hard-link from a new target_file to an existing source_file corresponding inumber.
 *
 * Input:
 *  - target_file - To create target file name.
 *  - source_file - Existing source file name.
 */

int tfs_link(char const *source_file, char const *target_file) {
    // Check if both paths are valid
    if (!valid_pathname(target_file) || !valid_pathname(source_file)) {
            return -1;
    }
    
    // Make sure the root dir inode exists, and get it.
    inode_t *root_dir_inode = inode_get(ROOT_DIR_INUM);
    ALWAYS_ASSERT(root_dir_inode != NULL,
                    "tfs_open: root dir inode must exist");

    // Get source_file inum.
    int source_inum = tfs_lookup(source_file, root_dir_inode);
    if (source_inum < 0) {
        return -1;
    }

    // Get source file inode.
    inode_t *source_inode = inode_get(source_inum);
        ALWAYS_ASSERT(source_inode != NULL,
                        "tfs_link: source file must have an inode");

    // Check if the source file is a symlink
    pthread_mutex_lock(&inode_mutexes_table[source_inum]);
    inode_type source_type = get_inode_type(source_inode);
    pthread_mutex_unlock(&inode_mutexes_table[source_inum]);
    if (source_type == T_SYMLINK) {
        return -1; // cannot hardlink to a symlink
    }

    // Check if the target file doesn't already exist
    int target_inum = tfs_lookup(target_file, root_dir_inode);
    if (target_inum >= 0) {
        return -1;
    }

    // We're going to create a new directory entry, in this directory, with the provided name and the source file inum.
    if (add_dir_entry(root_dir_inode, target_file + 1, source_inum) == -1) {
        return -1; // no space in directory
    }

    // Increment the source file link count.
    pthread_mutex_lock(&inode_mutexes_table[source_inum]);
    increment_inode_hardlinks(source_inode);
    pthread_mutex_unlock(&inode_mutexes_table[source_inum]);
    return 0;

}

int tfs_close(int fhandle) {
    open_file_entry_t *file = get_open_file_entry(fhandle);
    if (file == NULL) {
        return -1; // invalid fd
    }

    remove_from_open_file_table(fhandle);

    return 0;
}

ssize_t tfs_write(int fhandle, void const *buffer, size_t to_write) {
    open_file_entry_t *file = get_open_file_entry(fhandle);
    if (file == NULL) {
        return -1;
    }

    //  From the open file table entry, we get the inode
    int file_inum = get_open_file_inumber(file);
    inode_t *inode = inode_get(file_inum);
    ALWAYS_ASSERT(inode != NULL, "tfs_write: inode of open file deleted");

    // If it is a symlink, we need to follow it until we get to an actual file.
    pthread_mutex_lock(&inode_mutexes_table[file_inum]);
    inode_type type = get_inode_type(inode);
    pthread_mutex_unlock(&inode_mutexes_table[file_inum]);
    while (type == T_SYMLINK) {
        pthread_mutex_lock(&inode_mutexes_table[file_inum]);
        char *symlink = inode_get_symlink(file_inum);
        pthread_mutex_unlock(&inode_mutexes_table[file_inum]);

        // Get the inode of the symlink target
        int inum = tfs_lookup(symlink, inode_get(ROOT_DIR_INUM));
        if (inum < 0) {
            return -1;
        }

        inode = inode_get(inum);
        ALWAYS_ASSERT(inode != NULL, "tfs_write: inode of symlink target deleted");
    }

    // Determine how many bytes to write
    size_t block_size = state_block_size();
    pthread_mutex_lock(&open_file_entry_mutexes[fhandle]);
    size_t file_offset = get_open_file_offset(file);
    pthread_mutex_unlock(&open_file_entry_mutexes[fhandle]);
    if (to_write + file_offset > block_size) {
        to_write = block_size - file_offset;
    }

    /**
     * Critical section!
     * 
     * Reading and writing to inode. Reading and writing to openfile.
     */
    if (to_write > 0) {
        pthread_mutex_lock(&inode_mutexes_table[file_inum]);
        size_t inode_size = get_inode_size(inode);
        pthread_mutex_unlock(&inode_mutexes_table[file_inum]);
        if (inode_size == 0) {
            // If empty file, allocate new block
            int bnum = data_block_alloc();
            if (bnum == -1) {
                return -1; // no space
            }
            pthread_mutex_lock(&inode_mutexes_table[file_inum]);
            set_inode_data_block(inode, bnum);
            pthread_mutex_unlock(&inode_mutexes_table[file_inum]);
        }
        pthread_mutex_lock(&inode_mutexes_table[file_inum]);
        void *block = data_block_get(get_inode_data_block(inode));
        pthread_mutex_unlock(&inode_mutexes_table[file_inum]);
        ALWAYS_ASSERT(block != NULL, "tfs_write: data block deleted mid-write");

        // Perform the actual write
        memcpy(block + file_offset, buffer, to_write);

        // The offset associated with the file handle is incremented accordingly
        pthread_mutex_lock(&open_file_entry_mutexes[fhandle]);
        increment_open_file_offset(file, to_write);
        if (get_open_file_offset(file) > inode_size) {
            pthread_mutex_lock(&inode_mutexes_table[file_inum]);
            set_inode_size(inode, get_open_file_offset(file));
            pthread_mutex_unlock(&inode_mutexes_table[file_inum]);
        }
        pthread_mutex_unlock(&open_file_entry_mutexes[fhandle]);
        
    }

    return (ssize_t)to_write;
}

ssize_t tfs_read(int fhandle, void *buffer, size_t len) {
    open_file_entry_t *file = get_open_file_entry(fhandle);
    if (file == NULL) {
        return -1;
    }

    // From the open file table entry, we get the inode
    pthread_mutex_lock(&open_file_entry_mutexes[fhandle]);
    int inum = get_open_file_inumber(file);
    pthread_mutex_unlock(&open_file_entry_mutexes[fhandle]);

    inode_t * inode = inode_get(inum);

    ALWAYS_ASSERT(inode != NULL, "tfs_read: inode of open file deleted");

    // If it is a symlink, we need to follow it until we get to an actual file.
    pthread_mutex_lock(&inode_mutexes_table[inum]);
    inode_type type = get_inode_type(inode);
    pthread_mutex_unlock(&inode_mutexes_table[inum]);
    while (type == T_SYMLINK) {
        pthread_mutex_lock(&inode_mutexes_table[inum]);
        char *symlink = inode_get_symlink(inum);
        pthread_mutex_lock(&inode_mutexes_table[inum]);

        // Get the inode of the symlink target
        inum = tfs_lookup(symlink, inode_get(ROOT_DIR_INUM));
        if (inum < 0) {
            return -1;
        }

        inode = inode_get(inum);
        ALWAYS_ASSERT(inode != NULL, "tfs_read: inode of symlink target deleted");
        pthread_mutex_lock(&inode_mutexes_table[inum]);
        type = get_inode_type(inode);
        pthread_mutex_unlock(&inode_mutexes_table[inum]);
    }

    
    // Determine how many bytes to read
    pthread_mutex_lock(&inode_mutexes_table[inum]);
    pthread_mutex_lock(&open_file_entry_mutexes[fhandle]);
    size_t to_read = get_inode_size(inode) - get_open_file_offset(file);
    pthread_mutex_unlock(&open_file_entry_mutexes[fhandle]);
    pthread_mutex_unlock(&inode_mutexes_table[inum]);

    if (to_read > len) {
        to_read = len;
    }

    if (to_read > 0) {
        pthread_mutex_lock(&inode_mutexes_table[inum]);
        void *block = data_block_get(get_inode_data_block(inode));
        pthread_mutex_unlock(&inode_mutexes_table[inum]);
        ALWAYS_ASSERT(block != NULL, "tfs_read: data block deleted mid-read");

        pthread_mutex_lock(&open_file_entry_mutexes[fhandle]);
        // Perform the actual read
        memcpy(buffer, block + get_open_file_offset(file), to_read);
        // The offset associated with the file handle is incremented accordingly
        increment_open_file_offset(file, to_read);
        pthread_mutex_unlock(&open_file_entry_mutexes[fhandle]);
    }
    
    return (ssize_t)to_read;
}

int tfs_unlink(char const *target) {
    // Check if path is valid
    if (!valid_pathname(target)) {
        return -1;
    }

    // Get the root dir inode
    inode_t *root_dir_inode = inode_get(ROOT_DIR_INUM);
    ALWAYS_ASSERT(root_dir_inode != NULL,
                "tfs_unlink: root dir inode must exist");

    // Get the inode number of the file we want to delete
    int inum = tfs_lookup(target, root_dir_inode);
    if (inum == -1) {
        return -1;
    }

    // Get the inode
    inode_t *target_inode = inode_get(inum);
    ALWAYS_ASSERT(target_inode != NULL, "tfs_unlink: target inode must exist");

    /**
     * Critical section!
     * 
     * Reading inode. Reading and writing to openfile.
     */
    // First we need to determine if it is a file (whether it be a directory or not) or if it is a symlink
    pthread_mutex_lock(&inode_mutexes_table[inum]);
    inode_type target_type = get_inode_type(target_inode);
    pthread_mutex_unlock(&inode_mutexes_table[inum]);

    switch (target_type)
    {
    case T_FILE:
        // If it is a file, we need to decrement the hard link count
        pthread_mutex_lock(&inode_mutexes_table[inum]);
        decrement_inode_hardlinks(target_inode);
        clear_dir_entry(root_dir_inode, target + 1);
        // If the hard link count is 0, we need to delete the file
        if(get_inode_hardlinks(target_inode) == 0){
            pthread_mutex_unlock(&inode_mutexes_table[inum]);
            inode_delete(inum);
            return 0;
        }
        pthread_mutex_unlock(&inode_mutexes_table[inum]);
        return 0;

    case T_DIRECTORY:
        PANIC("tfs_unlink: cannot delete a directory");
        return -1;

    case T_SYMLINK:
        // If it is a symlink, we can delete it
        clear_dir_entry(root_dir_inode, target+1);
        inode_delete(inum);
        return 0;

    default:
        PANIC("tfs_unlink: invalid inode type");
        return -1;
    }
}

int tfs_copy_from_external_fs(char const *source_path, char const *dest_path){
    
    // Open the soure file in reading mode and checks if its null
    FILE *source = fopen(source_path, "r");
    if(source == NULL){
        return -1;
    }

    // Opens or creates the destination file 
    int dest = tfs_open(dest_path, TFS_O_CREAT | TFS_O_TRUNC);
    if (dest == -1){
        fclose(source);
        return -1;
    }

    tfs_params params = tfs_default_params();
    size_t size_of_buffer = params.block_size;
    char buffer[size_of_buffer];
    size_t size;
    memset(buffer, 0, sizeof(buffer));
    // Gets the text from the source file and copies it to the buffer
    size = fread(buffer, sizeof(char), sizeof(buffer), source);
    // Copies the text form the buffer and overwrites it on the destination file
    if(tfs_write(dest, buffer, size) == -1){
        fclose(source);
        tfs_close(dest);
        return -1;
    }

    if(fclose(source) == EOF){
        tfs_close(dest);
        return -1;
    }

    if(tfs_close(dest) == -1){
        return -1;
    }
    return 0;
}