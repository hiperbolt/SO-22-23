#include "operations.h"
#include "config.h"
#include "state.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "betterassert.h"



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
    // TODO: assert that root_inode is the root directory
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

        // Truncate (if requested)
        if (mode & TFS_O_TRUNC) {
            if (inode->i_size > 0) {
                data_block_free(inode->i_data_block);
                inode->i_size = 0;
            }
        }
        // Determine initial offset
        if (mode & TFS_O_APPEND) {
            offset = inode->i_size;
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
int tfs_sym_link(char const *target_file, char const *source_file) {
    // Check if both paths are valid
    if (!valid_pathname(target_file) || !valid_pathname(source_file)) {
        return -1;
    }

    // Make sure the root dir inode exists, and get it.
    inode_t *root_dir_inode = inode_get(ROOT_DIR_INUM);
    ALWAYS_ASSERT(root_dir_inode != NULL,
                "tfs_open: root dir inode must exist");

    // We're going to create a new inode for the symlink
    int inum = inode_create(T_SYMLINK);
    if (inum == -1) {
        return -1; // no space in inode table
    }

    inode_t *inode = inode_get(inum);
    strcpy(inode->i_symlink, source_file);

    // Add entry in the root directory
    if (add_dir_entry(root_dir_inode, target_file, inum) == -1) {
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

int tfs_link(char const *target_file, char const *source_file) {
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
  // Get source file inode.
  inode_t *source_inode = inode_get(source_inum);

  if(source_inum >= 0){
    // We're going to create a new directory entry, in this directory, with the provided name and the source file inum
    // TODO: deal with errors from add_dir_entry
    add_dir_entry(root_dir_inode, target_file, source_inum);
    // We need to increment the source file's hard-link count.
    source_inode->i_hardlinks++;
  } else {
    // If the file does not exist.
    return -1;
  }
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
    inode_t *inode = inode_get(file->of_inumber);
    ALWAYS_ASSERT(inode != NULL, "tfs_write: inode of open file deleted");

    // Determine how many bytes to write
    size_t block_size = state_block_size();
    if (to_write + file->of_offset > block_size) {
        to_write = block_size - file->of_offset;
    }

    if (to_write > 0) {
        if (inode->i_size == 0) {
            // If empty file, allocate new block
            int bnum = data_block_alloc();
            if (bnum == -1) {
                return -1; // no space
            }

            inode->i_data_block = bnum;
        }

        void *block = data_block_get(inode->i_data_block);
        ALWAYS_ASSERT(block != NULL, "tfs_write: data block deleted mid-write");

        // Perform the actual write
        memcpy(block + file->of_offset, buffer, to_write);

        // The offset associated with the file handle is incremented accordingly
        file->of_offset += to_write;
        if (file->of_offset > inode->i_size) {
            inode->i_size = file->of_offset;
        }
    }

    return (ssize_t)to_write;
}

ssize_t tfs_read(int fhandle, void *buffer, size_t len) {
    open_file_entry_t *file = get_open_file_entry(fhandle);
    if (file == NULL) {
        return -1;
    }

    // From the open file table entry, we get the inode
    inode_t const *inode = inode_get(file->of_inumber);
    ALWAYS_ASSERT(inode != NULL, "tfs_read: inode of open file deleted");

    // Determine how many bytes to read
    size_t to_read = inode->i_size - file->of_offset;
    if (to_read > len) {
        to_read = len;
    }

    if (to_read > 0) {
        void *block = data_block_get(inode->i_data_block);
        ALWAYS_ASSERT(block != NULL, "tfs_read: data block deleted mid-read");

        // Perform the actual read
        memcpy(buffer, block + file->of_offset, to_read);
        // The offset associated with the file handle is incremented accordingly
        file->of_offset += to_read;
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

    // Get the inode
    inode_t *target_inode = inode_get(inum);

    // First we need to determine if it is a file (wether it be a directory or not) or if it is a symlink
    switch (target_inode->i_node_type)
    {
    case T_FILE:
        // If it is a file, we need to decrement the hard link count
        target_inode->i_hardlinks--;
        // If the hard link count is 0, we need to delete the file
        if(target_inode->i_hardlinks == 0){
            inode_delete(inum);
            clear_dir_entry(root_dir_inode, target);
        }
        return 0;
        break;

    case T_DIRECTORY:
        // If it is a directory, we need to check if it is empty. And if it is not the root directory
        if(inum == ROOT_DIR_INUM){
            return -1;
        }
        if(check_empty_dir(inum)){
            // If it is empty, we can delete it
            inode_delete(inum);
            clear_dir_entry(root_dir_inode, target);
            return 0;
        }
        break;

    case T_SYMLINK:
        // If it is a symlink, we can delete it
        inode_delete(inum);
        clear_dir_entry(root_dir_inode, target);
        break;
    default:
        PANIC("tfs_unlink: invalid inode type");
        return -1;
    }
}

int tfs_copy_from_external_fs(char const *source_path, char const *dest_path){
        
    FILE *source = fopen(&source_path, "r");
    int size_of_buffer = 128;

    if(source == NULL){
        return -1;
    }

    int dest = tfs_open(dest_path, TFS_O_CREAT);

    if (dest == -1){
        fclose(source);
        return -1;
    }

    char buffer[size_of_buffer];

    while(feof(source)){
        memset(buffer, 0, sizeof(buffer));
        if(fread(buffer, sizeof(buffer), sizeof(buffer[0]), source) < 0){
            fclose(source);
            tfs_close(dest);
            return -1;
        }
        if(tfs_write(dest, buffer, sizeof(buffer)) == -1){
            fclose(source);
            tfs_close(dest);
            return -1;
        }
    }

    if(fclose(source) == NULL){
        tfs_close(dest);
        return -1;
    }

    if(tfs_close(dest) == -1){
        return -1;
    }
}
