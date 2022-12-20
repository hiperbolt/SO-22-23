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

        // If it is a symlink, we need to follow it until we get to an actual file.
        while (get_inode_type(inode) == T_SYMLINK) {
            char *symlink = inode_get_symlink_target(inode);

            // Get the inode of the symlink target
            int symlink_inum = tfs_lookup(symlink, inode_get(ROOT_DIR_INUM));
            if (symlink_inum < 0) {
                return -1;
            }

            inode = inode_get(symlink_inum);
            ALWAYS_ASSERT(inode != NULL, "tfs_write: inode of symlink target deleted");
        }

        size_t inode_size = get_inode_size(inode);

        // Truncate (if requested)
        if (mode & TFS_O_TRUNC) {
            if (inode_size > 0) {
                data_block_free(get_inode_data_block(inode));
                set_inode_size(inode, 0);
            }
        }
        // Determine initial offset
        if (mode & TFS_O_APPEND) {
            offset = inode_size;
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
 * @brief Creates a symbolic link to a file.
 * 
 * @param target_file - the file to be linked to
 * @param source_file - the file to be created
 * @return int - 0 on success, -1 on failure
 */
int tfs_sym_link(char const *target_file, char const *source_file) {
    // Checks if the path names are valid
    if (!valid_pathname(target_file) || !valid_pathname(source_file)) {
        return -1;
    }

    // Get the root directory inode
    inode_t *root_dir_inode = inode_get(ROOT_DIR_INUM);
    ALWAYS_ASSERT(root_dir_inode != NULL,
                  "tfs_open: root dir inode must exist");

    // Get the inumber of the target file (making sure it exists)
    int target_inum = tfs_lookup(target_file, root_dir_inode);
    if (target_inum < 0) {
        return -1; // target file does not exist
    }

    // Make sure a file with the same name does not already exist
    if (tfs_lookup(source_file, root_dir_inode) >= 0) {
        return -1;
    }

    // Create inode of type T_SYMLINK
    int source_inum = inode_create(T_SYMLINK);
    if (source_inum == -1) {
        return -1; // no space in inode table
    }

    if (inode_fill_symlink(source_inum, target_file) == -1) {
        return -1;
    }
    
    // Add entry in the root directory
    if (add_dir_entry(root_dir_inode, source_file + 1, source_inum) == -1) {
        inode_delete(source_inum);
        return -1; // no space in directory
    }

    return 0;
}

/**
 * @brief Creates a hard link to a file.
 * 
 * @param target_file - the file to be linked to
 * @param source_file - the file to be created
 * @return int - 0 on success, -1 on failure
 */
int tfs_link(char const *target_file, char const *source_file) {
    // Checks if the path names are valid
    if (!valid_pathname(target_file) || !valid_pathname(source_file)) {
        return -1;
    }

    // Get the root directory inode
    inode_t *root_dir_inode = inode_get(ROOT_DIR_INUM);
    ALWAYS_ASSERT(root_dir_inode != NULL,
                  "tfs_open: root dir inode must exist");
    
    // Get the inumber of the target file (making sure it exists)
    int target_inum = tfs_lookup(target_file, root_dir_inode);
    if (target_inum < 0) {
        return -1; // target file does not exist
    }

    // Make sure the source file does not already exist
    int source_inum = tfs_lookup(source_file, root_dir_inode);
    if (source_inum >= 0) {
        return -1; // source file already exists
    }

    // Add entry in the root directory (skipping the initial '/' character)
    if (add_dir_entry(root_dir_inode, source_file + 1, target_inum) == -1) {
        return -1; // no space in directory
    }

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
    inode_t *inode = inode_get(get_open_file_inumber(file));
    ALWAYS_ASSERT(inode != NULL, "tfs_write: inode of open file deleted");

    // If it is a symlink, we need to follow it until we get to an actual file.
    while (get_inode_type(inode) == T_SYMLINK) {
        char *symlink = inode_get_symlink_target(inode);

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
    size_t file_offset = get_open_file_offset(file);
    if (to_write + file_offset > block_size) {
        to_write = block_size - file_offset;
    }

    if (to_write > 0) {
        if (get_inode_size(inode) == 0) {
            // If empty file, allocate new block
            int bnum = data_block_alloc();
            if (bnum == -1) {
                return -1; // no space
            }

            set_inode_data_block(inode, bnum);
        }

        void *block = data_block_get(get_inode_data_block(inode));
        ALWAYS_ASSERT(block != NULL, "tfs_write: data block deleted mid-write");

        // Perform the actual write
        memcpy(block + file_offset, buffer, to_write);

        // The offset associated with the file handle is incremented accordingly
        set_open_file_offset(file, file_offset + to_write);
        if (file_offset > get_inode_size(inode)) {
            set_inode_size(inode, file_offset);
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
    inode_t const *inode = inode_get(get_open_file_inumber(file));
    ALWAYS_ASSERT(inode != NULL, "tfs_read: inode of open file deleted");

    // Determine how many bytes to read
    size_t file_offset = get_open_file_offset(file);
    size_t to_read = get_inode_size(inode) - file_offset;
    if (to_read > len) {
        to_read = len;
    }

    if (to_read > 0) {
        void *block = data_block_get(get_inode_data_block(inode));
        ALWAYS_ASSERT(block != NULL, "tfs_read: data block deleted mid-read");

        // Perform the actual read
        memcpy(buffer, block + file_offset, to_read);
        // The offset associated with the file handle is incremented accordingly
        set_open_file_offset(file, file_offset + to_read);
    }

    return (ssize_t)to_read;
}

int tfs_unlink(char const *target) {
    // Checks if the path name is valid
    if (!valid_pathname(target)) {
        return -1;
    }

    // Get the root directory inode
    inode_t *root_dir_inode = inode_get(ROOT_DIR_INUM);
    ALWAYS_ASSERT(root_dir_inode != NULL,
                  "tfs_open: root dir inode must exist");

    // Get the inumber of the target file (making sure it exists)
    int target_inum = tfs_lookup(target, root_dir_inode);
    if (target_inum < 0) {
        return -1; // target file does not exist
    }

    inode_t * target_inode = inode_get(target_inum);

    switch(get_inode_type(target_inode)) {
        case T_FILE:
            // Remove the entry from the root directory
            if(clear_dir_entry(root_dir_inode, target + 1) == -1) {
                return -1; // Error removing entry from root directory
            }
            // Decrement the hard link count
            decrement_inode_hardlinks(target_inode);

            // If the hard link count is 0, free the data block
            if (get_inode_hardlinks(target_inode) == 0) {
                inode_delete(target_inum);
            }
            return 0;
        case T_SYMLINK:
            // If it is a symlink, we can delete it
            clear_dir_entry(root_dir_inode, target+1);
            inode_delete(target_inum);
            return 0;
        case T_DIRECTORY:
            return -1; //cannot unlink directory.
        default:
            PANIC("tfs_unlink: invalid inode type");
            return -1; // invalid inode type
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
