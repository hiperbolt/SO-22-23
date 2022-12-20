#include "state.h"
#include "betterassert.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>


/*
 * Persistent FS state
 * (in reality, it should be maintained in secondary memory;
 * for simplicity, this project maintains it in primary memory).
 */
static tfs_params fs_params;

// Inode table
static inode_t *inode_table;
static allocation_state_t *freeinode_ts;

// Data blocks
static char *fs_data; // # blocks * block size
static allocation_state_t *free_blocks;

/*
 * Volatile FS state
 */
static open_file_entry_t *open_file_table;
static allocation_state_t *free_open_file_entries;


// Convenience macros
#define INODE_TABLE_SIZE (fs_params.max_inode_count)
#define DATA_BLOCKS (fs_params.max_block_count)
#define MAX_OPEN_FILES (fs_params.max_open_files_count)
#define BLOCK_SIZE (fs_params.block_size)
#define MAX_DIR_ENTRIES (BLOCK_SIZE / sizeof(dir_entry_t))

/*
 * rwlocks
 *
 * inode_table_rwlock: protects inode table - the justification being that we might need to read the inode table's last element (or any type of 
 * position relative inode) and an inode might be deleted or added in the meantime. We make sure read operations are not mutually exclusive at the cost
 * of preventing simultaneous inode table modifications. A singular inode is protected by its own mutex (so we dont end up with a global inode lock).
 * 
 * open_file_table_rwlock: protects open file table - same logic as above
 * 
 * dir_entries_table: protects directory entries - Since there is only one directory (root), we exclude it from normal inode protection for the sake of granularity.
 * We protect the "table" (this is, the directory data block) for the same reason as above, while having a mutex for a singular dir entry.
 */


static inline bool valid_inumber(int inumber) {
    return inumber >= 0 && inumber < INODE_TABLE_SIZE;
}

static inline bool valid_block_number(int block_number) {
    return block_number >= 0 && block_number < DATA_BLOCKS;
}

static inline bool valid_file_handle(int file_handle) {
    return file_handle >= 0 && file_handle < MAX_OPEN_FILES;
}

size_t state_block_size(void) { return BLOCK_SIZE; }


/**
 * Do nothing, while preventing the compiler from performing any optimizations.
 *
 * We need to defeat the optimizer for the insert_delay() function.
 * Under optimization, the empty loop would be completely optimized away.
 * This function tells the compiler that the assembly code being run (which is
 * none) might potentially change *all memory in the process*.
 *
 * This prevents the optimizer from optimizing this code away, because it does
 * not know what it does and it may have side effects.
 *
 * Reference with more information: https://youtu.be/nXaxk27zwlk?t=2775
 *
 * Exercise: try removing this function and look at the assembly generated to
 * compare.
 */
static void touch_all_memory(void) { __asm volatile("" : : : "memory"); }

/**
 * Artifically delay execution (busy loop).
 *
 * Auxiliary function to insert a delay.
 * Used in accesses to persistent FS state as a way of emulating access
 * latencies as if such data structures were really stored in secondary memory.
 */
static void insert_delay(void) {
    for (int i = 0; i < DELAY; i++) {
        touch_all_memory();
    }
}

/**
 * Initialize FS state.
 *
 * Input:
 *   - params: TécnicoFS parameters
 *
 * Returns 0 if successful, -1 otherwise.
 *
 * Possible errors:
 *   - TFS already initialized.
 *   - malloc failure when allocating TFS structures.
 */
int state_init(tfs_params params) {
    fs_params = params;

    if (inode_table != NULL) {
        return -1; // already initialized
    }

    inode_table = malloc(INODE_TABLE_SIZE * sizeof(inode_t));
    freeinode_ts = malloc(INODE_TABLE_SIZE * sizeof(allocation_state_t));
    inode_mutexes_table = malloc(INODE_TABLE_SIZE * sizeof(pthread_mutex_t));
    fs_data = malloc(DATA_BLOCKS * BLOCK_SIZE);
    free_blocks = malloc(DATA_BLOCKS * sizeof(allocation_state_t));
    open_file_table = malloc(MAX_OPEN_FILES * sizeof(open_file_entry_t));
    free_open_file_entries =
        malloc(MAX_OPEN_FILES * sizeof(allocation_state_t));
    open_file_entry_mutexes = malloc(MAX_OPEN_FILES * sizeof(pthread_mutex_t));

    if (!inode_table || !freeinode_ts || !inode_mutexes_table || !fs_data || !free_blocks ||
        !open_file_table || !free_open_file_entries || !open_file_entry_mutexes) {
        return -1; // allocation failed
    }

    for (size_t i = 0; i < INODE_TABLE_SIZE; i++) {
        freeinode_ts[i] = FREE;
    }

    for (size_t i = 0; i < DATA_BLOCKS; i++) {
        free_blocks[i] = FREE;
    }

    for (size_t i = 0; i < MAX_OPEN_FILES; i++) {
        free_open_file_entries[i] = FREE;

    }

    // initialize rwlocks
    pthread_rwlock_init(&inode_table_rwlock, NULL);
    pthread_rwlock_init(&open_file_table_rwlock, NULL);
    pthread_rwlock_init(&dir_entries_table_rwlock, NULL);

    return 0;
}

/**
 * Destroy FS state.
 *
 * Returns 0 if succesful, -1 otherwise.
 */
int state_destroy(void) {
    // destroy rwlocks
    pthread_rwlock_destroy(&inode_table_rwlock);
    pthread_rwlock_destroy(&open_file_table_rwlock);
    pthread_rwlock_destroy(&dir_entries_table_rwlock);

    free(inode_table);
    free(freeinode_ts);
    free(fs_data);
    free(free_blocks);
    free(open_file_table);
    free(free_open_file_entries);

    inode_table = NULL;
    freeinode_ts = NULL;
    fs_data = NULL;
    free_blocks = NULL;
    open_file_table = NULL;
    free_open_file_entries = NULL;

    return 0;
}

/**
 * (Try to) Allocate a new inode in the inode table, without initializing its
 * data.
 *
 * Returns the inumber of the newly allocated inode, or -1 in the case of error.
 *
 * Possible errors:
 *   - No free slots in inode table.
 */
static int inode_alloc(void) {
    /**
     * Critical section!
     * 
     * Reading inode_table to check if inode is free. Writing to it to mark it.
     */
    pthread_rwlock_wrlock(&inode_table_rwlock);
    for (size_t inumber = 0; inumber < INODE_TABLE_SIZE; inumber++) {
        if ((inumber * sizeof(allocation_state_t) % BLOCK_SIZE) == 0) {
            insert_delay(); // simulate storage access delay (to freeinode_ts)
        }
        
        // Finds first free entry in inode table
        if (freeinode_ts[inumber] == FREE) {
            freeinode_ts[inumber] = TAKEN;
            pthread_mutex_init(&inode_mutexes_table[inumber], NULL);
            pthread_rwlock_unlock(&inode_table_rwlock);
            return (int)inumber;
        }
    }

    // no free inodes
    pthread_rwlock_unlock(&inode_table_rwlock);
    return -1;
}

/**
 * Create a new inode in the inode table.
 *
 * Allocates and initializes a new inode.
 * Directories will have their data block allocated and initialized, with i_size
 * set to BLOCK_SIZE. Regular files will not have their data block allocated
 * (i_size will be set to 0, i_data_block to -1).
 *
 * Input:
 *   - i_type: the type of the node (file or directory)
 *
 * Returns inumber of the new inode, or -1 in the case of error.
 *
 * Possible errors:
 *   - No free slots in inode table.
 *   - (if creating a directory) No free data blocks.
 */
int inode_create(inode_type i_type) {
    int inumber = inode_alloc();
    if (inumber == -1) {
        return -1; // no free slots in inode table
    }

    /**
     * Critical section!
     * 
     * Reading inode_table to fetch inode pointer.
     */
    pthread_rwlock_rdlock(&inode_table_rwlock);
    inode_t *inode = &inode_table[inumber];
    pthread_rwlock_unlock(&inode_table_rwlock);

    insert_delay(); // simulate storage access delay (to inode)

    /**
     * Critical section!
     * 
     * Writing to and reading from inode.
     */
    pthread_mutex_lock(&inode_mutexes_table[inumber]);
    inode->i_node_type = i_type;
    switch (i_type) {
    case T_DIRECTORY: {
        // Initializes directory (filling its block with empty entries, labeled
        // with inumber==-1)
        int b = data_block_alloc();
        if (b == -1) {
            // ensure fields are initialized
            inode->i_size = 0;
            inode->i_data_block = -1;

            // run regular deletion process
            inode_delete(inumber);
            
            pthread_mutex_unlock(&inode_mutexes_table[inumber]);
            return -1;
        }

        inode_table[inumber].i_size = BLOCK_SIZE;
        inode_table[inumber].i_data_block = b;

        dir_entry_t *dir_entry = (dir_entry_t *)data_block_get(b);
        ALWAYS_ASSERT(dir_entry != NULL,
                      "inode_create: data block freed while in use");

        for (size_t i = 0; i < MAX_DIR_ENTRIES; i++) {
            dir_entry[i].d_inumber = -1;

        }
    } break;
    case T_FILE:
        // In case of a new file, simply sets its size to 0
        inode_table[inumber].i_hardlinks = 1;
        inode_table[inumber].i_size = 0;
        inode_table[inumber].i_data_block = -1;
        break;
    case T_SYMLINK:
        // In case of a new symlink, set i_symlink to NULL
        strcpy(inode_table[inumber].i_symlink, "-1");
        break;
    default:
        pthread_mutex_unlock(&inode_mutexes_table[inumber]);
        PANIC("inode_create: unknown file type");
    }

    pthread_mutex_unlock(&inode_mutexes_table[inumber]);
    return inumber;
}


/**
 * Delete an inode.
 *
 * Input:
 *   - inumber: inode's number
 */
void inode_delete(int inumber) {
    // simulate storage access delay (to inode and freeinode_ts)
    insert_delay();
    insert_delay();

    ALWAYS_ASSERT(valid_inumber(inumber), "inode_delete: invalid inumber");

    /**
     * Critical section!
     * 
     * Writing inode_table to free inode. Writing to inode.
     */
    pthread_rwlock_wrlock(&inode_table_rwlock);
    ALWAYS_ASSERT(freeinode_ts[inumber] == TAKEN,
                  "inode_delete: inode already freed");

    if (inode_table[inumber].i_size > 0) {
        data_block_free(inode_table[inumber].i_data_block);

    }

    freeinode_ts[inumber] = FREE;
    pthread_mutex_destroy(&inode_mutexes_table[inumber]);
    pthread_rwlock_unlock(&inode_table_rwlock);
}

/**
 * Obtain a pointer to an inode from its inumber.
 *
 * Input:
 *   - inumber: inode's number
 *
 * Returns pointer to inode.
 */
inode_t *inode_get(int inumber) {
    ALWAYS_ASSERT(valid_inumber(inumber), "inode_get: invalid inumber");

    insert_delay(); // simulate storage access delay to inode

    /**
     * Critical section!
     * 
     * Reading inode_table to fetch inode pointer.
     */
    pthread_rwlock_rdlock(&inode_table_rwlock);
    inode_t *inode = &inode_table[inumber];
    pthread_rwlock_unlock(&inode_table_rwlock);

    return inode;
}

/**
 * Clear the directory entry associated with a sub file.
 *
 * Input:
 *   - inode: directory inode
 *   - sub_name: sub file name
 *
 * Returns 0 if successful, -1 otherwise.
 *
 * Possible errors:
 *   - inode is not a directory inode.
 *   - Directory does not contain an entry for sub_name.
 */
int clear_dir_entry(inode_t *inode, char const *sub_name) {
    insert_delay();

     /**
     * Critical section!
     * 
     * Reading inode.
     */
    // We find to find the inode inum
    long int inumber = inode - inode_table;
    pthread_mutex_lock(&inode_mutexes_table[inumber]);
    if (inode->i_node_type != T_DIRECTORY) {
        return -1; // not a directory
    }

    // Locates the block containing the entries of the directory
    dir_entry_t *dir_entry = (dir_entry_t *)data_block_get(inode->i_data_block);
    pthread_mutex_unlock(&inode_mutexes_table[inumber]);

    ALWAYS_ASSERT(dir_entry != NULL,
                  "clear_dir_entry: directory must have a data block");

     /**
     * Critical section!
     * 
     * Reading and writing dir_entries_table. Writing to dir_entry.
     */
    pthread_rwlock_wrlock(&dir_entries_table_rwlock);
    for (size_t i = 0; i < MAX_DIR_ENTRIES; i++) {
        if (!strcmp(dir_entry[i].d_name, sub_name)) {

            dir_entry[i].d_inumber = -1;
            memset(dir_entry[i].d_name, 0, MAX_FILE_NAME);

            pthread_rwlock_unlock(&dir_entries_table_rwlock);
            return 0;
        }
    }

    pthread_rwlock_unlock(&dir_entries_table_rwlock);
    return -1; // sub_name not found
}

/**
 * Store the inumber for a sub file in a directory.
 *
 * Input:
 *   - inode: directory inode
 *   - sub_name: sub file name
 *   - sub_inumber: inumber of the sub inode
 *
 * Returns 0 if successful, -1 otherwise.
 *
 * Possible errors:
 *   - inode is not a directory inode.
 *   - sub_name is not a valid file name (length 0 or > MAX_FILE_NAME - 1).
 *   - Directory is already full of entries.
 */
int add_dir_entry(inode_t *inode, char const *sub_name, int sub_inumber) {
    if (strlen(sub_name) == 0 || strlen(sub_name) > MAX_FILE_NAME - 1) {
        return -1; // invalid sub_name
    }

    insert_delay(); // simulate storage access delay to inode with inumber

    /**
     * Critical section!
     * 
     * Reading inode.
     */
    // We find to find the inode inum
    long int inumber = inode - inode_table;
    pthread_mutex_lock(&inode_mutexes_table[inumber]);
    if (inode->i_node_type != T_DIRECTORY) {
        return -1; // not a directory
    }

    // Locates the block containing the entries of the directory
    dir_entry_t *dir_entry = (dir_entry_t *)data_block_get(inode->i_data_block);
    pthread_mutex_unlock(&inode_mutexes_table[inumber]);


    ALWAYS_ASSERT(dir_entry != NULL,
                  "add_dir_entry: directory must have a data block");

    // Finds and fills the first empty entry

    /**
     * Critical section!
     * 
     * Reading and writing dir_entries_table. Writing to dir_entry.
     */
    pthread_rwlock_wrlock(&dir_entries_table_rwlock);
    for (size_t i = 0; i < MAX_DIR_ENTRIES; i++) {
        if (dir_entry[i].d_inumber == -1) {
            dir_entry[i].d_inumber = sub_inumber;
            strncpy(dir_entry[i].d_name, sub_name, MAX_FILE_NAME - 1);
            dir_entry[i].d_name[MAX_FILE_NAME - 1] = '\0';


            pthread_rwlock_unlock(&dir_entries_table_rwlock);
            return 0;
        }

    }

    pthread_rwlock_unlock(&dir_entries_table_rwlock);
    return -1; // no space for entry
}

/**
 * Obtain the inumber for a sub file inside a directory.
 *
 * Input:
 *   - inode: directory inode
 *   - sub_name: sub file name
 *
 * Returns inumber linked to the target name, -1 if errors occur.
 *
 * Possible errors:
 *   - inode is not a directory inode.
 *   - Directory does not contain a file named sub_name.
 */
int find_in_dir(inode_t const *inode, char const *sub_name) {
    ALWAYS_ASSERT(inode != NULL, "find_in_dir: inode must be non-NULL");
    ALWAYS_ASSERT(sub_name != NULL, "find_in_dir: sub_name must be non-NULL");

    insert_delay(); // simulate storage access delay to inode with inumber

    /**
     * Critical section!
     * 
     * Reading inode.
     */
    // We find the inode inum
    long int inumber = inode - inode_table;
    pthread_mutex_lock(&inode_mutexes_table[inumber]);
    if (inode->i_node_type != T_DIRECTORY) {
        return -1; // not a directory
    }

    // Locates the block containing the entries of the directory
    dir_entry_t *dir_entry = (dir_entry_t *)data_block_get(inode->i_data_block);
    pthread_mutex_unlock(&inode_mutexes_table[inumber]);


    ALWAYS_ASSERT(dir_entry != NULL,
                  "find_in_dir: directory inode must have a data block");

    // Iterates over the directory entries looking for one that has the target
    // name
    /**
     * Critical section!
     * 
     * Reading dir_entries_table. Reading dir_entry
     */
    pthread_rwlock_rdlock(&dir_entries_table_rwlock);
    for (size_t i = 0; i < MAX_DIR_ENTRIES; i++){
        if ((dir_entry[i].d_inumber != -1) &&
            (strncmp(dir_entry[i].d_name, sub_name, MAX_FILE_NAME) == 0)) {
            int sub_inumber = dir_entry[i].d_inumber;
            pthread_rwlock_unlock(&dir_entries_table_rwlock);
            return sub_inumber;
        }
    }
    pthread_rwlock_unlock(&dir_entries_table_rwlock);
    return -1; // entry not found
}

int check_empty_dir(inode_t const *inode) {
    ALWAYS_ASSERT(inode != NULL, "check_empty_dir: inode must be non-NULL");

    insert_delay(); // simulate storage access delay to inode with inumber

    /**
     * Critical section!
     * 
     * Reading inode.
     */
    // We find the inode inum
    long int inumber = inode - inode_table;
    pthread_mutex_lock(&inode_mutexes_table[inumber]);
    if (inode->i_node_type != T_DIRECTORY) {
        return -1; // not a directory
    }

    // Locates the block containing the entries of the directory
    dir_entry_t *dir_entry = (dir_entry_t *)data_block_get(inode->i_data_block);
    pthread_mutex_unlock(&inode_mutexes_table[inumber]);

    ALWAYS_ASSERT(dir_entry != NULL,
                  "check_empty_dir: directory inode must have a data block");

    // Iterates over the directory entries looking for one that has the target
    // name

    /**
     * Critical section!
     * 
     * Reading dir entry.
     */
    pthread_rwlock_rdlock(&dir_entries_table_rwlock);
    for (int i = 0; i < MAX_DIR_ENTRIES; i++){
        if (dir_entry[i].d_inumber != -1) {
            pthread_rwlock_unlock(&dir_entries_table_rwlock);
            return -1;
        }
    }
    pthread_rwlock_unlock(&dir_entries_table_rwlock);
    return 0;
}

/**
 * Allocate a new data block.
 *
 * Returns block number/index if successful, -1 otherwise.
 *
 * Possible errors:
 *   - No free data blocks.
 */
int data_block_alloc(void) {
    for (size_t i = 0; i < DATA_BLOCKS; i++) {
        if (i * sizeof(allocation_state_t) % BLOCK_SIZE == 0) {
            insert_delay(); // simulate storage access delay to free_blocks
        }

        // THIS IS A CRITICAL SECTION, BUT THIS SHOULD ONLY BE ACESSED FOLLOWING AN INODE, SO WE SHOULD BE SAFE!
        if (free_blocks[i] == FREE) {
            free_blocks[i] = TAKEN;
            return (int)i;
        }
    }
    return -1;
}

/**
 * Free a data block.
 *
 * Input:
 *   - block_number: the block number/index
 */
void data_block_free(int block_number) {
    ALWAYS_ASSERT(valid_block_number(block_number),
                  "data_block_free: invalid block number");

    insert_delay(); // simulate storage access delay to free_blocks

    // THIS IS A CRITICAL SECTION, BUT THIS SHOULD ONLY BE ACESSED FOLLOWING AN INODE, SO WE SHOULD BE SAFE!
    // Mark block as free.
    free_blocks[block_number] = FREE;
}

/**
 * Obtain a pointer to the contents of a given block.
 *
 * Input:
 *   - block_number: the block number/index
 *
 * Returns a pointer to the first byte of the block.
 */
void *data_block_get(int block_number) {
    ALWAYS_ASSERT(valid_block_number(block_number),
                  "data_block_get: invalid block number");

    insert_delay(); // simulate storage access delay to block

    // THIS IS A CRITICAL SECTION, BUT THIS SHOULD ONLY BE ACESSED FOLLOWING AN INODE, SO WE SHOULD BE SAFE!
    return &fs_data[(size_t)block_number * BLOCK_SIZE]; // TODO: check if the lock falls out of scope
}

/**
 * Add a new entry to the open file table.
 *
 * Input:
 *   - inumber: inode number of the file to open
 *   - offset: initial offset
 *
 * Returns file handle if successful, -1 otherwise.
 *
 * Possible errors:
 *   - No space in open file table for a new open file.
 */
int add_to_open_file_table(int inumber, size_t offset) {
    /**
     * Critical section!
     * 
     * Reading and writing open file table, then reading and writing to open file entry
     */
    pthread_rwlock_wrlock(&open_file_table_rwlock);
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (free_open_file_entries[i] == FREE) {
            free_open_file_entries[i] = TAKEN;
            open_file_table[i].of_inumber = inumber;
            open_file_table[i].of_offset = offset;

            pthread_mutex_init(&open_file_entry_mutexes[i], NULL);
            pthread_rwlock_unlock(&open_file_table_rwlock);
            return i;
        }
    }

    pthread_rwlock_unlock(&open_file_table_rwlock);
    return -1;
}

/**
 * Free an entry from the open file table.
 *
 * Input:
 *   - fhandle: file handle to free/close
 */
void remove_from_open_file_table(int fhandle) {
    ALWAYS_ASSERT(valid_file_handle(fhandle),
                  "remove_from_open_file_table: file handle must be valid");

    /**
     * Critical section!
     * 
     * Reading and writing to open_file_table.
     */
    pthread_rwlock_wrlock(&open_file_table_rwlock);
    ALWAYS_ASSERT(free_open_file_entries[fhandle] == TAKEN,
                  "remove_from_open_file_table: file handle must be taken");


    free_open_file_entries[fhandle] = FREE;
    pthread_rwlock_unlock(&open_file_table_rwlock);
    pthread_mutex_destroy(&open_file_entry_mutexes[fhandle]);
}

/**
 * Obtain pointer to a given entry in the open file table.
 *
 * Input:
 *   - fhandle: file handle
 *
 * Returns pointer to the entry, or NULL if the fhandle is invalid/closed/never
 * opened.
 */
open_file_entry_t *get_open_file_entry(int fhandle) {
    if (!valid_file_handle(fhandle)) {
        return NULL;
    }

    /**
     * Critical section!
     * 
     * Reading open file table.
     */
    pthread_rwlock_rdlock(&open_file_table_rwlock);
    if (free_open_file_entries[fhandle] != TAKEN) {
        return NULL;
    }

    open_file_entry_t * res = &open_file_table[fhandle];
    pthread_rwlock_unlock(&open_file_table_rwlock);
    return res;
}

/**
 * Set symlink, either in inode or in disk depending on size
 * 
 * Input:
 *  - inode: inode to set symlink in
 *  - symlink: symlink to set
 * 
 */
int inode_set_symlink(int inumber, char const *symlink){
    ALWAYS_ASSERT(symlink != NULL, "inode_set_symlink: symlink must be non-NULL");
    
    inode_t *inode = inode_get(inumber);

    ALWAYS_ASSERT(inode != NULL, "inode_set_symlink: inode must be non-NULL");

    if (inode->i_node_type != T_SYMLINK) {
        return -1; // not a symlink
    }

    size_t symlink_len = strlen(symlink);

    if (symlink_len <= MAX_INODE_SYMLINK_SIZE){
        // symlink fits in inode
        strcpy(inode->i_symlink, symlink);
        inode->i_symlink_location = ON_INODE;
    } else {
        // symlink does not fit in inode, so we need to allocate a data block
        int block_number = data_block_alloc();

        if (block_number == -1){
            return -1; // no free data blocks
        }

        // set data block in inode
        inode->i_data_block = block_number;

        // set symlink in data block
        char *symlink_block = (char *)data_block_get(block_number);

        strcpy(symlink_block, symlink);
        inode->i_symlink_location = ON_DISK;
        inode->i_size = symlink_len;
    }

    return 0;
}

/**
 * Get symlink, either from inode or from disk depending on size
 * 
 * Input:
 *  - inode: inode to get symlink from
 * 
 */
char *inode_get_symlink(int inumber){
    inode_t *inode = inode_get(inumber);

    ALWAYS_ASSERT(inode != NULL, "inode_get_symlink: inode must be non-NULL");

    if (inode->i_node_type != T_SYMLINK) {
        return NULL; // not a symlink
    }

    if (inode->i_symlink_location == ON_INODE){
        // symlink is in inode
        return inode->i_symlink;
    } else {
        // symlink does not fit in inode, so we need to get it from the data block
        int block_number = inode->i_data_block;

        if (block_number == -1){
            return NULL; // no data block
        }

        // get symlink from data block
        char *symlink_block = (char *)data_block_get(block_number);

        return symlink_block;
    }
}

// Setters and getters to preserve abstraction
inode_type get_inode_type(inode_t * inode){
    ALWAYS_ASSERT(inode != NULL, "get_inode_type: inode must be non-NULL");
    return inode->i_node_type;
}

size_t get_inode_size(inode_t * inode){
    ALWAYS_ASSERT(inode != NULL, "get_inode_size: inode must be non-NULL");
    return inode->i_size;
}

void set_inode_size(inode_t * inode, size_t size){
    ALWAYS_ASSERT(inode != NULL, "set_inode_size: inode must be non-NULL");
    inode->i_size = size;
}

int get_inode_data_block(inode_t * inode){
    ALWAYS_ASSERT(inode != NULL, "get_inode_data_block: inode must be non-NULL");
    return inode->i_data_block;
}

void set_inode_data_block(inode_t * inode, int block){
    ALWAYS_ASSERT(inode != NULL, "set_inode_data_block: inode must be non-NULL");
    inode->i_data_block = block;
}

int get_inode_hardlinks(inode_t * inode){
    ALWAYS_ASSERT(inode != NULL, "get_inode_hardlinks: inode must be non-NULL");
    return inode->i_hardlinks;
}

void set_inode_hardlinks(inode_t * inode, int hardlinks){
    ALWAYS_ASSERT(inode != NULL, "set_inode_hardlinks: inode must be non-NULL");
    inode->i_hardlinks = hardlinks;
}

void increment_inode_hardlinks(inode_t * inode){
    ALWAYS_ASSERT(inode != NULL, "increment_inode_hardlinks: inode must be non-NULL");
    inode->i_hardlinks++;
}

void decrement_inode_hardlinks(inode_t * inode){
    ALWAYS_ASSERT(inode != NULL, "decrement_inode_hardlinks: inode must be non-NULL");
    inode->i_hardlinks--;
}

int get_open_file_inumber(open_file_entry_t *entry) {
    ALWAYS_ASSERT(entry != NULL, "get_open_file_inumber: entry must be non-NULL");
    return entry->of_inumber;
}

size_t get_open_file_offset(open_file_entry_t *entry) {
    ALWAYS_ASSERT(entry != NULL, "get_open_file_offset: entry must be non-NULL");
    return entry->of_offset;
}

void set_open_file_offset(open_file_entry_t *entry, size_t offset) {
    ALWAYS_ASSERT(entry != NULL, "set_open_file_offset: entry must be non-NULL");
    entry->of_offset = offset;
}

void increment_open_file_offset(open_file_entry_t *entry, size_t increment) {
    ALWAYS_ASSERT(entry != NULL, "increment_open_file_offset: entry must be non-NULL");
    entry->of_offset += increment;
}