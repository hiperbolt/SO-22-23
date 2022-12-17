ssize_t tfs_read(int fhandle, void *buffer, size_t len) {
    open_file_entry_t *file = get_open_file_entry(fhandle);
    if (file == NULL) {
        return -1;
    }

    /**
     * Critical section!
     * 
     * Reading inode. Reading and writing to openfile.
     */

    // From the open file table entry, we get the inode
    pthread_mutex_lock(&file->open_file_mutex);
    inode_t const *inode = inode_get(file->of_inumber);
    ALWAYS_ASSERT(inode != NULL, "tfs_read: inode of open file deleted");

    // Determine how many bytes to read
    pthread_mutex_lock((pthread_mutex_t *) &inode->i_mutex);
    size_t to_read = inode->i_size - file->of_offset;
    pthread_mutex_unlock((pthread_mutex_t *) &inode->i_mutex);    
    if (to_read > len) {
        to_read = len;
    }

    if (to_read > 0) {
        pthread_mutex_lock((pthread_mutex_t *) &inode->i_mutex);
        void *block = data_block_get(inode->i_data_block);
        pthread_mutex_unlock((pthread_mutex_t *) &inode->i_mutex);
        ALWAYS_ASSERT(block != NULL, "tfs_read: data block deleted mid-read");

        // Perform the actual read
        memcpy(buffer, block + file->of_offset, to_read);
        // The offset associated with the file handle is incremented accordingly
        file->of_offset += to_read;
    }


    pthread_mutex_lock(&file->open_file_mutex);
    return (ssize_t)to_read;
}