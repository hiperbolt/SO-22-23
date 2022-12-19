#include "fs/operations.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

// Tests if the copy_from_external_tfs is replacing all the content if the 
//destination file is totally written
int main() {
    tfs_params params = tfs_default_params();
    size_t size_of_buffer = params.block_size;
    char buffer[size_of_buffer];
    char *path1 = "/f1";
    char *check = "overwrite";
    char *full = "tests/gibberish.txt";
    char *source = "tests/overwrite.txt";

    assert(tfs_init(NULL) != -1);
    int file = tfs_open(path1, TFS_O_CREAT);

    tfs_copy_from_external_fs(full, path1);
    assert((tfs_read(file, buffer, sizeof(buffer))) == size_of_buffer);
    tfs_close(file);

    file = tfs_open(path1, TFS_O_CREAT);

    tfs_copy_from_external_fs(source, path1);
    assert((tfs_read(file, buffer, sizeof(buffer))) == strlen(check));

    printf("Successful test.\n");

    tfs_close(file);

    return 0;
}
