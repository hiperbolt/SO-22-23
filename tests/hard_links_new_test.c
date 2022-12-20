#include "fs/operations.h"
#include <assert.h>
#include <stdio.h>
#include <state.h>
#include <string.h>

// Test to see if doing an hard link of an hard link is possible and to check that it isn't possible to create an hard 
// link of an soft link.

int main(){

    char target_path1[] = "/f1";
    char link_path1[] = "/l1";
    char link_path2[] = "/l2";
    char link_path3[] = "/l3";
    char link_path4[] = "/l4";
    char link_path5[] = "/l5";
    
    assert(tfs_init(NULL) == 0);
    
    int f = tfs_open(target_path1, TFS_O_CREAT);
    assert(f != -1);
    assert(tfs_close(f) != -1);

    assert(tfs_link(target_path1, link_path1) != -1);
    assert(tfs_sym_link(target_path1, link_path2) == 0);
    assert(tfs_link(link_path1, link_path3) == 0);
    
    
    assert(tfs_link(link_path2, link_path4) == -1);
  
    char *full = "tests/gibberish.txt";
    tfs_copy_from_external_fs(full,target_path1);
    char buffer[1024];
    int fhandle = tfs_open(target_path1, TFS_O_CREAT);
    tfs_write(fhandle, buffer, sizeof(buffer));
    tfs_close(fhandle);
    tfs_open(target_path1, TFS_O_CREAT);
    ssize_t check = tfs_read(fhandle, buffer, sizeof(buffer));
    tfs_close(fhandle);
    assert(tfs_sym_link(link_path2, link_path5) == 0);
    

    fhandle = tfs_open(link_path5, TFS_O_CREAT);
    assert(tfs_read(fhandle, buffer, sizeof(buffer)) == check);
    tfs_close(fhandle);

    printf("Successful test.\n");

    return 0;   

}