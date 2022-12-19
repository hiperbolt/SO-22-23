#include "fs/operations.h"
#include <assert.h>
#include <stdio.h>

char const target_path1[] = "/f1";
char const link_path1[] = "/l1";
char const link_path2[] = "/l2";
char const link_path3[] = "/l3";

int main(){
    assert(tfs_init(NULL) == 0);
    
    int f = tfs_open(target_path1, TFS_O_CREAT);
    assert(f != -1);
    assert(tfs_close(f) != -1);

    assert(tfs_link(target_path1, link_path1) != -1);
    assert(tfs_sym_link(target_path1, link_path2) == 0);
    assert(tfs_link(link_path2, link_path3) == -1);

    printf("Successful test.\n");

    return 0;   

}