#include "../fs/operations.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#define NUM_THREADS 3000

char *to_write = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
char *path = "/f1";
char buffer[1000];

void *read(){
    int f;
    f = tfs_open(path, 0);
    assert(f != -1);

    assert(tfs_read(f, buffer, sizeof(buffer) - 1) == strlen(to_write));

    assert(memcmp(buffer, to_write, strlen(to_write)) == 0);
    assert(tfs_close(f) != -1);
    return 0;
}

int main(){
    assert(tfs_init(NULL) != -1);

    pthread_t threads[NUM_THREADS];

    long int f;
    int fhandle;
    fhandle = tfs_open(path, TFS_O_CREAT);
    assert(fhandle != -1);

    f = tfs_write(fhandle, to_write, strlen(to_write));
    assert(f == strlen(to_write));

    f = tfs_close(fhandle);
    assert(f != -1);

    for (int i = 0; i < NUM_THREADS; i++){
        pthread_create(&threads[i], NULL, read, NULL);
    }
    
    for (int i = 0; i < NUM_THREADS; i++){
        pthread_join(threads[i], NULL);
    }
        
    assert(tfs_destroy() != -1);

    printf("Successful test.\n");
    
    return 0; 
}