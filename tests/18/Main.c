#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{
    int i;
    pid_t pid;
    while(1) {
        pid = fork();
        if(pid >= 0)
           printf("success %d %d\n", i, pid);
    }
    return 0;
}
