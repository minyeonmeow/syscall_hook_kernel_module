#include <stdio.h>
#include <stdlib.h>
/*
int main(void)
{
    char *argv[] = {"ps", "-ef", NULL};
//	system("cat /proc/$$/cmdline");
	//system("ps -ef > out");
	execve("/bin/ps", argv, 0);
    return 0;
}

*/


int main(void){
    FILE *fp;

    if ((fp = popen("/bin/cat /proc/cpuinfo", "r")) == NULL){
        perror("open failed");
        return -1;
    }

    char buf[256];
    while (fgets(buf, 255, fp) != NULL)
        printf("%s", buf);

    if (pclose(fp) == -1){
        perror("close failed");
        return -2;
    }
    return 0;
}

