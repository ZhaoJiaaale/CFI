#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void func1(char *s)
{
    char buffer[16];
    strcpy(buffer, s);
}

void func2(void)
{
    printf("Hello from func2!\n");
    system("/bin/sh");
}

int main(int argc, char **argv)
{
    if (argc > 1)
    {
        func1(argv[1]);
        printf("Hello World!\n");
    }

    return 0;
}