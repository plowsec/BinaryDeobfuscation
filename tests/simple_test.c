#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    volatile int a = 3;
    a += 1337;
    printf("a should be 1340, and it actually is %d\n", a);
    return a;
}
