#include <stdio.h>

int add(int x, int y) {
    x = x + 1;
    return x + y;
}

int main() {
    int x = 1;
    int y = 1;
    int z = add(x, y);
    printf("%d\n", z);
}