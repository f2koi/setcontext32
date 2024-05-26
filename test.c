#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>


int main() {
    printf("%p\n", &system);

    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);

    while (1) {
        char n;
        unsigned long *ptr;
        unsigned long value;

        read(0, &n, 1);
        if (n == 'r') {
            read(0, &ptr, 8);
            write(1, ptr, 8);
        }
        else if (n == 'w') {
            read(0, &ptr, 8);
            read(0, &value, 8);
            *ptr = value;
        }
        else {
            break;
        }
    }

    puts("bye");

    return 0;
}