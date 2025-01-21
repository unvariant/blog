#include <stdio.h>

int main() {
    printf("%2$*c", 0xffffff, 0x41);
}