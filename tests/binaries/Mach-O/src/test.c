#include <stdio.h>
#include <string.h>

void unsafe_function(const char *input) {
    char buffer[64];
    // Unsafe copy to demonstrate stack canary effectiveness
    strcpy(buffer, input);
    printf("Buffer contains: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        unsafe_function(argv[1]);
    } else {
        printf("Usage: %s <input>\n", argv[0]);
    }
    return 0;
}
