#import <Foundation/Foundation.h>

int main() {
    @autoreleasepool {
        NSString *str = [[NSString alloc] initWithFormat:@"Hello, ARC!"];
        NSLog(@"%@", str);
    }
    return 0;
}
