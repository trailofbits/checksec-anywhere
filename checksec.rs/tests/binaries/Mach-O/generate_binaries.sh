clang -o basic src/test.c
clang -o arc_enabled src/obj_c_prog.m -fobjc-arc -framework Foundation
clang -o no_canary src/test.c -fno-stack-protector
clang -o nosig src/test.c && codesign --remove-signature ./nosig
clang -o no_fortify src/test.c  -D_FORTIFY_SOURCE=0
clang -o restrict src/test.c -Wl,-sectcreate,__restrict,__RESTRICT,/dev/null
clang -o runpaths src/test.c -Wl,-rpath,@executable_path/lib -Wl,-rpath,./src
clang -o asan_enabled src/test.c -fsanitize=address






