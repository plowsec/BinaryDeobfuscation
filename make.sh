#!/usr/bin/bash
clang -S -emit-llvm tests/simple_test.c -o bin/simple_test.ll
clang -g3 -shared -fPIC StackOverflow.cpp -o pass/StackOverflow.so
opt -S -O0 -load pass/StackOverflow.so -MyPass -level 1 bin/simple_test.ll -o bin/simple_test.opt.ll
clang -mllvm -disable-llvm-optzns -O0 bin/simple_test.opt.ll -o bin/simple_test.bin