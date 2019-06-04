#! /usr/bin/bash
clang -target x86_64-w64-windows-gnu -emit-llvm -c inso19/check_flag.c -o bin/ad.bc 
opt -O0 -load pass/StackOverflow.so -MyPass -level 3 -load pass/AntiDebug.so -antidbg bin/ad.bc  -o bin/ad_out.ll  2>&1
#clang -target x86_64-w64-windows-gnu -mllvm -disable-llvm-optzns -O0 bin/ad_out.ll -o bin/hello_ad.exe -lm
clang -target x86_64-w64-windows-gnu -mllvm -disable-llvm-optzns -O0 bin/ad_out.ll -o bin/hello_ad.exe -lm -lcrypto -L/usr/x86_64-w64-mingw32/lib/ -static

#clang -emit-llvm -c inso19/check_flag.c -o bin/ad.bc
#opt -O0 -load pass/StackOverflow.so -MyPass -level 2 -load pass/AntiDebug.so -antidbg bin/ad.bc  -o bin/ad_out.ll 2>&1
#clang -mllvm -disable-llvm-optzns -O0 bin/ad_out.ll -o bin/hello_ad.bin -lm -lcrypto
#clang -mllvm -disable-llvm-optzns -O0 bin/ad_out.ll -o bin/hello_ad.bin -lm
