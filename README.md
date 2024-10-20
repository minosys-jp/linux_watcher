# linux_watcher

Required apt library
- libcurl4
- libcurl4-openssl-dev
- libssl-dev
- g++

Run 'make clean all' to compile and generate target code

## Caution!!

The current version only targeted to the x86-64 CPU architecture.
For Arm64, you should rewrite source code in the graph.cc:

```c++
graph.cc:92:            // check AMD X86_64 compatible
graph.cc:93:            if (eh.e_machine != EM_X86_64) {
```
```
EM_AARCH64
```
