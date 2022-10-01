# Introduction
mDNS- is a simple mDNS-SD browser inspired from from https://github.com/sudomesh/mdnssd-min
It has been updated to compile under Linux, OSX and Windows and split into a library and a test program so that it can be included into various project.
Makefile are for Linux (x86, x86_64, arm and aarch64) and Windows with a VS project. The V2 also has osx that is not here for now on master

Compared to v2 branch, this rationalizes build tools and moved to VS. 

# Building
The bin/ directory contains pre-built binary, but you can easily re-generate them all. This can be used by 3rd party application to incorporate this as a mDNS query system. (see for example https://github.com/philippe44/AirConnect)

To cross-compile, add the following compilers
```
x86     => sudo apt install gcc make gcc-i686-linux-gnu binutils-i686-linux-gnu
aarch64 => sudo apt install gcc make gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu
arm     => sudo apt install gcc make gcc-arm-linux-gnueabi binutils-aarch64-linux-gnueabi
```
Do *not* use gcc-multilib to get arm/aarch64 cross-compile together with x86 on a x86_64 Debian-based distro, it will not work, they are multually exclusive. Instead use "gcc-i86-linux-gnu". Of course, you loose the benefit of compiling with the 64 bits compile and use -m32 switch
