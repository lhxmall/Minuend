#!/bin/bash
# xval: build m4 (for GMP configure) + sail-riscv 0.16 from source, all under /data/hark/spike-rv/xval
set -ex
X=/data/hark/spike-rv/xval; T=$X/tools; mkdir -p $T
export PATH=$T/bin:$X/cmake-3.31.6-linux-x86_64/bin:$X/sail/bin:$PATH
cd $X
if [ ! -x $T/bin/m4 ]; then
  curl -sL -o m4.tar.xz https://ftp.gnu.org/gnu/m4/m4-1.4.19.tar.xz
  tar xJf m4.tar.xz; cd m4-1.4.19; ./configure --prefix=$T -q; make -j4 -s; make install -s; cd $X
fi
m4 --version | head -1; sail --version; cmake --version | head -1
cd sail-riscv-0.16
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DDOWNLOAD_GMP=TRUE -DENABLE_RISCV_TESTS=FALSE
time cmake --build build -j4
ls -la build/c_emulator/sail_riscv_sim
echo BUILD-DONE
