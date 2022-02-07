cd ..
cmake .; make -j$(nproc);
cd examples/
make clean
make
