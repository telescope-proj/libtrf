cd ../..
cmake .
make -j $(nproc)

cd examples/subchannel
make clean
make -j $(nproc)

pids=()

./server 127.0.0.1 9999 ci & pids+=($!)
sleep 5
./client 127.0.0.1 9999 ci & pids+=($!)

for pid in ${pids[*]}; do
    wait $pid
    if [ $? -ne 0 ]
    then
        echo "Failed!"
        exit $?
    fi
done

echo "Check passed!"
exit 0