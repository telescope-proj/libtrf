if [ ! -f /usr/bin/protod-c ]
then
    echo "Protocol Buffers C compiler required."
    echo "Please install it from your distribution's package manager."
    echo "Fedora, RHEL, and derivatives: protobuf-c-devel protobuf-c-compiler"
    echo "Debian, Ubuntu, and derivatives: libprotobuf-c-dev protobuf-c-compiler"
    exit 1
fi

rm -f trf_msg.pb-c.c ../include/trf_msg.pb-c.h
protoc-c --c_out=. trf_msg.proto
sed -i 's,\/\*$,/**,g' trf_msg.pb-c.h
mv trf_msg.pb-c.h ../include/trf_msg.pb-c.h

echo "Regenerated trf_msg.pb-c.c and trf_msg.pb-c.h"