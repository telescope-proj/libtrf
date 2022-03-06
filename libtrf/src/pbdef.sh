rm -f trf_msg.pb-c.c ../include/trf_msg.pb-c.h
protoc-c --c_out=. trf_msg.proto
sed -i 's,\/\*$,/**,g' trf_msg.pb-c.h
mv trf_msg.pb-c.h ../include/trf_msg.pb-c.h