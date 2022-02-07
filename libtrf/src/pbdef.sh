rm trf_msg.pb-c.c
rm ../include/trf_msg.pb-c.h
protoc-c --c_out=. trf_msg.proto
mv trf_msg.pb-c.h ../include/trf_msg.pb-c.h