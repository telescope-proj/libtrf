# Telescope Remote Framebuffer Library

![CodeQL Analysis](https://github.com/telescope-proj/libtrf/actions/workflows/codeql-analysis.yml/badge.svg?branch=main)
![Documentation Build](https://github.com/telescope-proj/libtrf/actions/workflows/docs.yml/badge.svg)
![Library Build](https://github.com/telescope-proj/libtrf/actions/workflows/ubuntu-build.yml/badge.svg)

[Documentation](https://telescope-proj.github.io/libtrf/)

## Introduction

`libtrf` abstracts the connection, synchronization, and transmission aspects of
remote framebuffer relay, attempting to make the best use of available network
hardware. It supports both standard TCP and common RDMA transports with
extremely low latency and high performance.

## Performance

Preliminary benchmark results on ConnectX-6 EDR & EPYC 7742:

LibTRF Configuration

* Libfabric: 1.15.0rc1
* Libfabric API: 1.14
* Transport: verbs;ofi_rxm
* Hugepages: Enabled, 2MB
* Affinity: Not configured
* Polling mode: Busy

Message performance (4 byte messages, n = 99, first message excluded):  

* Message processing latency: **1.488 μs** -> **672,043 msgs/sec**

Frame performance (Protobuf messages, 1920x1080 dummy frame data, n = 99, first frame excluded):  

* Request latency: **2.236 μs**
* Throughput: **171.419 Gbit/sec**

## License

Copyright (c) 2022 Tim Dettmar  
Licensed under the LGPL v2.1