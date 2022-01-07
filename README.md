# Telescope Remote Framebuffer Library

## Introduction

`libtrf` abstracts the connection, synchronization, and transmission aspects of remote framebuffer relay, attempting to make the best use of available network hardware. 

While this library initially targets Linux users, it keeps to standard C as much as possible and may eventually be usable on other operating systems supported by Libfabric, such as FreeBSD, macOS, and Windows. It does not require special hardware support, falling back to TCP when acceleration is unavailable.

## License

Copyright (c) 2022 Tim Dettmar  
Licensed under the LGPL v2.1