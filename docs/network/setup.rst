.. _network_setup:

Network Setup & Usage Guide
===========================

Using the LibTRF APIs with RDMA NICs may require additional configuration for
optimal performance. Please see below for setup considerations depending on the
fabric provider.

General Configuration
---------------------

For all transports, the use of jumbo frames is highly recommended. Be wary of
the limitations of both your switches and network cards. A safe bet is a 4KB
MTU, and most newer hardware supports 9KB+ MTUs. Try reducing the MTU if you
experience packet loss.

A quick check to determine whether your MTU is set too high is to ping the peer
address with PMTUD enabled. For instance, if your MTU is set to 4000 bytes and
my peer address is 203.0.113.0, you may do the following:

::
    
    ping -M do -s $((4000-28)) 203.0.113.10


Transport-specific configuration
--------------------------------

TCP
~~~

- Practically all network hardware

No switch configuration is required. Usually, this transport does not have any
hardware acceleration support, save for checksum offload. Use of a NIC's
full-stack TCP Offload Engine (TOE), as supported by some Chelsio NICs, is not
recommended.

Realtek NICs are barely deserving of the term "NIC", and may require disabling
hardware offloads if poor performance is experienced. See the 
:doc:`Hardware Offload Configuration <offload>` section.

RDMA over Converged Ethernet (RoCE) v1
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Mellanox ConnectX-2 EN / VPI
- Mellanox ConnectX-3 EN / VPI

Requires the port to be dedicated for RDMA traffic with regular flow control
(802.3x) enabled along the entire path, or for Priority Flow Control (PFC) to be
configured.

RDMA over Converged Ethernet (RoCE) v2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Not interoperable** with RoCE v1. However, some NICs, such as Mellanox NICs,
may be toggled between RoCE v1 and RoCE v2 operating modes. 

- Software RoCE Driver (rdma_rxe)
- Mellanox ConnectX-3 Pro EN / VPI
- Mellanox ConnectX-4 and later
- Marvell / QLogic FastLinq 41000/45000 Series
- Intel E810 Series

Unless the NIC supports Zero Touch RoCE (ZTR-RTTCC, ConnectX-5 and newer), the
port must either be dedicated for RDMA traffic with regular flow control
(802.3x) enabled along the entire path. Alternatively, either PFC or ECN must be
configured.

iWARP
~~~~~

- Chelsio Terminator 3 or later
- Chelsio T520-CR
- Intel X722 Series
- Intel E810 Series
- Marvell / QLogic FastLinq 41000/45000 Series

iWARP requires no special switch configuration. However, configuring jumbo
frames and ECN may improve performance.

InfiniBand
~~~~~~~~~~

**Not interoperable with Ethernet.** All InfiniBand versions should support RDMA
traffic.

- Mellanox ConnectX-2 VPI or later
- Mellanox Connect-IB
- QLogic QLE7300 Series

Requires a Subnet Manager (SM) and InfiniBand switching hardware, but no special
switch configuration as by design, InfiniBand is a lossless fabric. See
:ref:`_setup_infiniband`

Unsupported Transports
----------------------

Some transports supported by Libfabric, but unsupported by LibTRF are as
follows:

- UDP
- Omni-Path (PSM2/OPX)
- PSM3
- EFA
- BGQ
- SHM