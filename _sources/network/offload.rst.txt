.. _network_offload:

Hardware Offload Configuration
==============================

Many NICs support hardware offload. Some do it well, and some may end up
reducing performance at high packet rates. In general, leaving the defaults as
is is fine, as long as performance is acceptable.

On Linux, you may use the ``ethtool`` package to view and enable/disable
offloads.

::

    $ ethtool -k enp225s0f0
    Features for enp225s0f0:
    rx-checksumming: on
    tx-checksumming: on
            tx-checksum-ipv4: off [fixed]
            tx-checksum-ip-generic: on
            tx-checksum-ipv6: off [fixed]
            tx-checksum-fcoe-crc: off [fixed]
            tx-checksum-sctp: off [fixed]
    scatter-gather: on
            tx-scatter-gather: on
            tx-scatter-gather-fraglist: off [fixed]
    tcp-segmentation-offload: on
            tx-tcp-segmentation: on
            tx-tcp-ecn-segmentation: off [fixed]
            tx-tcp-mangleid-segmentation: off
            tx-tcp6-segmentation: on
    generic-segmentation-offload: on
    generic-receive-offload: on
    large-receive-offload: off
    rx-vlan-offload: on
    tx-vlan-offload: on

Some of the key offloads that may want to be toggled on/off are shown above.
Particularly on Realtek "network cards" the use of specific offloads, such as
checksumming and segmentation offload that are enabled by default may result in
poor performance, especially if you are using a virtual switch.

For example, to disable hardware checksum offload, the command is as follows:

::

    # ethtool -K enp225s0f0 rx-checksumming off tx-checksumming off
