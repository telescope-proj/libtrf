.. _network_mellanox:

Mellanox NIC configuration
==========================

Mellanox NICs usually come in three flavours:

- Connect-IB, which is InfiniBand-only
- EN, which is Ethernet-only
- VPI, which supports both protocols

All types are supported through the LibTRF verbs interface. In general, it does
not matter which hardware you have so long as all types are the same across the
network and switches. 

.. warning::
    
    Differing transport types may only be interoperable over TCP, without any
    RDMA acceleration! IB and Ethernet **are not interoperable at the link
    layer.** 

Determine the NIC you want to query using ``lspci``:

::

    $ lspci | egrep -i "infiniband|ethernet"
    0c:00.0 Infiniband controller: Mellanox Technologies MT28908 Family [ConnectX-6]
    12:00.0 Infiniband controller: Mellanox Technologies MT28908 Family [ConnectX-6]
    4b:00.0 Infiniband controller: Mellanox Technologies MT28908 Family [ConnectX-6]
    54:00.0 Infiniband controller: Mellanox Technologies MT28908 Family [ConnectX-6]
    8d:00.0 Infiniband controller: Mellanox Technologies MT28908 Family [ConnectX-6]
    94:00.0 Infiniband controller: Mellanox Technologies MT28908 Family [ConnectX-6]
    ba:00.0 Infiniband controller: Mellanox Technologies MT28908 Family [ConnectX-6]
    cc:00.0 Infiniband controller: Mellanox Technologies MT28908 Family [ConnectX-6]
    e1:00.0 Ethernet controller: Mellanox Technologies MT28908 Family [ConnectX-6]
    e1:00.1 Ethernet controller: Mellanox Technologies MT28908 Family [ConnectX-6]
    e2:00.0 Ethernet controller: Intel Corporation I210 Gigabit Network Connection (rev 03)

To change the operating mode, install the ``mstflint`` package, which should be
available from your distribution package manager or preinstalled in the
MLNX-OFED driver, where you may also use ``mlxconfig``.

::

    # mstconfig -d 0c:00.0 set LINK_TYPE_P1=ETH

    Device #1:
    ----------

    Device type:    ConnectX6       
    Name:           MCX653105A-HDA_Ax
    Description:    ConnectX-6 VPI adapter card; HDR IB (200Gb/s) and 200GbE; single-port QSFP56; PCIe4.0 x16; tall bracket; ROHS R6
    Device:         0c:00.0         

    Configurations:                              Next Boot       New
            LINK_TYPE_P1                         IB(1)           ETH(2)
    
    Apply new Configuration? (y/n) [n] : y
    Applying... Done!
    -I- Please reboot machine to load new configurations.

If you are using SR-IOV to pass a VF into a virtual machine, you may also
configure this from ``mstconfig``. The parameters are:

``SRIOV_EN=1 NUM_OF_VFS=x``, where ``x`` is your desired virtual NIC count.

.. note::

    Older NICs, such as the ConnectX-3 Pro and older may either not support
    SR-IOV out of the box, or VFs may not work properly when passed through,
    especially if the guest is a Windows guest. The fix may require the
    installation of the MLNX-OFED 4.x LTS driver, which is known to fail to
    compile on newer kernel versions. You may have to pass the entire PCIe
    device to the virtual machine if you would like to use it in a virtual
    environment.

.. note::

    If SRIOV_EN option does not show up in mstconfig, you may have to configure
    this in the FlexBoot option ROM at boot time. In your motherboard UEFI/BIOS,
    you will also have to enable VT-d/IOMMU and SR-IOV support.

Enabling SR-IOV at boot time
----------------------------

Enabling SR-IOV at boot time for mlx4 can be done by adding a file to
``/etc/modprobe.d/``. As previously mentioned, ``x`` is your desired virtual NIC
count.

::

    # mlx4 and OFED LTS 4.x driver users
    options mlx4_core probe_vf=0 max_vfs=x

    # mlx5 and current OFED driver users
    options mlx5_core probe_vf=0 max_vfs=x

Setting VF MAC Addresses
------------------------

Setting VF MACs can be done using the ``ip`` command. For instance:

::

    ip link set enp225s0f0 vf 1 mac 00:52:44:11:22:33