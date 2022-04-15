.. _network_infiniband:

InfiniBand Configuration
========================

Infiniband ports, unlike Ethernet, will not automatically come up on a
connection - an SM, or Subnet Manager, is required. OpenSM may run on the
switch, or on any one of the nodes in the network, but only one OpenSM instance
may be active per subnet.

OpenSM should be available via your distribution package manager as ``opensm``.
Once installed, ensure the service is started.

::

    $ sudo systemctl status opensm
    ● opensm.service - Starts the OpenSM InfiniBand fabric Subnet Manager
        Loaded: loaded (/usr/lib/systemd/system/opensm.service; disabled; vendor preset: disabled)
        Active: active (running) since Tue 2022-03-29 10:09:59 +07; 1s ago
        Docs: man:opensm
        Process: 50756 ExecStart=/usr/libexec/opensm-launch (code=exited, status=0/SUCCESS)
    Main PID: 50757 (opensm-launch)
        Tasks: 2 (limit: 56452)
        Memory: 640.0K
            CPU: 14ms
        CGroup: /system.slice/opensm.service
                ├─50757 /usr/bin/bash /usr/libexec/opensm-launch
                └─50769 sleep 30

    Mar 29 10:09:59 tls-1 opensm-launch[50758]: -------------------------------------------------
    Mar 29 10:09:59 tls-1 opensm-launch[50758]: OpenSM 3.3.24
    Mar 29 10:09:59 tls-1 opensm-launch[50758]:  Reading Cached Option File: /etc/rdma/opensm.conf
    Mar 29 10:09:59 tls-1 opensm-launch[50758]: Command Line Arguments:
    Mar 29 10:09:59 tls-1 opensm-launch[50758]:  Log File: /var/log/opensm.log
    Mar 29 10:09:59 tls-1 opensm-launch[50758]: -------------------------------------------------
    Mar 29 10:09:59 tls-1 OpenSM[50758]: /var/log/opensm.log log file opened
    Mar 29 10:09:59 tls-1 OpenSM[50758]: OpenSM 3.3.24
    Mar 29 10:09:59 tls-1 opensm-launch[50758]: OpenSM 3.3.24

For most users, the default configuration is fine. If you are using SR-IOV VFs,
you must also enable virtualization support. Depending on how you installed
OpenSM and what distribution you are using, the file location is very likely to
differ. Use the cached option file shown in your own output, not the above
example output. In this case, it is ``/etc/rdma/opensm.conf``. Add the following
line:

``virt_enabled 2``

Save and restart OpenSM.

SR-IOV Configuration
--------------------

You should ensure the Port GUIDs are set before passing through a VF, as the
guest is not usually allowed to change this value. Unlike a MAC address, a GUID
is **64 bits**. A sample configuration is provided below for the mlx5 driver
(run as the root user):

.. code-block:: bash

    # If you haven't enabled SR-IOV, you can do this now
    echo 1 > /sys/class/infiniband/mlx5_0/device/mlx5_num_vfs

    # Verify the number of VFs
    cat /sys/class/infiniband/mlx5_0/device/mlx5_num_vfs
    1

    # Set node & port GUIDs
    echo ad:3a:73:c4:06:29:20:f5 > /sys/class/infiniband/mlx5_0/device/sriov/0/node
    echo ad:3a:73:c4:06:29:20:f6 > /sys/class/infiniband/mlx5_0/device/sriov/0/port
    echo Follow > /sys/class/infiniband/mlx5_0/device/sriov/0/policy

