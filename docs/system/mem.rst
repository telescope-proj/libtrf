.. _system_mem:

Memory Locking Configuration
============================

By default, the amount of locked memory available to user processes is limited
and often inadequate for RDMA use. The locked memory limit may be increased
by adding these lines into ``/etc/security/limits.conf``:

.. code-block:: text

    * soft memlock unlimited
    * hard memlock unlimited

You may also change the amount of locked memory to a lower value, larger than
the framebuffer size you expect to use, and limit the use of locked memory to a
specific group, however this configuration is out of the scope of this
documentation. A typical configuration may look like:

.. code-block:: text

    john soft memlock 1048576
    john hard memlock 1048576

To allow the user ``john`` up to 1GB of locked memory.