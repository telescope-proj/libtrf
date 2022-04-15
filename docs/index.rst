.. libtrf documentation master file, created by
   sphinx-quickstart on Sun Feb  6 21:28:10 2022.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Telescope Remote Framebuffer Library
====================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

What is libtrf?
---------------

``libtrf`` is a transport library designed for uncompressed, point-to-point
video transmission across high-bandwidth, low-latency networks. It features
request latencies measured in microseconds, and high throughput up to 200
Gbit/s on RDMA transports.

Software Support
----------------

Currently, LibTRF supports major Linux distributions with a focus on RHEL-based
distributions where RDMA packages are well-maintained and tested. Most features
will likely work on FreeBSD and macOS, though releases are not regularly tested
on these targets.

Windows is not currently supported.

`Github Repository <https://github.com/telescope-proj/libtrf>`_

Indices and tables
------------------

* :ref:`genindex`
* :ref:`search`

Table of Contents
~~~~~~~~~~~~~~~~~

.. toctree::
   
   network/index
   api/index

Software License
----------------

Telescope Remote Framebuffer Library (libtrf)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Copyright (c) 2022 `Tim Dettmar <https://github.com/beanfacts>`_. Licensed under
`LGPL 2.1 only <https://www.gnu.org/licenses/old-licenses/lgpl-2.1.en.html>`_.

INI Not Invented Here (inih)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Copyright (c) 2009 `Ben Hoyt <https://github.com/benhoyt>`_. Licensed under `BSD
3-Clause <https://github.com/benhoyt/inih/blob/master/LICENSE.txt>`_.