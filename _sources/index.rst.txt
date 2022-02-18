.. libtrf documentation master file, created by
   sphinx-quickstart on Sun Feb  6 21:28:10 2022.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to libtrf's documentation!
==================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

What is libtrf?
***************
`libtrf` abstracts the connection, synchronization, and transmission aspects of remote framebuffer relay, attempting to make the best use of available network hardware.

While this library initially targets Linux users, it keeps to standard C as much as possible and may eventually be usable on other operating systems supported by Libfabric, such as FreeBSD, macOS, and Windows. It does not require special hardware support, falling back to TCP when acceleration is unavailable.

`Github Repository <https://github.com/telescope-proj/libtrf>`_

Indices and tables
==================

* :ref:`genindex`
* :ref:`search`

Table of Contents
^^^^^^^^^^^^^^^^^

.. toctree::
   
   api/index

