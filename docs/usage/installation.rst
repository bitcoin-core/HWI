Installation
************

HWI is distributed in 2 different ways:

1. Self-contained executable binaries
2. Python package

Binaries
========

The self-contained binaries are availabe for download from the `releases page <https://github.com/bitcoin-core/HWI/releases>`_.

Download and extract the package for your operating system and architecture.
The ``hwi`` binary (``hwi.exe`` for Windows) is a command line tool and executed from the terminal (command prompt in Windows).
The ``hwi-qt`` binary (``hwi-qt.exe`` for Windows) is a GUI tool and can be executed as any typical application.

Python Package
==============

The python packages are distributed both from the `releases page <https://github.com/bitcoin-core/HWI/releases>`_ and from `PyPi <https://pypi.org/project/hwi/>`_.

In either case, make sure that you have installed ``pip`` and that it is update to date.

From Releases
-------------

Download either the Python wheel ``hwi-<version>-py3-none-any.whl`` or the source package ``hwi-<version>.tar.gz``.
It is recommended to use the wheel over the source package unless your Python installation does not support wheels.

Install the downloaded file using ``pip``. For example::

    pip install hwi-1.1.2-py3-none-any.whl

or::

    pip install hwi-1.1.2.tar.gz

From PyPI
---------

As HWI is also uploaded to PyPi, it can be installed with::

    pip install hwi
