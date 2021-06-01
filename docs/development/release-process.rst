Release Process
***************

1. Bump version number in ``pyproject.toml`` and ``hwilib/__init__.py``, generate the setup.py file, and git tag release
2. Build distribution archives for PyPi with ``contrib/build_dist.sh``
3. For MacOS and Linux, use ``contrib/build_bin.sh``. This needs to be run on a MacOS machine for the MacOS binary and on a Linux machine for the linux one.
4. For Windows, use ``contrib/build_wine.sh`` to build the Windows binary using wine
5. Make ``SHA256SUMS.txt`` using ``contrib/make_shasums.sh``.
6. Make ``SHA256SUMS.txt.asc`` using ``gpg --clearsign SHA256SUMS.txt``
7. Upload distribution archives to PyPi
8. Upload distribution archives and standalone binaries to Github

Deterministic builds with Docker
================================

Create the docker image::

    docker build --no-cache -t hwi-builder -f contrib/build.Dockerfile .

Build everything::

    docker run -it --name hwi-builder -v $PWD:/opt/hwi --rm  --workdir /opt/hwi hwi-builder /bin/bash -c "contrib/build_bin.sh && contrib/build_dist.sh && contrib/build_wine.sh"

Building macOS binary
=====================

Note that the macOS build is non-deterministic.

First install `pyenv <https://github.com/pyenv/pyenv>`_ using whichever method you prefer.

Then a deterministic build of Python 3.6.8 needs to be installed. This can be done with the patch in ``contrib/reproducible-python.diff``. First ``cd`` into HWI's source tree. Then use::

    cat contrib/reproducible-python.diff | PYTHON_CONFIGURE_OPTS="--enable-framework" BUILD_DATE="Jan  1 2019" BUILD_TIME="00:00:00" pyenv install -kp 3.6.8

Make sure that python 3.6.8 is active::

    $ python --version
    Python 3.6.8

Now install `Poetry <https://github.com/sdispater/poetry>`_ with ``pip install poetry``

Additional dependencies can be installed with::

    brew install libusb

Build the binaries by using ``contrib/build_bin.sh``.
