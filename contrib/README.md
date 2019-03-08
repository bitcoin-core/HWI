# Assorted tools

## `build_bin.sh`

Creates a virtualenv with the locked dependencies using Poetry. Then uses pyinstaller to create a standalone binary for the OS type currently running.

## `build_dist.sh`

Creates a virtualenv with the locked dependencies using Poetry. Then uses Poetry to produce deterministic builds of the wheel and sdist for upload to PyPi

`faketime` needs to be installed

## `build_wine.sh`

Sets up Wine with Python and everything needed to build Windows binaries. Creates a virtualenv with the locked dependencies using Poetry. Then uses pyinstaller to create a standalone Windows binary.

`wine` needs to be installed

## `generate_setup.sh`

Builds the source distribution and extracts the setup.py from it.

## `build.Dockerfile`

A Dockerfile for setting up the deterministic build environment.

# Other files

## `reproducible-python.diff`

A path for python in order to do a deterministic build of Python for the deterministically built binaries.

## `pyinstaller-hooks/hook-hwilib.devices.py`

Pyinstaller hook so that the device drivers are actually included. Due to how the imports work, we need this hook.
