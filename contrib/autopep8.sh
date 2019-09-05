#! /bin/bash
# Script for running autopep8

autopep8 --in-place test/*.py hwilib/*.py hwilib/devices/*.py hwi.py
