#!/usr/bin/python

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

from . import wam_log as log
import inspect
import os

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

def _get_frame_info():
    # 0 represents this line
    # 1 represents line at caller (namely, debug functions)
    # 2 represents line at caller of debug functions
    callerframerecord = inspect.stack()[2]  
    frame = callerframerecord[0]
    info = inspect.getframeinfo(frame)
    return info

def NOT_SUPPORTED():
    info = _get_frame_info()
    filename = os.path.basename(info.filename)
    print("[ERROR" + "|" + filename + "|" + str(info.lineno) + "]" + " NOT SUPPORTED")
    raise NotImplementedError("NOT_SUPPORTED")
    return

def NOT_IMPLEMENTED():
    info = _get_frame_info()
    filename = os.path.basename(info.filename)
    print("[ERROR" + "|" + filename + "|" + str(info.lineno) + "]" + " NOT IMPLEMENTED")
    raise NotImplementedError("NOT_IMPLEMENTED")
    return

def NOT_REACHED():
    info = _get_frame_info()
    filename = os.path.basename(info.filename)
    print("[ERROR" + "|" + filename + "|" + str(info.lineno) + "]" + " CANNOT BE REACHED")
    raise NotImplementedError("NOT_REACHED")
    return

def ASSERT(condition):
    assert(condition)
    return

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

