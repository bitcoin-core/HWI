#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

import inspect
import os
import json

from enum import Enum

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

class LogLevel(Enum):
    none = 0
    critical = 1
    error = 2
    debug = 3
    info = 4
    verbose = 5

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

_vIsLogLevel = LogLevel.debug.value
#_vIsLogLevel = LogLevel.debug

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

def _get_frame_info(stack_depth):
    # 0 represents this line
    # 1 represents line at caller (namely, function trace())
    # 2 represents line at caller of trace()
    callerframerecord = inspect.stack()[stack_depth]  
    frame = callerframerecord[0]
    info = inspect.getframeinfo(frame)
    return info

def set(log_level):
    global _vIsLogLevel
    if log_level < LogLevel.none.value or log_level > LogLevel.verbose.value:
        raise IndexError("Invalid Log Level")
    _vIsLogLevel = log_level
    return

def off():
    global _vIsLogLevel
    _vIsLogLevel = LogLevel.none.value
    return

def trace(log_level, message):
    global _vIsLogLevel
    if _vIsLogLevel >= log_level:
        info = _get_frame_info(3)
        filename = os.path.basename(info.filename)
        print("|" + filename + "|" + str(info.lineno) + "|" + message)
    return

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

def c(message):
    trace(LogLevel.critical.value, message)
    return

def e(message):
    trace(LogLevel.error.value, message)
    return

def d(message):
    trace(LogLevel.debug.value, message)
    return

def i(message):
    trace(LogLevel.info.value, message)
    return

def v(message):
    trace(LogLevel.verbose.value, message)
    return

def dump_json(name, msg):
    global _vIsLogLevel
    if _vIsLogLevel >= LogLevel.debug.value:
        info = _get_frame_info(2)
        filename = os.path.basename(info.filename)
        print("|" + filename + "|" + str(info.lineno) + "|" + "JSON DUMP : " + name)
        print(json.dumps(msg, indent="    "))
    return

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

