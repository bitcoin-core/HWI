#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

from . import wam_log as log
from .protobuf import error_code_t
from . import wam_encoder as encoder
#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

class WamException(Exception):
	def __init__(self, code, msg):
		self.args = (code, msg)
		self.errno = code
		self.errmsg = msg
		log.d("code = " + str(code))
		log.d("msg = " + msg)
	def get_code(self):
		log.d("code = " + str(self.errno))
		return self.errno
	def get_msg(self):
		log.d("msg = " + self.errmsg)
		return self.errmsg

def raiseWam(msg):
	raise WamException(error_code_t.invalid_format, msg)

def raiseWamByCode(code):
  	raise WamException(encoder.pb_get("error.code", code), code)
  	
#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

