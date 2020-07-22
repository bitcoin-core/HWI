#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */
from io import BytesIO
from . import wam_log as log
from . import prototrez as proto
from . import protobuf as message
#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

def string2hexbin(hexstring):
	if len(hexstring) % 2 != 0 :
		raise Exception("invalid hexstring")

	hexstr = hexstring[:2]
	if hexstr == "0x":
		hexstring = hexstring[2:]

	hexbin = []
	while len(hexstring) > 0:
		hexstr = hexstring[:2]
		# log.d("hexstr = " + hexstr)
		hexbin.append(int(hexstr, 16))
		hexstring = hexstring[2:]
	# log.d("hexbin = " + str(bytes(hexbin)))
	return bytes(hexbin)

def string2hex(string):
	if len(string)==0:
		return bytes()
	
	hexString = "".join(x.encode("utf-8").hex() for x in string)
	return hexString

def len_hexstring(hexstring):
	#log.d("hexstring = " + hexstring)
	if len(hexstring) % 2 != 0 :
		raise Exception("invalid hexstring")

	hexstr = hexstring[:2]
	if hexstr == "0x":
		hexstring = hexstring[2:]

	#log.d("hexstring = " + hexstring)
	return len(hexstring)//2

def bin2hexstring(hexbin):
	return hexbin.hex()

def int2bytes(value):
	return value.to_bytes((value.bit_length() + 7) // 8, byteorder='big', signed=False)

def pb_serializeToString(msg):
	data = BytesIO()
	proto.dump_message(data, msg)
	ser = data.getvalue()
	return ser

def pb_serializeFromString(stream, messageType):
	data = BytesIO(stream)
	pb_response = proto.load_message(data, messageType)
	return pb_response

def pb_makeTransactionReq():
	h = message.req_header_t()
	b = message.req_body_t(message.command_t())
	t = message.request(h, b)
	return t


#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

