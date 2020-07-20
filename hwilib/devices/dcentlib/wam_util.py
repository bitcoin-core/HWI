#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

from . import wam_log as log

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

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

