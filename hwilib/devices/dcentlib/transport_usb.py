#!/usr/bin/env python

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

from . import wam_log as log
from . import wam_debug as DEBUG
from . import wam_util as util

# import hid

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

PACKET_HEAD_LEN = 8
PACKET_DATA_LEN = 56

class TransportUsb:
	def __init__(self, dev):
		self.usbdev = dev
		return

	def send(self, data):
		dev = self.usbdev

		raw_data = list(data)
		#log.d("raw_data = " + str(raw_data))
		total_len = "%08X" % len(raw_data)
		#log.d("total_len = " + total_len)
		total_len_list = list(util.string2hexbin(total_len))
		blk_idx = 0
		while len(raw_data) > 0 :
			raw_data_packet = raw_data[:PACKET_DATA_LEN]
			padlen = PACKET_DATA_LEN - len(raw_data_packet)
			blk_idx_str = "%08X" % blk_idx
			blk_idx_list = list(util.string2hexbin(blk_idx_str))
			#log.d("blk_idx = " + blk_idx_str)

			send_list = [0] + total_len_list + blk_idx_list + raw_data_packet + [0]*padlen
			#log.d("send_list = " + str(send_list))
			#log.d("send_list len = " + str(len(send_list)))
			
			dev.write(send_list)
			blk_idx += 1
			raw_data = raw_data[PACKET_DATA_LEN:]
	
		return

	def receive(self):
		#packet = [0 for i in range(256)]

		next_blk_idx = 0
		received_len = 0
		data = bytearray(b'')
		while True:
			#log.d("wait to read")
			packet = self.usbdev.read(64)
			#log.d("packet : " + str(packet))
			total_len = int(util.bin2hexstring(bytearray(packet[:4])), 16)
			#log.d("total_len = " + str(total_len))

			blk_idx = int(util.bin2hexstring(bytearray(packet[4:8])), 16)
			#log.d("blk_idx = " + str(blk_idx))
			if blk_idx < 0:
				raise Exception("Commumication Error")
			elif next_blk_idx != blk_idx:
				raise Exception("Commumication Error")

			if total_len < received_len+PACKET_DATA_LEN:
				packet_data_len = total_len - received_len
			else:
				packet_data_len = PACKET_DATA_LEN

			#log.d("packet_data_len = " + str(packet_data_len))
			#log.d("packet[8:packet_data_len] : " + str(packet[8:8+packet_data_len]))
			data.extend(bytearray(packet[8:8+packet_data_len]))
			next_blk_idx += 1
			received_len += packet_data_len
			if len(data) >= total_len:
				break

		return bytes(data)

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

