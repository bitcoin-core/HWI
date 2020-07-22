#!/usr/bin/env python

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */
import json
from io import BytesIO

from . import wam_log as log
from . import wam_debug as DEBUG
from . import protobuf as message
from . import wam_encoder_device as encoder_device
from . import wam_encoder_coin as encoder_coin
from . import wam_encoder_bitcoin as encoder_bitcoin
from . import prototrez as proto

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

_pb_version_dicts = {
	"1.0" : 1
}

_pb_cointype_dicts = {
	"device" : message.cointype_t.device,
	"coin" : message.cointype_t.coin,
	"bitcoin" : message.cointype_t.bitcoin,
	"bitcoin-testnet" : message.cointype_t.bitcoin_testnet,
	"bitcoin-segwit" : message.cointype_t.bitcoin_segwit,
	"bitcoin-segwit-testnet" : message.cointype_t.bitcoin_segwit_testnet,
}

_pb_status_dicts = {
	"success" : 0,
	"error" : 1
}

_pb_error_code_dicts = {
	"none" : message.error_code_t.none,
	"invalid_access" : message.error_code_t.invalid_access,
	"internal_process" : message.error_code_t.internal_process,
	"memory_access" : message.error_code_t.memory_access,
	"invalid_format" : message.error_code_t.invalid_format,
	"not_support" : message.error_code_t.not_support,
	"invalid_command" : message.error_code_t.invalid_command,
	"wrong_length" : message.error_code_t.wrong_length,
	"wrong_number" : message.error_code_t.wrong_number,
	"lowlevel_protocol" : message.error_code_t.lowlevel_protocol,
	"user_cancel" : message.error_code_t.user_cancel,
	"device_busy" : message.error_code_t.device_busy,
	"unknown" : message.error_code_t.unknown
}

_pb_json_map_dicts = {
	"version" : _pb_version_dicts,
	"request_to" : _pb_cointype_dicts,
	"response_from" : _pb_cointype_dicts,
	"status" : _pb_status_dicts,
	"error.code" : _pb_error_code_dicts
}

def convert_dics(dics):
	converted_dics = {}
	for (key, value) in dics.items():
		converted_dics[value] = key
	return converted_dics

def pb_get(key, json_value):
	dicts = _pb_json_map_dicts[key]
	return dicts[json_value]

def json_get(key, pb_value):
	dicts = _pb_json_map_dicts[key]
	new_dicts = convert_dics(dicts)
	return new_dicts[pb_value]

def json_get_error_code(pb_error_code):
	error_code = json_get("error.code", pb_error_code)
	return error_code

def json_get_error(pb_error):
	error_code = json_get_error_code(pb_error.code)
	error_msg = pb_error.message

	json_error = {
		"code" : error_code,
		"message" : error_msg
	}

	return json_error

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

class Encoder:
	def __init__(self):
		self.version = ""
		self.request_to = ""
		self.command = ""
		return
		
	def encode(self, message):
		log.i("JSON To be Encoded : ")
		log.i(message)

		##
		#

		log.i("json load")
		json_dict = json.loads(message)
		log.dump_json("massage to be encoded", json_dict)

		##
		#
	    
		try:
			json_header = json_dict["request"]["header"]
			json_body = json_dict["request"]["body"]
			#parameter = json_body["parameter"]

		except KeyError as e:
			log.e("No Key in JSON : " + str(e))

		##
		#

		self.version = json_header["version"]
		self.request_to = json_header["request_to"]
		self.command = json_body["command"]

		##
		#

		version = pb_get("version", json_header["version"])
		request_to = json_header["request_to"]
		pb_request_to = pb_get("request_to", json_header["request_to"])
		if request_to == "device":
			pb_request_list = encoder_device.encode(pb_request_to, version, json_body)
		elif request_to == "coin":
			pb_request_list = encoder_coin.encode(pb_request_to, version, json_body)
		elif request_to == "bitcoin" or request_to == "bitcoin-testnet"  \
			or self.request_to == "bitcoin-segwit" or self.request_to == "bitcoin-segwit-testnet":
			pb_request_list = encoder_bitcoin.encode(pb_request_to, version, json_body)
		else:
			log.e("request to : "+request_to)
			DEBUG.NOT_SUPPORTED()

		encoded_list = []
		for pb_request in pb_request_list:
			data = BytesIO()
			proto.dump_message(data, pb_request)
			encoded = data.getvalue()
			encoded_list.append(encoded)

		return encoded_list

	def decode(self, stream_list):
		#log.i("STREAM to be decoded :")
		#log.i(str(stream))

		pb_response_list = []
		is_error_case = False
		for encoded_stream in stream_list:
			data = BytesIO(encoded_stream)
			pb_response = proto.load_message(data, message.response)
			
			if pb_response.body.error is not None:
				json_error = json_get_error(pb_response.body.error)
				json_body = {
					"command" : self.command,
					"error" : json_error
				}
				is_error_case = True
				break
			else:
				pb_response_list.append(pb_response)

		#//
		#

		if is_error_case is False:
			if self.request_to == "device":
				json_body = encoder_device.decode(self.command, pb_response_list)
			elif self.request_to == "coin":
				json_body = encoder_coin.decode(self.command, pb_response_list)
			elif self.request_to == "bitcoin" or self.request_to == "bitcoin-testnet" \
				or self.request_to == "bitcoin-segwit" or self.request_to == "bitcoin-segwit-testnet":
				json_body = encoder_bitcoin.decode(self.command, pb_response_list)
			else:
				log.e("request to : "+self.request_to)
				DEBUG.NOT_SUPPORTED()

		#//
		#

		if "error" in json_body:
			json_status = "error"
		else:
			json_status = "success"

		json_header = {
			"version" : self.version,
			"response_from" : self.request_to,
			"status" : json_status
		}

		json_response = {
			"response" : {
				"header" : json_header,
				"body" : json_body
			}
		}

		log.dump_json("decoded", json_response)
		json_string = json.dumps(json_response)

		return json_string

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

def get_has_more(stream):
	data = BytesIO(stream)
	pb_response = proto.load_message(data, message.response)
	return pb_response.body.has_more

def get_is_error(stream):
	data = BytesIO(stream)
	pb_response = proto.load_message(data, message.response)
	return pb_response.header.is_error

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

