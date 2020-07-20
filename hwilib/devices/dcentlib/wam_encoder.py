#!/usr/bin/env python

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

from . import wam_log as log
from . import wam_debug as DEBUG

from .protobuf import general_pb2

import json

from . import wam_encoder_device as encoder_device
from . import wam_encoder_coin as encoder_coin
from . import wam_encoder_bitcoin as encoder_bitcoin

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

_pb_version_dicts = {
	"1.0" : 1
}

_pb_cointype_dicts = {
	"device" : general_pb2.device,
	"coin" : general_pb2.coin,
	"bitcoin" : general_pb2.bitcoin,
	"bitcoin-testnet" : general_pb2.bitcoin_testnet,
	"bitcoin-segwit" : general_pb2.bitcoin_segwit,
	"bitcoin-segwit-testnet" : general_pb2.bitcoin_segwit_testnet,
}

_pb_status_dicts = {
	"success" : 0,
	"error" : 1
}

_pb_error_code_dicts = {
	"none" : general_pb2.none,
	"invalid_access" : general_pb2.invalid_access,
	"internal_process" : general_pb2.internal_process,
	"memory_access" : general_pb2.memory_access,
	"invalid_format" : general_pb2.invalid_format,
	"not_support" : general_pb2.not_support,
	"invalid_command" : general_pb2.invalid_command,
	"wrong_length" : general_pb2.wrong_length,
	"wrong_number" : general_pb2.wrong_number,
	"lowlevel_protocol" : general_pb2.lowlevel_protocol,
	"user_cancel" : general_pb2.user_cancel,
	"device_busy" : general_pb2.device_busy,
	"unknown" : general_pb2.unknown
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
			encoded = pb_request.SerializeToString()
			#log.d("encoded : " + str(encoded))
			encoded_list.append(encoded)

		return encoded_list

	def decode(self, stream_list):
		#log.i("STREAM to be decoded :")
		#log.i(str(stream))

		pb_response_list = []
		is_error_case = False
		for encoded_stream in stream_list:
			pb_response = general_pb2.response()
			pb_response.ParseFromString(encoded_stream)
			if pb_response.body.HasField("error") is True:
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
	pb_response = general_pb2.response()
	pb_response.ParseFromString(stream)
	return pb_response.body.has_more

def get_is_error(stream):
	pb_response = general_pb2.response()
	pb_response.ParseFromString(stream)
	return pb_response.header.is_error

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

