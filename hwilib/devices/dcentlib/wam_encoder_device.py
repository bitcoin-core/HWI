#!/usr/bin/python

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

from . import wam_log as log
from . import wam_debug as DEBUG
from . import wam_error as error

from . import protobuf as message
from . import wam_util as util
import json

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */
MAX_LABEL_SIZE = 11

_pb_state_dicts = {
	"init" : message.wallet_state_t.init,
	"ready" : message.wallet_state_t.ready,
	"secure" : message.wallet_state_t.secure,
	"locked_fp" : message.wallet_state_t.locked_fp,
	"locked_pin" : message.wallet_state_t.locked_pin,
	"invalid" : message.wallet_state_t.invalid
}

_pb_json_map_dicts = {
	"state" : _pb_state_dicts,
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

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

def pb_get_parameter_set_label(json_parameter):
	if len(json_parameter["label"]) >= MAX_LABEL_SIZE:
		error.raiseWam("max label len is " + str(MAX_LABEL_SIZE))

	pb_parameter = message.set_label_req_parameter_t(json_parameter["label"])
	return util.pb_serializeToString(pb_parameter)

def pb_get_parameter_init_wallet(json_parameter):
	#
	# no parameter check because this command only for test mode

	mnemonic_str = json_parameter["mnemonic"]
	pb_parameter = message.init_wallet_req_parameter_t()
	pb_parameter.mnemonic.extend(mnemonic_str.split(' '))
	return util.pb_serializeToString(pb_parameter)

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

def encode_getinfo(request_to, version, json_parameter):
	pb_request_list = []
	
	pb_request = util.pb_makeTransactionReq()
	pb_request.header.version = version
	pb_request.header.request_to = request_to
	pb_request.body.command.value = message.device_t.get_info

	pb_request_list.append(pb_request)

	return pb_request_list

def encode_setlabel(request_to, version, json_parameter):
	pb_request_list = []
	
	pb_request = util.pb_makeTransactionReq()
	pb_request.header.version = version
	pb_request.header.request_to = request_to

	pb_request.body.command.value = message.device_t.set_label
	pb_request.body.parameter = pb_get_parameter_set_label(json_parameter)

	pb_request_list.append(pb_request)

	return pb_request_list

def encode_init_wallet(request_to, version, json_parameter):
	pb_request_list = []
	
	pb_request = util.pb_makeTransactionReq()
	pb_request.header.version = version
	pb_request.header.request_to = request_to

	pb_request.body.command.value = message.device_t.init_wallet
	pb_request.body.parameter = pb_get_parameter_init_wallet(json_parameter)

	pb_request_list.append(pb_request)

	return pb_request_list

def encode_reboot_to_bl(request_to, version, json_parameter):
	pb_request_list = []
	
	pb_request = util.pb_makeTransactionReq()
	pb_request.header.version = version
	pb_request.header.request_to = request_to

	pb_request.body.command.value = message.device_t.reboot_to_bl

	pb_request_list.append(pb_request)

	return pb_request_list


def encode(request_to, version, json_body):
	command = json_body["command"]
	if command == "get_info":
		pb_request_list = encode_getinfo(request_to, version, json_body["parameter"])
	elif command == "set_label":
		pb_request_list = encode_setlabel(request_to, version, json_body["parameter"])
	elif command == "init_wallet":
		pb_request_list = encode_init_wallet(request_to, version, json_body["parameter"])
	elif command == "reboot_to_bl":
		pb_request_list = encode_reboot_to_bl(request_to, version, json_body["parameter"])
	else:
		DEBUG.NOT_IMPLEMENTED()

	return pb_request_list

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

def json_get_fingerprint(pb_fingerprint):
	json_max = int(pb_fingerprint.max_num)
	json_enrolled = int(pb_fingerprint.enrolled)
	json_fingerprint = {
		"max" : json_max,
		"enrolled" : json_enrolled
	}
	return json_fingerprint

def json_get_coinlist(pb_coinlist):
	json_coin_list = []
	for pb_coin in pb_coinlist:
		json_name = pb_coin.name
		json_coin = {
			"name" : json_name
		}
		json_coin_list.append(json_coin)

	return json_coin_list

def decode_getinfo(command, pb_response_list):
	if len(pb_response_list) != 1:
		DEBUG.NOT_REACHED()
	
	for pb_response in pb_response_list:
		if pb_response.body.error is not None:
			DEBUG.NOT_REACHED()	# Error already Checked

		if pb_response.body.command.value != message.device_t.get_info:
			DEBUG.NOT_REACHED()
		pb_get_info_parameter = util.pb_serializeFromString(pb_response.body.parameter, message.get_info_res_parameter_t)
		this_param = pb_get_info_parameter

		json_device_id = this_param.devid
		json_fw_version = this_param.fw_ver
		json_ksm_version = this_param.ksm_ver
		json_state = json_get("state", this_param.state)
		json_coin_list = json_get_coinlist(this_param.coin)
		json_fingerprint = json_get_fingerprint(this_param.fingerprint)
		json_label = this_param.label

	# //

	json_parameter = {
		"device_id" : json_device_id,
		"fw_version" : json_fw_version,
		"ksm_version" : json_ksm_version,
		"state" : json_state, 
		"coin_list" : json_coin_list,
		"fingerprint" : json_fingerprint,
		"label" : json_label
	}
			
	json_body = {
		"command" : command,
		"parameter" : json_parameter
	}

	return json_body

def decode_setlabel(command, pb_response_list):
	if len(pb_response_list) != 1:
		DEBUG.NOT_REACHED()
	
	for pb_response in pb_response_list:
		if pb_response.body.error is not None:
			DEBUG.NOT_REACHED()	# Error already Checked

		if pb_response.body.command.value != message.device_t.set_label:
			DEBUG.NOT_REACHED()

	# //

	json_parameter = {
	}
			
	json_body = {
		"command" : command,
		"parameter" : json_parameter
	}

	return json_body

def decode_init_wallet(command, pb_response_list):
	if len(pb_response_list) != 1:
		DEBUG.NOT_REACHED()
	
	for pb_response in pb_response_list:
		if pb_response.body.error is not None:
			DEBUG.NOT_REACHED()	# Error already Checked

		if pb_response.body.command.value != message.device_t.init_wallet:
			DEBUG.NOT_REACHED()

	# //

	json_parameter = {
	}
			
	json_body = {
		"command" : command,
		"parameter" : json_parameter
	}

	return json_body

def decode(command, pb_response_list):
	if command == "get_info":
		json_body = decode_getinfo(command, pb_response_list)
	elif command == "set_label":
		json_body = decode_setlabel(command, pb_response_list)
	elif command == "init_wallet":
		json_body = decode_init_wallet(command, pb_response_list)
	else:
		DEBUG.NOT_IMPLEMENTED()

	return json_body

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

