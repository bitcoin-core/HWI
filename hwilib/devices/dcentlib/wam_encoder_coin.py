#!/usr/bin/python

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

from . import wam_log as log
from . import wam_debug as DEBUG
from . import wam_util as util
from . import wam_error as error

from . import protobuf as message

import json

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */
#
MAX_DATE_SIZE = 17
MAX_COIN_GROUP_SIZE = 16
MAX_COIN_NAME_SIZE = 16
MAX_LABEL_SIZE = 15
MAX_BALANCE_SIZE = 15
MAX_ADDRESS_PATH_SIZE = 25

#
MAX_PUBKEY_BIP32NAME_SIZE = 17
MAX_PUBKEY_PATH_SIZE = 51

def convert_dics(dics):
	converted_dics = {}
	for (key, value) in dics.items():
		converted_dics[value] = key
	return converted_dics
#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

def pb_get_parameter_sync_account(json_parameter):

	log.d("[ENTER]")

	if len(json_parameter["date"]) >= MAX_DATE_SIZE:
		error.raiseWam("max date len is " + str(MAX_DATE_SIZE))

	json_date = json_parameter["date"]
	log.v("json_date = "+json_date)

	total_num = len(json_parameter["account"])
	account_idx = 0
	pb_parameter_list = []
	for json_account in json_parameter["account"]:
		if len(json_account["coin_group"]) >= MAX_COIN_GROUP_SIZE:
			error.raiseWam("max coin group len is " + str(MAX_COIN_GROUP_SIZE))
		elif len(json_account["coin_name"]) >= MAX_COIN_NAME_SIZE:
			error.raiseWam("max coin name len is " + str(MAX_COIN_NAME_SIZE))
		elif len(json_account["label"]) >= MAX_LABEL_SIZE:
			error.raiseWam("max label len is " + str(MAX_LABEL_SIZE))
		elif len(json_account["balance"]) >= MAX_BALANCE_SIZE:
			error.raiseWam("max balance len is " + str(MAX_BALANCE_SIZE))
		elif len(json_account["address_path"]) >= MAX_ADDRESS_PATH_SIZE:
			error.raiseWam("max address path len is " + str(MAX_ADDRESS_PATH_SIZE))

		pb_parameter = message.sync_account_info_req_parameter_t()
		pb_parameter.total_num = total_num
		pb_parameter.account_idx = account_idx
		pb_parameter.date = json_date
		pb_parameter.coin_group = json_account["coin_group"].upper()
		pb_parameter.coin_name = json_account["coin_name"].upper()
		pb_parameter.label = json_account["label"]
		pb_parameter.balance = json_account["balance"]
		pb_parameter.address_path = json_account["address_path"]
		
		pb_parameter_list.append(util.pb_serializeToString(pb_parameter))
		account_idx += 1

	log.d("LEAVE")
		
	return pb_parameter_list

def pb_get_parameter_xpub(json_parameter):
	pb_parameter = message.extract_pubkey_req_parameter_t()

	if "bip32name" in json_parameter:
		if len(json_parameter["bip32name"]) >= MAX_PUBKEY_BIP32NAME_SIZE:
			error.raiseWam("max bip32name len is " + str(MAX_PUBKEY_BIP32NAME_SIZE))
		pb_parameter.bip32name = json_parameter["bip32name"]
	else:
		pb_parameter.bip32name = "Bitcoin seed"

	##
	#

	if len(json_parameter["key"]) >= MAX_PUBKEY_PATH_SIZE:
		error.raiseWam("max key path len is " + str(MAX_PUBKEY_PATH_SIZE))

	pb_parameter.key_path = json_parameter["key"]
		
	return util.pb_serializeToString(pb_parameter)

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

def encode_sync_account(request_to, version, json_parameter):
	pb_request_list = []
	
	pb_parameter_list = pb_get_parameter_sync_account(json_parameter)
	for pb_parameter in pb_parameter_list:
		pb_request = util.pb_makeTransactionReq()
		pb_request.header.version = version
		pb_request.header.request_to = request_to

		pb_request.body.command.value = message.coin_t.sync_account_info
		pb_request.body.parameter = pb_parameter

		pb_request_list.append(pb_request)

	return pb_request_list

def encode_get_account_info(request_to, version, json_parameter):
	pb_request_list = []
	
	pb_request = util.pb_makeTransactionReq()
	pb_request.header.version = version
	pb_request.header.request_to = request_to

	pb_request.body.command.value = message.coin_t.get_account_info

	pb_request_list.append(pb_request)

	return pb_request_list

def encode_xpub(request_to, version, json_parameter):
	pb_request_list = []
	
	pb_request = util.pb_makeTransactionReq()
	pb_request.header.version = version
	pb_request.header.request_to = request_to

	pb_request.body.command.value = message.coin_t.extract_pubkey
	pb_request.body.parameter = pb_get_parameter_xpub(json_parameter)

	pb_request_list.append(pb_request)

	return pb_request_list

def encode(request_to, version, json_body):
	command = json_body["command"]
	if command == "sync_account":
		pb_request_list = encode_sync_account(request_to, version, json_body["parameter"])
	elif command == "get_account_info":
		pb_request_list = encode_get_account_info(request_to, version, json_body["parameter"])
	elif command == "xpub":
		pb_request_list = encode_xpub(request_to, version, json_body["parameter"])
	else:
		DEBUG.NOT_IMPLEMENTED()

	return pb_request_list

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

def decode_sync_account(command, pb_response_list):

	for pb_response in pb_response_list:
		if pb_response.body.error is not None:
			DEBUG.NOT_REACHED()	# Error already Checked

		if pb_response.body.command.value != message.coin_t.sync_account_info:
			DEBUG.NOT_REACHED()

	# //

	json_parameter = {
	}
			
	json_body = {
		"command" : command,
		"parameter" : json_parameter
	}

	return json_body

def decode_get_account_info(command, pb_response_list):

	json_account_list = []
	account_idx = 0
	total_num = 0
	for pb_response in pb_response_list:
		if pb_response.body.error is not None:
			DEBUG.NOT_REACHED()	# Error already Checked

		if pb_response.body.command.value != message.coin_t.get_account_info:
			DEBUG.NOT_REACHED()

		pb_get_account_info_parameter = util.pb_serializeFromString(pb_response.body.parameter, message.get_account_info_res_parameter_t)
		this_param = pb_get_account_info_parameter

		# //

		total_num = this_param.total_num
		if total_num == 0:
			break;

		log.d("account_idx = "+str(account_idx))
		if account_idx != this_param.account_idx:
			DEBUG.NOT_REACHED()
		elif account_idx >= total_num:
			DEBUG.NOT_REACHED()

		# //

		json_account = {
			"coin_name" : this_param.coin_name,
			"label" : this_param.label,
			"address_path" : this_param.address_path
		}

		if this_param.coin_group is not None:
			json_account["coin_group"] = this_param.coin_group

		json_account_list.append(json_account)
		account_idx += 1

	log.d("total_num = "+str(total_num))
	log.d("account_idx = "+str(account_idx))
	if total_num != account_idx:
		DEBUG.NOT_REACHED()

	# //

	json_parameter = {
		"account" : json_account_list
	}
			
	json_body = {
		"command" : command,
		"parameter" : json_parameter
	}

	return json_body

def decode_xpub(command, pb_response_list):
	if len(pb_response_list) != 1:
		DEBUG.NOT_REACHED()

	json_public_key = ""
	for pb_response in pb_response_list:
		if pb_response.body.error is not None:
			DEBUG.NOT_REACHED()	# Error already Checked

		if pb_response.body.command.value != message.coin_t.extract_pubkey:
			DEBUG.NOT_REACHED()

		pb_xpub_parameter = util.pb_serializeFromString(pb_response.body.parameter, message.extract_pubkey_res_parameter_t)
		this_param = pb_xpub_parameter
		json_public_key += util.bin2hexstring(this_param.pubkey)

	json_parameter = {
		"public_key" : json_public_key
	}
			
	json_body = {
		"command" : command,
		"parameter" : json_parameter
	}

	return json_body


def decode(command, pb_response_list):
	if command == "sync_account":
		json_body = decode_sync_account(command, pb_response_list)
	elif command == "get_account_info":
		json_body = decode_get_account_info(command, pb_response_list)
	elif command == "xpub":
		json_body = decode_xpub(command, pb_response_list)
	else:
		DEBUG.NOT_IMPLEMENTED()

	return json_body

#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */

