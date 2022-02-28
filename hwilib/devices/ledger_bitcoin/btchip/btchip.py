"""
*******************************************************************************
*   BTChip Bitcoin Hardware Wallet Python API
*   (c) 2014 BTChip - 1BTChip7VfTnrPra5jqci7ejnMguuHogTn
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*   limitations under the License.
********************************************************************************
"""

from .bitcoinTransaction import *
from .bitcoinVarint import *
from .btchipException import *
from .btchipHelpers import *
from binascii import hexlify, unhexlify

class btchip:
	BTCHIP_CLA = 0xe0
	BTCHIP_CLA_COMMON_SDK = 0xb0
	BTCHIP_JC_EXT_CLA = 0xf0

	BTCHIP_INS_GET_APP_NAME_AND_VERSION = 0x01
	BTCHIP_INS_SET_ALTERNATE_COIN_VERSION = 0x14
	BTCHIP_INS_SETUP = 0x20
	BTCHIP_INS_VERIFY_PIN = 0x22
	BTCHIP_INS_GET_OPERATION_MODE = 0x24
	BTCHIP_INS_SET_OPERATION_MODE = 0x26
	BTCHIP_INS_SET_KEYMAP = 0x28
	BTCHIP_INS_SET_COMM_PROTOCOL = 0x2a
	BTCHIP_INS_GET_WALLET_PUBLIC_KEY = 0x40
	BTCHIP_INS_GET_TRUSTED_INPUT = 0x42
	BTCHIP_INS_HASH_INPUT_START = 0x44
	BTCHIP_INS_HASH_INPUT_FINALIZE = 0x46
	BTCHIP_INS_HASH_SIGN = 0x48
	BTCHIP_INS_HASH_INPUT_FINALIZE_FULL = 0x4a
	BTCHIP_INS_GET_INTERNAL_CHAIN_INDEX = 0x4c
	BTCHIP_INS_SIGN_MESSAGE = 0x4e
	BTCHIP_INS_GET_TRANSACTION_LIMIT = 0xa0
	BTCHIP_INS_SET_TRANSACTION_LIMIT = 0xa2
	BTCHIP_INS_IMPORT_PRIVATE_KEY = 0xb0
	BTCHIP_INS_GET_PUBLIC_KEY = 0xb2
	BTCHIP_INS_DERIVE_BIP32_KEY = 0xb4
	BTCHIP_INS_SIGNVERIFY_IMMEDIATE = 0xb6
	BTCHIP_INS_GET_RANDOM = 0xc0
	BTCHIP_INS_GET_ATTESTATION = 0xc2
	BTCHIP_INS_GET_FIRMWARE_VERSION = 0xc4
	BTCHIP_INS_COMPOSE_MOFN_ADDRESS = 0xc6
	BTCHIP_INS_GET_POS_SEED = 0xca

	BTCHIP_INS_EXT_GET_HALF_PUBLIC_KEY = 0x20
	BTCHIP_INS_EXT_CACHE_PUT_PUBLIC_KEY = 0x22
	BTCHIP_INS_EXT_CACHE_HAS_PUBLIC_KEY = 0x24
	BTCHIP_INS_EXT_CACHE_GET_FEATURES = 0x26

	OPERATION_MODE_WALLET = 0x01
	OPERATION_MODE_RELAXED_WALLET = 0x02 
	OPERATION_MODE_SERVER = 0x04
	OPERATION_MODE_DEVELOPER = 0x08

	FEATURE_UNCOMPRESSED_KEYS = 0x01
	FEATURE_RFC6979 = 0x02
	FEATURE_FREE_SIGHASHTYPE = 0x04
	FEATURE_NO_2FA_P2SH = 0x08

	QWERTY_KEYMAP = bytearray(unhexlify("000000000000000000000000760f00d4ffffffc7000000782c1e3420212224342627252e362d3738271e1f202122232425263333362e37381f0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d2f3130232d350405060708090a0b0c0d0e0f101112131415161718191a1b1c1d2f313035"))
	QWERTZ_KEYMAP = bytearray(unhexlify("000000000000000000000000760f00d4ffffffc7000000782c1e3420212224342627252e362d3738271e1f202122232425263333362e37381f0405060708090a0b0c0d0e0f101112131415161718191a1b1d1c2f3130232d350405060708090a0b0c0d0e0f101112131415161718191a1b1d1c2f313035"))
	AZERTY_KEYMAP = bytearray(unhexlify("08000000010000200100007820c8ffc3feffff07000000002c38202030341e21222d352e102e3637271e1f202122232425263736362e37101f1405060708090a0b0c0d0e0f331112130415161718191d1b1c1a2f64302f2d351405060708090a0b0c0d0e0f331112130415161718191d1b1c1a2f643035"))

	def __init__(self, dongle):
		self.dongle = dongle
		self.needKeyCache = False
		try:
			firmware = self.getFirmwareVersion()['version']
			self.multiOutputSupported = tuple(map(int, (firmware.split(".")))) >= (1, 1, 4)
			if self.multiOutputSupported:
				self.scriptBlockLength = 50
			else:
				self.scriptBlockLength = 255
		except Exception:
			pass				

	def getWalletPublicKey(self, path, showOnScreen=False, segwit=False, segwitNative=False, cashAddr=False):
		result = {}
		donglePath = parse_bip32_path(path)
		if self.needKeyCache:
			self.resolvePublicKeysInPath(path)			
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_WALLET_PUBLIC_KEY, 0x01 if showOnScreen else 0x00, 0x03 if cashAddr else 0x02 if segwitNative else 0x01 if segwit else 0x00, len(donglePath) ]
		apdu.extend(donglePath)
		response = self.dongle.exchange(bytearray(apdu))
		offset = 0
		result['publicKey'] = response[offset + 1 : offset + 1 + response[offset]]
		offset = offset + 1 + response[offset]
		result['address'] = str(response[offset + 1 : offset + 1 + response[offset]])
		offset = offset + 1 + response[offset]
		result['chainCode'] = response[offset : offset + 32]
		return result

	def getTrustedInput(self, transaction, index):
		result = {}
		# Header
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x00, 0x00 ]
		params = bytearray.fromhex("%.8x" % (index))
		params.extend(transaction.version)
		writeVarint(len(transaction.inputs), params)
		apdu.append(len(params))
		apdu.extend(params)
		self.dongle.exchange(bytearray(apdu))
		# Each input
		for trinput in transaction.inputs:
			apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00 ]
			params = bytearray(trinput.prevOut)
			writeVarint(len(trinput.script), params)
			apdu.append(len(params))
			apdu.extend(params)
			self.dongle.exchange(bytearray(apdu))
			offset = 0
			while True:
				blockLength = 251
				if ((offset + blockLength) < len(trinput.script)):
					dataLength = blockLength
				else:
					dataLength = len(trinput.script) - offset
				params = bytearray(trinput.script[offset : offset + dataLength])
				if ((offset + dataLength) == len(trinput.script)):
					params.extend(trinput.sequence)
				apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00, len(params) ]
				apdu.extend(params)
				self.dongle.exchange(bytearray(apdu))
				offset += dataLength
				if (offset >= len(trinput.script)):
					break
		# Number of outputs
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00 ]
		params = []
		writeVarint(len(transaction.outputs), params)
		apdu.append(len(params))
		apdu.extend(params)
		self.dongle.exchange(bytearray(apdu))
		# Each output
		indexOutput = 0
		for troutput in transaction.outputs:
			apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00 ]
			params = bytearray(troutput.amount)
			writeVarint(len(troutput.script), params)
			apdu.append(len(params))
			apdu.extend(params)
			self.dongle.exchange(bytearray(apdu))
			offset = 0
			while (offset < len(troutput.script)):
				blockLength = 255
				if ((offset + blockLength) < len(troutput.script)):
					dataLength = blockLength
				else:
					dataLength = len(troutput.script) - offset
				apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00, dataLength ]
				apdu.extend(troutput.script[offset : offset + dataLength])
				self.dongle.exchange(bytearray(apdu))
				offset += dataLength
		# Locktime
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_TRUSTED_INPUT, 0x80, 0x00, len(transaction.lockTime) ]
		apdu.extend(transaction.lockTime)
		response = self.dongle.exchange(bytearray(apdu))
		result['trustedInput'] = True
		result['value'] = response
		return result

	def startUntrustedTransaction(self, newTransaction, inputIndex, outputList, redeemScript, version=0x01, cashAddr=False, continueSegwit=False):
		# Start building a fake transaction with the passed inputs
		segwit = False
		if newTransaction:
			for passedOutput in outputList:
				if ('witness' in passedOutput) and passedOutput['witness']:
					segwit = True
					break
		if newTransaction:
			if segwit:
				p2 = 0x03 if cashAddr else 0x02
			else:
				p2 = 0x00
		else:
				p2 = 0x10 if continueSegwit else 0x80
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_START, 0x00, p2 ]
		params = bytearray([version, 0x00, 0x00, 0x00])
		writeVarint(len(outputList), params)
		apdu.append(len(params))
		apdu.extend(params)
		self.dongle.exchange(bytearray(apdu))
		# Loop for each input
		currentIndex = 0
		for passedOutput in outputList:
			if ('sequence' in passedOutput) and passedOutput['sequence']:
				sequence = bytearray(unhexlify(passedOutput['sequence']))
			else:
				sequence = bytearray([0xFF, 0xFF, 0xFF, 0xFF]) # default sequence
			apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_START, 0x80, 0x00 ]
			params = []
			script = bytearray(redeemScript)
			if ('trustedInput' in passedOutput) and passedOutput['trustedInput']:
				params.append(0x01)
			elif ('witness' in passedOutput) and passedOutput['witness']:
				params.append(0x02)
			else:
				params.append(0x00)
			if ('trustedInput' in passedOutput) and passedOutput['trustedInput']:
				params.append(len(passedOutput['value']))
			params.extend(passedOutput['value'])
			if currentIndex != inputIndex:
				script = bytearray()
			writeVarint(len(script), params)
			apdu.append(len(params))
			apdu.extend(params)
			self.dongle.exchange(bytearray(apdu))
			offset = 0
			while(offset < len(script)):
				blockLength = 255
				if ((offset + blockLength) < len(script)):
					dataLength = blockLength
				else:
					dataLength = len(script) - offset
				params = script[offset : offset + dataLength]
				if ((offset + dataLength) == len(script)):
					params.extend(sequence)
				apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_START, 0x80, 0x00, len(params) ]
				apdu.extend(params)
				self.dongle.exchange(bytearray(apdu))
				offset += blockLength
			if len(script) == 0:
				apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_START, 0x80, 0x00, len(sequence) ]
				apdu.extend(sequence)
				self.dongle.exchange(bytearray(apdu))				
			currentIndex += 1

	def finalizeInput(self, outputAddress, amount, fees, changePath, rawTx=None):
		alternateEncoding = False
		donglePath = parse_bip32_path(changePath)
		if self.needKeyCache:
			self.resolvePublicKeysInPath(changePath)		
		result = {}
		outputs = None
		if rawTx is not None:
			try:
				fullTx = bitcoinTransaction(bytearray(rawTx))
				outputs = fullTx.serializeOutputs()
				if len(donglePath) != 0:
					apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_FINALIZE_FULL, 0xFF, 0x00 ]
					params = []
					params.extend(donglePath)
					apdu.append(len(params))
					apdu.extend(params)
					response = self.dongle.exchange(bytearray(apdu))
				offset = 0
				while (offset < len(outputs)):
					blockLength = self.scriptBlockLength
					if ((offset + blockLength) < len(outputs)):
						dataLength = blockLength
						p1 = 0x00
					else:
						dataLength = len(outputs) - offset
						p1 = 0x80
					apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_FINALIZE_FULL, \
						p1, 0x00, dataLength ]
					apdu.extend(outputs[offset : offset + dataLength])
					response = self.dongle.exchange(bytearray(apdu))
					offset += dataLength
				alternateEncoding = True
			except Exception:
				pass
		if not alternateEncoding:
			apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_INPUT_FINALIZE, 0x02, 0x00 ]
			params = []
			params.append(len(outputAddress))
			params.extend(bytearray(outputAddress))
			writeHexAmountBE(btc_to_satoshi(str(amount)), params)
			writeHexAmountBE(btc_to_satoshi(str(fees)), params)
			params.extend(donglePath)
			apdu.append(len(params))
			apdu.extend(params)
			response = self.dongle.exchange(bytearray(apdu))
		result['confirmationNeeded'] = response[1 + response[0]] != 0x00
		result['confirmationType'] = response[1 + response[0]]
		if result['confirmationType'] == 0x02:
			result['keycardData'] = response[1 + response[0] + 1:]
		if result['confirmationType'] == 0x03:
			offset = 1 + response[0] + 1 
			keycardDataLength = response[offset]
			offset = offset + 1
			result['keycardData'] = response[offset : offset + keycardDataLength]
			offset = offset + keycardDataLength
			result['secureScreenData'] = response[offset:]
		if result['confirmationType'] == 0x04:
			offset = 1 + response[0] + 1
			keycardDataLength = response[offset]
			result['keycardData'] = response[offset + 1 : offset + 1 + keycardDataLength]			
		if outputs == None:
			result['outputData'] = response[1 : 1 + response[0]]
		else:
			result['outputData'] = outputs
		return result

	def untrustedHashSign(self, path, pin="", lockTime=0, sighashType=0x01):
		if isinstance(pin, str):
			pin = pin.encode('utf-8')
		donglePath = parse_bip32_path(path)
		if self.needKeyCache:
			self.resolvePublicKeysInPath(path)		
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_HASH_SIGN, 0x00, 0x00 ]
		params = []
		params.extend(donglePath)
		params.append(len(pin))
		params.extend(bytearray(pin))
		writeUint32BE(lockTime, params)
		params.append(sighashType)
		apdu.append(len(params))
		apdu.extend(params)
		result = self.dongle.exchange(bytearray(apdu))
		result[0] = 0x30
		return result

	def signMessagePrepareV1(self, path, message):
		donglePath = parse_bip32_path(path)
		if self.needKeyCache:
			self.resolvePublicKeysInPath(path)		
		result = {}
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_SIGN_MESSAGE, 0x00, 0x00 ]
		params = []
		params.extend(donglePath)
		params.append(len(message))
		params.extend(bytearray(message))
		apdu.append(len(params))
		apdu.extend(params)
		response = self.dongle.exchange(bytearray(apdu))
		result['confirmationNeeded'] = response[0] != 0x00
		result['confirmationType'] = response[0]
		if result['confirmationType'] == 0x02:
			result['keycardData'] = response[1:]
		if result['confirmationType'] == 0x03:
			result['secureScreenData'] = response[1:]
		return result

	def signMessagePrepareV2(self, path, message):
		donglePath = parse_bip32_path(path)
		if self.needKeyCache:
			self.resolvePublicKeysInPath(path)				
		result = {}
		offset = 0
		encryptedOutputData = b""
		while (offset < len(message)):
			params = [];
			if offset == 0:
				params.extend(donglePath)
				params.append((len(message) >> 8) & 0xff)
				params.append(len(message) & 0xff)
				p2 = 0x01
			else:
				p2 = 0x80
			blockLength = 255 - len(params)
			if ((offset + blockLength) < len(message)):
				dataLength = blockLength
			else:
				dataLength = len(message) - offset
			params.extend(bytearray(message[offset : offset + dataLength]))
			apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_SIGN_MESSAGE, 0x00, p2 ]
			apdu.append(len(params))
			apdu.extend(params)
			response = self.dongle.exchange(bytearray(apdu))
			encryptedOutputData = encryptedOutputData + response[1 : 1 + response[0]]
			offset += blockLength
		result['confirmationNeeded'] = response[1 + response[0]] != 0x00
		result['confirmationType'] = response[1 + response[0]]
		if result['confirmationType'] == 0x03:
			offset = 1 + response[0] + 1
			result['secureScreenData'] = response[offset:]			
			result['encryptedOutputData'] = encryptedOutputData 

		return result

	def signMessagePrepare(self, path, message):
		try:
			result = self.signMessagePrepareV2(path, message)
		except BTChipException as e:
			if (e.sw == 0x6b00): # Old firmware version, try older method
				result = self.signMessagePrepareV1(path, message)
			else:
				raise
		return result

	def signMessageSign(self, pin=""):
		if isinstance(pin, str):
			pin = pin.encode('utf-8')
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_SIGN_MESSAGE, 0x80, 0x00 ]
		params = []
		if pin is not None:
			params.append(len(pin))
			params.extend(bytearray(pin))
		else:
			params.append(0x00)
		apdu.append(len(params))
		apdu.extend(params)
		response = self.dongle.exchange(bytearray(apdu))
		return response

	def getAppName(self):
		apdu = [ self.BTCHIP_CLA_COMMON_SDK, self.BTCHIP_INS_GET_APP_NAME_AND_VERSION, 0x00, 0x00, 0x00 ]
		try:
			response = self.dongle.exchange(bytearray(apdu))
			name_len = response[1]
			name = response[2:][:name_len]
			if b'OLOS' not in name:
				return name.decode('ascii')
		except BTChipException as e:
			if e.sw == 0x6faa:
				# ins not implemented"
				return None
			if e.sw == 0x6d00:
				# Not in an app, return just a string saying that
				return "not in an app"
			raise

	def getFirmwareVersion(self):
		result = {}
		apdu = [ self.BTCHIP_CLA, self.BTCHIP_INS_GET_FIRMWARE_VERSION, 0x00, 0x00, 0x00 ]
		try:
			response = self.dongle.exchange(bytearray(apdu))
		except BTChipException as e:
			if (e.sw == 0x6985):
				response = [0x00, 0x00, 0x01, 0x04, 0x03 ]
				pass
			else:
				raise
		result['compressedKeys'] = (response[0] == 0x01)
		result['version'] = "%d.%d.%d" % (response[2], response[3], response[4])
		result['major_version'] = response[2]
		result['minor_version'] = response[3]
		result['patch_version'] = response[4]
		result['specialVersion'] = response[1]
		return result
