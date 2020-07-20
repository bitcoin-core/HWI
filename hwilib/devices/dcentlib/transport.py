#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */
from . import wami_message
from . import wam_util as util
from . import wam_error as error
from . import wam_encoder as encoder
#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */
_pb_cointype = [
    { "to": "bitcoin", "isTestnet": False, "isWit": False},
	{ "to": "bitcoin-testnet", "isTestnet": True, "isWit": False},
	{ "to": "bitcoin-segwit", "isTestnet": False, "isWit": True},
	{ "to": "bitcoin-segwit-testnet", "isTestnet": True, "isWit": True},
]

def getRequestTo(isWit, isTestnet):
    ret = next((cointype for cointype in _pb_cointype if (cointype["isWit"] == isWit and cointype["isTestnet"] == isTestnet)), None)
    return ret["to"]

def _checkError(resJson):
    if(resJson["response"]["header"]["status"] == "error"):
        raise error.raiseWamByCode(resJson["response"]["body"]["error"]["code"])

class TransportRunner:

    def __init__(self):
        return

    @staticmethod
    def getPubKey(dev, path):
        request = wami_message.WamiRequest()
        request.xpub(path)
        res_json = request.send_and_receive(dev)
        _checkError(res_json)
        xpub = res_json["response"]["body"]["parameter"]["public_key"][:-2]
        return util.string2hexbin(xpub).decode('utf-8')
    
    @staticmethod
    def getSignedTx(dev, inputs, outputs, version=1, locktime=0, isTestnet=False, isSegwit=False):
        request = wami_message.WamiRequest()
        
        # requestTo = getRequestTo(inputs[0]["type"] == "p2wpkh", isTestnet)
        requestTo = getRequestTo(isSegwit, isTestnet)
        request.bitcoin_transaction(requestTo, version, locktime)

        for input in inputs:
            prev_tx = input["rawtx"]
            utxo_idx = input["vout"]
            type = input["type"]
            key = input["path"]
            sequence = input["seq"]
            request.body.parameter.add_input(prev_tx, utxo_idx, type, key, sequence)
        
        for output in outputs:
            type = output["type"]
            value = output["value"]
            to = [output["address"]]
            request.body.parameter.add_output(type, value, to)
        
        res_json = request.send_and_receive(dev)

        _checkError(res_json)
        return res_json['response']['body']['parameter']['signed']

    @staticmethod
    def signMessage(dev, message, path):
        request = wami_message.WamiRequest()
        request.sign_message(message, path)
        res_json = request.send_and_receive(dev)

        _checkError(res_json)
        signature = res_json["response"]["body"]["parameter"]["msg_signed"]
        return signature

    @staticmethod
    def getAddress(dev, path, isWit, isTestnet):
        request = wami_message.WamiRequest()
        requestTo = getRequestTo(isWit, isTestnet)
        request.get_address(requestTo, path)
        res_json = request.send_and_receive(dev)

        _checkError(res_json)
        return res_json['response']['body']['parameter']['address']



#/* ############################################################ */
#/* //////////////////////////////////////////////////////////// */
#/* */
#/* //////////////////////////////////////////////////////////// */
#/* ############################################################ */
