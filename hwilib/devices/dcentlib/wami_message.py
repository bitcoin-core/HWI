import json
import datetime
import codecs
from . import wami

string_types = (bytes, str, bytearray)

def encode_hex(value):
    binary_hex = codecs.encode(value, 'hex')
    return "0x" + binary_hex.decode('ascii')

def is_string(value):
    return isinstance(value, string_types)

class Object:
    def to_json(self, type):
        obj = Object()
        setattr(obj, type, self)
        return json.dumps(obj, default=lambda o: o.__dict__,
                          indent=4)

class WamiHeader(Object):
    def __init__(self, version="1.0", request_to="device"):
        self.version = version
        self.request_to = request_to

    #def to_json(self):
    #    result = json.dumps(self, default=lambda o: o.__dict__, indent=4)
    #    print(result)
    #    return self.__dict__

class WamiRequestBodyParameterAccount(Object):
    def __init__(self, **kargs):
        for key, value in kargs.items():
            setattr(self, key, value)

class WamiRequestBodyParameterValue(Object):
    def __init__(self, **kargs):
        for key, value in kargs.items():
            setattr(self, key, value)

class WamiRequestBodyParameter(Object):
    def __init__(self):
        pass

    def add_account(self, coin_group, coin_name, label, balance, address_path):
        if not hasattr(self, "account"):
            self.account = []

        self.account.append(WamiRequestBodyParameterAccount(
            coin_group=coin_group, coin_name=coin_name,
            label=label, balance=balance, address_path=address_path))

    def add_input(self, prev_tx, utxo_idx, type, key, sequence):
        if not hasattr(self, "input"):
            self.input = []

        self.input.append(WamiRequestBodyParameterValue(
            prev_tx=prev_tx, utxo_idx=utxo_idx, type=type, key=key, sequence=sequence))

    def add_output(self, type, value, to):
        if not hasattr(self, "output"):
            self.output = []

        self.output.append(WamiRequestBodyParameterValue(
            type=type, value=value, to=to))

    def set_value(self, **kargs):
        for key, value in kargs.items():
            setattr(self, key, value)

class WamiRequstBody(Object):
    def __init__(self, command=None):
        self.command = None
        self.parameter = WamiRequestBodyParameter()

class WamiRequest(Object):
    def __init__(self):
        self.header = WamiHeader()
        self.body = WamiRequstBody()

    def to_json(self):
        return super(WamiRequest, self).to_json("request")

    def init_wallet(self, mnemonic):
        self.header.request_to = "device"
        self.body.command = "init_wallet"

        self.body.parameter.mnemonic = mnemonic

    def get_info(self):
        self.header.request_to = "device"
        self.body.command = "get_info"

    def set_label(self, label):
        self.header.request_to = "device"

        self.body.command = "set_label"
        self.body.parameter.label = label

    def sync_account(self):
        self.header.request_to = "coin"

        self.body.command = "sync_account"
        self.body.parameter.date = str(datetime.datetime.now())[:16]

    def get_account_info(self):
        self.header.request_to = "coin"

        self.body.command = "get_account_info"
    
    def xpub(self, key="m/44'/0'/0'", bip32name='Bitcoin seed',):
        self.header.request_to = "coin"
        self.body.command = "xpub"
        self.body.parameter.bip32name = bip32name
        self.body.parameter.key = key

    def sign_message(self, message, path):
        # TODO: set request_to value to bitcoin 
        self.header.request_to = "bitcoin"
        self.body.command = "msg_sign"
        
        self.body.parameter.message = message
        self.body.parameter.path = path
            
    def bitcoin_transaction(self, request_to, version=1, locktime=0):
        self.header.request_to = request_to

        self.body.command = "transaction"

        self.body.parameter.version = version
        self.body.parameter.locktime = locktime

    def get_address(self, request_to, path):
        self.header.request_to = request_to
        self.body.command = "get_address"

        self.body.parameter.path = path
    
    def send_and_receive(self, dev):
        str = self.to_json()
        res_str = wami.send_and_receive(str, dev)
        json_res = json.loads(res_str)
        return json_res


