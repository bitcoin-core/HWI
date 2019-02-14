#
# Details of our USB level protocol. Shared file between desktop and embedded.
#
# - first 4 bytes of all messages is the command code or response code
# - use <I and <H, never >H
#
from struct import pack, unpack_from
from .constants import *

class CCProtoError(RuntimeError):
    def __str__(self):
        return self.args[0]

class CCUserRefused(RuntimeError):
    def __str__(self):
        return 'You refused permission to do the operation'

class CCBusyError(RuntimeError):
    def __str__(self):
        return 'Coldcard is handling another request right now'

class CCProtocolPacker:
    # returns a lamba that will take correct args
    # and then give you a binary string to encode the
    # request

    @staticmethod
    def logout():
        return pack('4s', b'logo')

    @staticmethod
    def reboot():
        return pack('4s', b'rebo')

    @staticmethod
    def version():
        # returns a string, with newline separators
        return pack('4s', b'vers')

    @staticmethod
    def ping(msg):
        # returns whatever binary you give it
        return b'ping' + bytes(msg)

    @staticmethod
    def check_mitm():
        return b'mitm'

    @staticmethod
    def start_backup():
        # prompts user with password for encrytped backup
        return b'back'

    @staticmethod
    def encrypt_start(device_pubkey, version=0x1):
        assert len(device_pubkey) == 64, "want uncompressed 64-byte pubkey, no prefix byte"
        return pack('<4sI64s', b'ncry', version, device_pubkey)

    @staticmethod
    def upload(offset, total_size, data):
        # note: see MAX_MSG_LEN above
        assert len(data) <= MAX_MSG_LEN, 'badlen'
        return pack('<4sII', b'upld', offset, total_size) + data

    @staticmethod
    def download(offset, length, file_number=0):
        assert 0 <= file_number < 2
        return pack('<4sIII', b'dwld', offset, length, file_number)

    @staticmethod
    def sha256():
        return b'sha2'

    @staticmethod
    def sign_transaction(length, file_sha, finalize=False):
        # must have already uploaded binary, and give expected sha256
        assert len(file_sha) == 32
        return pack('<4sII32s', b'stxn', length, int(finalize), file_sha)

    @staticmethod
    def sign_message(raw_msg, subpath='m', addr_fmt=AF_CLASSIC):
        # only begins user interaction
        return pack('<4sIII', b'smsg', addr_fmt, len(subpath), len(raw_msg)) \
                    + subpath.encode('ascii') + raw_msg

    @staticmethod
    def get_signed_msg():
        # poll completion/results of message signing
        return b'smok'

    @staticmethod
    def get_backup_file():
        # poll completion/results of backup
        return b'bkok'

    @staticmethod
    def get_signed_txn():
        # poll completion/results of transaction signing
        return b'stok'

    @staticmethod
    def get_xpub(subpath='m'):
        # takes a string, like: m/44'/0'/23/23
        return b'xpub' + subpath.encode('ascii')

    @staticmethod
    def show_address(subpath, addr_fmt=AF_CLASSIC):
        # takes a string, like: m/44'/0'/23/23
        # shows on screen, no feedback from user expected
        return pack('<4sI', b'show', addr_fmt) + subpath.encode('ascii')

    @staticmethod
    def sim_keypress(key):
        # Simulator ONLY: pretend a key is pressed
        return b'XKEY' + key

    @staticmethod
    def bag_number(new_number=b''):
        # one time only: put into bag, or readback bag
        return b'bagi' + bytes(new_number)


class CCProtocolUnpacker:
    # Take a binary response, and turn it into a python object
    # - we support a number of signatures, and expand as needed
    # - some will be general-purpose, but others can be very specific to one command
    # - given full rx message to work from
    # - this is done after un-framing

    @classmethod
    def decode(cls, msg):
        assert len(msg) >= 4
        sign = str(msg[0:4], 'utf8', 'ignore')

        d = getattr(cls, sign, cls)
        if d is cls:
            raise CCProtoError('Unknown response signature: ' + repr(sign))

        return d(msg)
        

    # struct info for each response
    
    def okay(msg):
        # trivial response, w/ no content
        assert len(msg) == 4
        return None

    # low-level errors
    def fram(msg):
        raise CCProtoError("Framing Error", str(msg[4:], 'utf8'))
    def err_(msg):
        raise CCProtoError("Remote Error: " + str(msg[4:], 'utf8', 'ignore'), msg[4:])

    def refu(msg):
        # user didn't want to approve something
        raise CCUserRefused()

    def busy(msg):
        # user didn't want to approve something
        raise CCBusyError()

    def biny(msg):
        # binary string: length implied by msg framing
        return msg[4:]

    def int1(msg):
        return unpack_from('<I', msg, 4)[0]

    def int2(msg):
        return unpack_from('<2I', msg, 4)

    def int3(msg):
        return unpack_from('<3I', msg, 4)

    def mypb(msg):
        # response to "ncry" command: 
        # - the (uncompressed) pubkey of the Coldcard
        # - info about master key: xpub, fingerprint of that
        # - anti-MitM: remote xpub 
        # session key is SHA256(point on sec256pk1 in binary) via D-H
        dev_pubkey, fingerprint, xpub_len = unpack_from('64sII', msg, 4)
        xpub = msg[-xpub_len:] if xpub_len else b''
        return dev_pubkey, fingerprint, xpub

    def asci(msg):
        # hex/base58 string or other for-computers string, which isn't international
        return msg[4:].decode('ascii')

    def smrx(msg):
        # message signing result. application specific!
        # returns actual address used (text), and raw binary signature (65 bytes)
        aln = unpack_from('<I', msg, 4)[0]
        return msg[8:aln+8].decode('ascii'), msg[8+aln:]

    def strx(msg):
        # txn signing result, or other file operation. application specific!
        # returns length of resulting PSBT and it's sha256
        ln, sha = unpack_from('<I32s', msg, 4)
        return ln, sha

# EOF
