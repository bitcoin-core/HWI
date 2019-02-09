#
# client.py
#
# Implement the desktop side of our Coldcard USB protocol.
#
# If you would like to use a different EC/AES library, you may subclass
# and override these member functions:
#
#   - ec_mult, ec_setup, aes_setup, mitm_verify
#
import hid, sys, os, platform
from binascii import b2a_hex, a2b_hex
from hashlib import sha256
from .protocol import CCProtocolPacker, CCProtocolUnpacker, CCProtoError, MAX_MSG_LEN, MAX_BLK_LEN
from .utils import decode_xpub, get_pubkey_string

# unofficial, unpermissioned... USB numbers
COINKITE_VID = 0xd13e
CKCC_PID     = 0xcc10

# Unix domain socket used by the simulator
CKCC_SIMULATOR_PATH = '/tmp/ckcc-simulator.sock'

class ColdcardDevice:
    def __init__(self, sn=None, dev=None, encrypt=True):
        # Establish connection via USB (HID) or Unix Pipe
        self.is_simulator = False

        if not dev and sn and '/' in sn:
            if platform.system() == 'Windows':
                raise RuntimeError("Cannot connect to simulator. Is it running?")
            dev = UnixSimulatorPipe(sn)
            found = 'simulator'
            self.is_simulator = True

        if not dev:

            for info in hid.enumerate(COINKITE_VID, CKCC_PID):
                found = info['serial_number']

                if sn and sn != found:
                    continue

                # only one interface per device, so only one 'path'
                dev = hid.device(serial=found)
                assert dev, "failed to open: "+found
                dev.open_path(info['path'])

                break

            if not dev:
                raise KeyError("Could not find Coldcard!" 
                        if not sn else ('Cannot find CC with serial: '+sn))
        else:
            found = dev.get_serial_number_string()

        self.dev = dev
        self.serial = found

        # they will be defined after we've established a shared secret w/ device
        self.session_key = None
        self.encrypt_request = None
        self.decrypt_response = None
        self.master_xpub = None
        self.master_fingerprint = None

        self.resync()

        if encrypt:
            self.start_encryption()

    def close(self):
        # close underlying HID device
        if self.dev:
            self.dev.close()
            self.dev = None

    def resync(self):
        # flush anything already waiting on the EP
        while 1:
            junk = self.dev.read(64, timeout_ms=1)
            if not junk: break

        # write a special packet, that encodes zero-length data, and last packet in sequence
        # prefix with 0x00 for "report number"
        self.dev.write(b'\x00\x80' + (b'\xff'*63))

        # flush any response (perhaps error) waiting on the EP
        while 1:
            junk = self.dev.read(64, timeout_ms=1)
            if not junk: break

        # check the above all worked
        err = self.dev.error()
        if err != '':
            raise RuntimeError('hidapi: '+err)

        assert self.dev.get_serial_number_string() == self.serial

    def send_recv(self, msg, expect_errors=False, verbose=0, timeout=1000, encrypt=True):
        # first byte of each 64-byte packet encodes length or packet-offset
        assert 4 <= len(msg) <= MAX_MSG_LEN, "msg length: %d" % len(msg)

        if not self.encrypt_request:
            # disable encryption if not already enabled for this connection
            encrypt = False

        if encrypt:
            msg = self.encrypt_request(msg)

        left = len(msg)
        offset = 0
        while left > 0:
            # Note: first byte always zero (HID report number), 
            # [1] is framing header (length+flags)
            # [2:65] payload (63 bytes, perhaps including padding)
            here = min(63, left)
            buf = bytearray(65)
            buf[2:2+here] = msg[offset:offset+here]
            if here == left:
                # final one in sequence
                buf[1] = here | 0x80 | (0x40 if encrypt else 0x00)
            else:
                # more will be coming
                buf[1] = here

            assert len(buf) == 65

            if verbose:
                print("Tx [%2d]: %s (0x%x)" % (here, b2a_hex(buf[1:]), buf[1]))

            rv = self.dev.write(buf)
            assert rv == len(buf) == 65, repr(rv)

            offset += here
            left -= here

        # collect response, framed in the same manner
        resp = b''
        while 1:
            buf = self.dev.read(64, timeout_ms=(timeout or 0))

            assert buf, "timeout reading USB EP"

            # (trusting more than usual here)
            flag = buf[0]
            resp += bytes(buf[1:1+(flag & 0x3f)])
            if flag & 0x80:
                break

        if flag & 0x40:
            if verbose:
                print('Enc response: %s' % b2a_hex(resp))

            resp = self.decrypt_response(resp)

        try:
            if verbose:
                print("Rx [%2d]: %r" % (len(resp), b2a_hex(bytes(resp))))

            return CCProtocolUnpacker.decode(resp)
        except CCProtoError as e:
            if expect_errors: raise
            raise
        except:
            #print("Corrupt response: %r" % resp)
            raise

    def ec_setup(self):
        # Provides the ECSDA primatives in portable way.
        # Needed to do D-H session key aggreement and then AES.
        # - should be replaced in subclasses if you have other EC libraries
        # - curve is always secp256k1
        # - values are binary strings
        # - write whatever you want onto self.

        # - setup: return 65 of public key, and 16 bytes of AES IV
        # - second call: give the pubkey of far side, calculate the shared pt on curve
        from ecdsa.curves import SECP256k1
        from ecdsa import SigningKey

        self.my_key = SigningKey.generate(curve=SECP256k1, hashfunc=sha256)
        pubkey = self.my_key.get_verifying_key().to_string()
        assert len(pubkey) == 64

        #print("my pubkey = %s" % b2a_hex(pubkey))

        return pubkey

    def ec_mult(self, his_pubkey):
        # - second call: given the pubkey of far side, calculate the shared pt on curve
        # - creates session key based on that
        from ecdsa.curves import SECP256k1
        from ecdsa import VerifyingKey
        from ecdsa.util import number_to_string

        # Validate his pubkey a little: this call will check it's on the curve.
        assert len(his_pubkey) == 64
        his_pubkey = VerifyingKey.from_string(his_pubkey, curve=SECP256k1, hashfunc=sha256)

        #print("his pubkey = %s" % b2a_hex(his_pubkey.to_string()))

        # do the D-H thing
        pt = self.my_key.privkey.secret_multiplier * his_pubkey.pubkey.point

        # final key is sha256 of that point, serialized (64 bytes).
        order = SECP256k1.order
        kk = number_to_string(pt.x(), order) + number_to_string(pt.y(), order)

        del self.my_key

        return sha256(kk).digest()

    def aes_setup(self, session_key):
        # Load keys and define encrypt/decrypt functions
        # - for CTR mode, we have different counters in each direction, so need two instances
        # - count must start at zero, and increment in LSB for each block.
        import pyaes

        self.encrypt_request = pyaes.AESModeOfOperationCTR(session_key, pyaes.Counter(0)).decrypt
        self.decrypt_response = pyaes.AESModeOfOperationCTR(session_key, pyaes.Counter(0)).encrypt

    def start_encryption(self):
        # setup encryption on the link
        # - pick our own key pair, IV for AES
        # - send IV and pubkey to device
        # - it replies with own pubkey
        # - determine what the session key was/is

        pubkey = self.ec_setup()

        msg = CCProtocolPacker.encrypt_start(pubkey)

        his_pubkey, fingerprint, xpub = self.send_recv(msg, encrypt=False)

        self.session_key = self.ec_mult(his_pubkey)

        # capture some public details of remote side's master key
        # - these can be empty/0x0 when no secrets on device yet
        self.master_xpub = str(xpub, 'ascii')
        self.master_fingerprint = fingerprint

        #print('sess key = %s' % b2a_hex(self.session_key))
        self.aes_setup(self.session_key)

    def mitm_verify(self, sig, expected_xpub):
        # First try with Pycoin
        try:
            from pycoin.key.BIP32Node import BIP32Node
            from pycoin.contrib.msg_signing import verify_message
            from pycoin.encoding  import from_bytes_32
            from base64 import b64encode

            mk = BIP32Node.from_wallet_key(expected_xpub)
            return verify_message(mk, b64encode(sig), msg_hash=from_bytes_32(self.session_key))
        except ImportError:
            pass

        # If Pycoin is not available, do it using ecdsa
        from ecdsa import BadSignatureError, SECP256k1, VerifyingKey
        pubkey, chaincode = decode_xpub(expected_xpub)
        vk = VerifyingKey.from_string(get_pubkey_string(pubkey), curve=SECP256k1)
        try:
            ok = vk.verify_digest(sig[1:], self.session_key)
        except BadSignatureError:
            ok = False

        return ok

    def check_mitm(self, expected_xpub=None, sig=None):
        # Optional? verification against MiTM attack:
        # Using the master xpub, check a signature over the session public key, to
        # verify we talking directly to the real Coldcard (no active MitM between us).
        # - message is just the session key itself; no digests or prefixes
        # - no need for this unless concerned about *active* mitm on USB bus
        # - passive attackers (snoopers) will get nothing anyway, thanks to diffie-helman sauce
        # - unfortunately might be too slow to do everytime?

        xp = expected_xpub or self.master_xpub
        assert xp, "device doesn't have any secrets yet"
        assert self.session_key, "connection not yet in encrypted mode"

        # this request is delibrately slow on the device side
        if not sig:
            sig = self.send_recv(CCProtocolPacker.check_mitm(), timeout=5000)

        assert len(sig) == 65

        ok = self.mitm_verify(sig, xp)

        if ok != True:
            raise RuntimeError("Possible active MiTM attack in progress! Incorrect signature.")

    def upload_file(self, data, verify=True, blksize=1024):
        # upload a single file, up to 1MB? in size. Can check arrives ok.
        chk = sha256(data).digest()

        for i in range(0, len(data), blksize):
            here = data[i:i+blksize]
            pos = self.send_recv(CCProtocolPacker.upload(i, len(data), here))
            assert pos == i

        if verify:
            rb = self.send_recv(CCProtocolPacker.sha256())
            if rb != chk:
                raise RuntimeError('Checksum wrong during file upload')

        return len(data), chk

    def download_file(self, length, checksum, blksize=1024, file_number=1):
        # Download a single file, when you already know it's checksum. Will check arrives ok.
        data = b''
        chk = sha256()

        pos = 0
        while pos < length:
            here = self.send_recv(CCProtocolPacker.download(pos, min(blksize, length-pos), file_number))
            data += here
            chk.update(here)
            pos += len(here)
            assert len(here) > 0

        if chk.digest() != checksum:
            raise RuntimeError('Checksum wrong during file download')

        return data


class UnixSimulatorPipe:
    # Use a UNIX pipe to the simulator instead of a real USB connection.
    # - emulates the API of hidapi device object.

    def __init__(self, path):
        import socket, atexit
        self.pipe = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            self.pipe.connect(path)
        except FileNotFoundError:
            raise RuntimeError("Cannot connect to simulator. Is it running?")

        instance = 0
        while instance < 10:
            pn = '/tmp/ckcc-client-%d-%d.sock' % (os.getpid(), instance)
            try:
                self.pipe.bind(pn)     # just needs any name
                break
            except OSError:
                instance += 1
                continue

        self.pipe_name = pn
        atexit.register(self.close)

    def read(self, max_count, timeout_ms=None):
        import socket
        if not timeout_ms:
            self.pipe.settimeout(None)
        else:
            self.pipe.settimeout(timeout_ms / 1000.0)

        try:
            return self.pipe.recv(max_count)
        except socket.timeout:
            return None

    def write(self, buf):
        assert len(buf) == 65
        self.pipe.settimeout(10)
        rv = self.pipe.send(buf[1:])
        return 65 if rv == 64 else rv

    def error(self):
        return ''

    def close(self):
        self.pipe.close()
        try:
            os.unlink(self.pipe_name)
        except: pass

    def get_serial_number_string(self):
        return 'simulator'


# EOF
