MuSig2 With Bitcoin Core And HWI
================================

This walkthrough describes the HWI side of a 2-of-2 MuSig2 wallet where
cosigner A is a hardware wallet and cosigner B is a hot key in the same
Bitcoin Core wallet. It assumes a Bitcoin Core build with ``tr(musig(...))``
descriptors and external-signer descriptor registration support.

The hardware wallet can be a Ledger or a Coldcard Edge. MuSig2 uses Taproot,
which is supported by the Edge firmware but not by the standard Coldcard
firmware.

Get The Hardware Wallet Key
---------------------------

Use BIP87 account keys for MuSig2. For test networks the account path is
``m/87h/1h/0h``:

.. code-block:: bash

   ./hwi.py --chain test --fingerprint "$FP_A" getxpub "m/87h/1h/0h"

Build the key expression with origin information:

.. code-block:: bash

   COSIGNER_A_KEY="[${FP_A}/87h/1h/0h]tpub..."

Create the Core wallet with ``external_signer=true``,
``disable_private_keys=false``, and ``blank=true``. Add cosigner B's hot HD key
to that wallet, derive its BIP87 account xpub, and build a descriptor like:

.. code-block:: bash

   DESC_NO_CKSUM="tr(musig(${COSIGNER_A_KEY},${COSIGNER_B_KEY})/<0;1>/*)"

Register The Descriptor
-----------------------

Bitcoin Core's ``registerdescriptor`` RPC derives the ordinary multipath
descriptor from the wallet's active receive and change descriptors and passes
it to HWI. The equivalent direct HWI command is:

.. code-block:: bash

   ./hwi.py --chain test --fingerprint "$FP_A" registerdescriptor \
       MuSigTest "$DESC_NO_CKSUM"

The result contains an opaque serialized registration. Bitcoin Core stores it
unchanged and supplies it to HWI when displaying addresses or signing:

.. code-block:: json

   {"registration":"..."}

On Ledger, this registration includes data that authenticates the policy to
the device. Coldcard Edge instead stores the named policy on the device during
registration. In either case, applications should treat the serialized value
as opaque and reuse it unchanged. Confirm the policy on the hardware wallet
before accepting the registration.

Display A Registered Address
----------------------------

For registered descriptors, Bitcoin Core's ``walletdisplayaddress`` invokes
HWI with the stored registration instead of passing a single-address
descriptor:

.. code-block:: bash

   ./hwi.py --chain test --fingerprint "$FP_A" displayaddress \
       --registration "$REGISTRATION" \
       --index 0

Use ``--change`` to display the change branch for the same index. HWI returns
the address reported by the device:

.. code-block:: json

   {
     "address": "tb1p...",
     "index": 0,
     "change": false
   }

Coldcard Edge looks up the policy stored under its registration name, then
derives the requested branch and index. Ledger reconstructs the registered
policy from the serialized registration. Both devices display the resulting
address for confirmation.

Sign
----

Core invokes HWI's ``signtx`` with the same opaque registration:

.. code-block:: bash

   ./hwi.py --chain test --fingerprint "$FP_A" signtx "$PSBT" \
       --registration "$REGISTRATION"

MuSig2 signing has two rounds. When the coordinating wallet has another
cosigner locally, Bitcoin Core can run both rounds inside one ``send`` call:
first HWI yields the hardware wallet's public nonce, then Core adds the hot
cosigner's nonce and partial signature, and finally HWI yields the hardware
wallet's partial signature. The returned PSBT is then ready for finalization
by Core.

Coldcard Edge and Ledger both accept PSBT version 2, so HWI can combine their
independent updates without first converting the PSBT.
