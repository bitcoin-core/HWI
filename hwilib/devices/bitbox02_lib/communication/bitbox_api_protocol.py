# Copyright 2019 Shift Cryptosecurity AG
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""BitBox02"""

from abc import ABC, abstractmethod
import os
import enum
import sys
import base64
import hashlib
import time
from typing import Callable, Optional, Dict, Tuple, Union, Sequence

import ecdsa
from noise.connection import NoiseConnection, Keypair
import semver

from .devices import parse_device_version, DeviceInfo

from .communication import TransportLayer
from .devices import BITBOX02MULTI, BITBOX02BTC, BITBOX02PLUS_MULTI, BITBOX02PLUS_BTC

try:
    from .generated import hww_pb2 as hww
    from .generated import system_pb2 as system
except ModuleNotFoundError:
    print("Run `make py` to generate the protobuf messages")
    sys.exit()


HWW_CMD = 0x80 + 0x40 + 0x01


class HwwRequestCode:
    # New request.
    REQ_NEW = b"\x00"
    # Poll an outstanding request for completion.
    REQ_RETRY = b"\x01"
    # Cancel any outstanding request.
    REQ_CANCEL = b"\x02"
    # INFO api call (used to be OP_INFO api call), graduated to the toplevel framing so it works
    # the same way for all firmware versions.
    REQ_INFO = b"i"


class HwwResponseCode:
    # Request finished, payload is valid.
    RSP_ACK = b"\x00"
    # Request is outstanding, retry later.
    RSP_NOT_READY = b"\x01"
    # Device is busy, request was dropped.
    RSP_BUSY = b"\x02"
    # Bad request.
    RSP_NACK = b"\x03"


ERR_GENERIC = 103
ERR_DUPLICATE_ENTRY = 107
ERR_USER_ABORT = 104

HARDENED = 0x80000000


# uncompressed secp256k1 pubkey serialization, hex-encoded.
ATTESTATION_PUBKEYS: Sequence[str] = [
    "04074ff1273b36c24e80fe3d59e0e897a81732d3f8e9cd07e17e9fc06319cd16b25cf74255674477b3ac9cbac2d12f0dc27a662681fcbc12955b0bccdcbbdcfd01",
    "044c53a84f41fa7301b378bb3c260fc9b2ff1cbea7a78181279a8566797a736f12cea25fa2b1c27a844392fe9b37547dc6fbd00a2676b816e7d2d3562be2a0cbbd",
    "04e9c8dc929796aac65af5084eb54dc1ee482d5e0b5c58e2c93f243c5b70b21523324bdb78d7395317da165ef1138826c3ca3c91ca95e6f490c340cf5508a4a3ec",
    "04c2fb05889b9dff5a9fb22a59ee1d16bfc2863f0400ddcb69566e2abe8a15fa0ba1240254ca45aa310d170e724e1310ce5f611cada76c12e3c24a926a390ca4be",
    "04c4e82d6d1b91e7853eba96a871ad31fc62620b826b0b8acf815c03de31b792a98e05bb34d3b9e0df1040eac485f03ff8bbbf7a857ef1cf2a49a60ac084efb88f",
    "040526f5b8348a8d55e7b1cac043ce98c55bbdb3311b4d1bb2d654281edf8aeb21f018fb027a6b08e4ddc62c919e648690722d00c6f54c668c9bd8224a1d82423a",
    "0422491e19766bd96a56e3f2f3926a6c57b89209ff47bd10e523b223ff65ab9af11c0a5f62c187514f2117ce772de90f9901ee122af78e69bbc4d29eec811be8ec",
    "049f1b7180014b6de60d41f16a3c0a37b20146585e4884960249d30f3cd68c74d04420d0cedef5719d6b1529b085ecd534fa6c1690be5eb1b3331bc57b5db224dc",
    "04adaa011a4ced11310728abb64f09636267ce0b05782da6d3eeaf987cec7c64f279ad55327184f9e5b4a1e53089b31bcc65032dad7205325f41ed3d9fdfba1f88",
    "044a70e663d7fe5fe0d4cbbb752883e35222b8d7d7bffdaa8d591995d1252528a4e9a3e4d5220d485021728b3cdad4fccc681a6ddeea8e2f7c55b4acde8d53573d",
    "04ef42d5c74254dd6afb36ec752068252ed6b6e231d019b0dfe32ee9ac2d5444471698e0ce7626e2f1f6266f42e343a20fd6fe2fd9f206e623c2eb6c1c9922465d",
    "04438a5d3a6262e631ad7a59ae9ffa0ee73b68957c4b3ad46d5747cae81beb15beafd1feed9c50fbff7f005ae649181c987649e1b251db74a052fef0b6e99a8064",
    "04d145a6ba3bf76d5db1b80dbeaef8c66a4eea215d1b6f7260a0b2b63fd30c3f4c3e92913a6ce272b36ff622fff64a67b5cf8ef5db645f403c2647d4c11d5f968e",
    "04458f68edde1d059ef2ccc970938cd44f012da4a8556f35f5a4e1df87313c7adfcd4f22e77345e5cc900eb6dd48af9bcb42bebe3163a79b3a3a3d32c359b5c06d",
    "0456bb82ddc84bd87d0d6dca27439dad6f0901518bdea2347c1c07e1a53a8480ec24b615af1d6cdb9344d8ea8b2103c9daa674742c260b1d2532acc07cb1b4fce6",
    "04f9d9ab547dce5b4d1c4778dae1990746e9e1f9a02475b46f88d8d4cc901db348988be3a5b8466a89f5a55e75416912d4b109eed86298577a718c0e3a023b0bf2",
    "040682f7a78d6290e6c59e9d1bde9cd665fa24232198385a10948906b473c59b160f95308ac8adf092276722d68f9db77d61df72587797ee8c3cf0df45ae19a0ba",
    "0432b2b5f54365847dcd1a9c96abb041a3d6483e93049fc3440b7b46ef8bac8d397d042dd48bb9928de3f2e343a670792fe25f65e5ffcbbf0121c4a0a061e55cd3",
    "043eef9f2af390dfb456800fc7673f1ac61baefa68bff84ccd36fdfe408f90205b865ddd2c6036ceb6260bd6e6b2f2b0a0ade9a60579f259bcb945ea5eced8bfe8",
    "04bc9b0fee1e5e088c77608e6ce16313a96a5b725de2c77fb3504e8c6ecf54ba278837f6ecdeb5a537d89d0a655cdaface33ef7786b949533ea8cec90694b15840",
    "046f8f4942d0ffea7078850917b850b96fac0d1010ff9ef1419e5e9a8fce94796ff1c451f64ec8e5fbb20bc1cb73fd5fdddf5c647883f3966a82ed3e816d8da862",
    "04995f9c5d5f539e53cd106837ca3eba50626df5dd5e54ce3146477c57cd5918c0b83b30f3e469c8ee7c741cd7c6833e78eeab710dfb96360ce464905fbda8179e",
    "049991c5db649d7cf37f0a1cae2b4f14461404e0286c0b86e3dd5462a18a3ec35f54e66865a8e88aab14f94cbd8778c3c79440c54e5eeb5f96ba097638017b71dc",
    "0433b669b2346c99824e81352a254ef4688349f41570f531e031a9c51e901aa0d74dc1206e0bd41929a75e44ee3e842c9d746f93172f5d9e3dd7a22e79d0fbad1c",
    "04d2b99da82c7da93db72b6e6ab52dad09bd71d661e6ff63f22170afb4599fd88456aa8f555d910c5d4cc5a8cffb38f0cd7ec514aeecf3af990dc3ea7ba9d0d1ff",
    "043be5abaf680e97f416a66538f0196f9ac8a2efc4f5ddc73ba43b6b3c261216b10f08b4c8c37a63dea0d2fa05240408f6d3de6d9f730af2c4e890fe1256d134aa",
    "04f9b88dcff16de9f4d0372e36dbf220cec95099041003ed4f3a894bc6ffd0e881ca45f3c5dd0518d14d98e7e377623f5c4d99f302ce482b0a1ca0c6f046f5d251",
    "04564c4238efbaca156d159ec945b80b7979dce14c4a59d380b1fc242d3aa3de0ad4ddae7262a11169819913e4346cb89b1ddc427d2192abd8f6c5a2c850768ba1",
    "0486fb44812e9284ac4843463021729f33da45f0b90e3947d642f84320fd1be68deb24989b48b0a8d5c2ce438693ec1405d2358198fa939ea1ecd52b0df1fbc498",
    "04a4b9b7a03abd093543b2d8dddddead13be13e7529ce0202b5b29a8ac52d0cfabb97bae52301a8a0e4853f3220e69dd2a0abfce526fdc087e7e0463e6495f739f",
    "04fb09aa6b917f136a221d299e4d021adbb309d4753f94fb502f4b6e87abeb475221180c3467762f8342a1edb55a871c016262c1a8526a025a9bb3035efbf1c566",
    "04f7b1dfff6f5b91432c6fdc0f79d13017b95d03d12e8b688ac446f89f9e5749d056ea2ea32d4f43cf12b174e2f7dbbd35c86d99891fd15512dddc7813ce710d6a",
    "04476ed4537511dd1f24588bfd74e3e34d0d4158d7042037abe6ad86e91beac3b29a4db33c3eeffeaf8e41c86996da2992a0a168bd7f8f6298a6f0c592046635dd",
    "04e6a3ba1a4024d7f7a666af76c880f3285bad6e945416b06ba66c6ad2c9ba0344315136d4d2a398c9142ec205f844b896e2eeb2060a3ad1108879f811040902b7",
    "04f6d29602c85fbc3af84f295face5b10e996520d19e8e3b95e71a56c30d6c868c38e11df16293c304ccb9cb6e0d4c7d9e7f5badd488e6747eaf88d0be221319fe",
    "04517ad3854bf3b9fa52ff703bd6d0fefc61406a7cd606cff270fc8ea1233366e5592321a8bb4dbbaca4df3a80ad68ef9de92e245aae898616d0ababad5f2449a6",
    "04e1d94a45345ff33512c63ed5a6bb2f3fb92cc1db15267389cad9e8ef70de3db522faad29ad06f2a73f174b12a23e49c272e673f28a710243bfa8adc2ffd12f1a",
    "045570fa35433648d7a6e98274629c3dc565e3211331802baa64087d12a63c53488071a619dd0313993d423a65a2175baba1abdcd5df7186ed247a9eaceb8b74fd",
    "0401fe456142c8fa3b15f7d381fc62b40dcc546d5786aaf5fd08d8b2963c90895096ce773dff54b41ef604192ba9dd48786319a4c53e22217200c20cf3fcd95d6b",
    "04c552738db26ef0e89bed1be8ade4951e7734579f5c49954373e78ae5e613235835e7835255eb92b64dba9d52db768895d8890e1f60f95522127cbfdf501581a8",
    "040366885c11552f8354a6d6d133c1d3a1d4486ac5b85d94733f583d494d39aa05f54bb0d47746bcc082ebdf7f317f33df32e517982a3e1454fbc4b776c012ce79",
    "04fb246edb986718ac4e892c336fd3100cd225f389806042d9fdbff1ac84be110ee1b9cfa38c4bd7c7334c8b8d21b7d07e00a1b9910b6b103b8b83cf4f27b352b4",
    "046003d369e24ce07356355c3bc0326856412b9d2259686e0f391b223305a7a3894b2cfe9285752865326d47fce223ea24d3c6a087fefd2a80f38041d6406da5c2",
    "044481ac1f9fd76dc8d87d4df88944fcc974c8ef4a4283610454eaf67393c38bcc21459132d90d115d208afbdf4bf77d3dede3e904804339a7fce5e57f0ab1bc0b",
    "04c7b2d16a898ba1233ff19a3bb1ce8c8956f2db8b42b0ed57bc1b1d249d1e2cb53a800a18050e44bb2d82d48066fc617dd81a0739dc71957a3daf6f22e30d5b39",
    "046d3e716eb3580f5335d9d3869ea048c1b4c065817716f2edd2dcb8cefbe9f6d53fe3afd76d43ee48c4b4467fee60685a0afe555ce2b65a2a6a96768f05601bc4",
    "044473a7c536402aa209b666acaa95f28379916cbaa6a2f4f03f544698e590e917678b102bfb08a8bb31a8d7ef4f82508373a42903d5bf4b267e4e0d285da81d75",
    "0451e34fa15a57dfa8c1bed92d965a8e9ad58531f79851f7aca792f3ae55e83daed5ff4b9552bd9b49eefb6f1aca173cde9b9469e7df3194a089b8f4d833305398",
    "0434aac7b381d143f4588e5018ec956d8dfcbca4b9e04d17e0c9abd96c5a88b562cc816c8ca24a0c50550df80e992801e2fc3427ae15ff5857083319686019d4b5",
    "047560b4430a1fa56ff42e47fd5f4063f39e993a7af0f04d13a75d601ca42508ba11c3245362763fb0c7847002d364a4d7913052131c11c1c7056330c12e9c29aa",
    "0408a651514bf9e992d297629be1f4c1ef7804760451bad13daf701fc3c662f2297fdd166cb8440c6d78527926d71664b1eb5a88ac5b75fd7a9aebfa30a2ac2db1",
    "04b6be971ec9f51de953e9689a9d7df828f45459f78cbfbc6f9bdab8a1d5f7bf6305991207c2f3fc48695f113936eac5599130b3bd4bf3f8ed125888c106bf6675",
    "04a7436fd434513ec3748e01dba2f1cc6406a945a0329cfd3e60fa04fc8196d21c83a8e34d688afb1a29f251ef29ea659849eac310c8bc38ec29edc23b40cd860e",
    "041e432d24bed03c5cfddb38155e2df8e42482294423c79a0341f0b86073d91cea71ffc58bacaf08c11511461e000ecd6db33170ee99e1aca8aff89f68b7c5db31",
    "045604b119b5d7ce91093a429c70a246842d9150390eaf5e98530fdd68ff0263051159d4baed1eacde5cce3064a061910348ae3e5dc88b9daef5417418b7fdb57d",
    "04aa59b2506202e2112e9bb794cfe43aace1c303559332869e04a151a2b2dc70d382b9b156cfd5a710ff476b5e4744439e7763e076f7dd834ef21900d949798f93",
    "0433f5b6c27f93489a98c3a109cae3da0ea86b93d75cf8871f3f78e9696b4045a7342ae38ac06359f710aa2c06a88821ac79672c2498fbec051e4f1525e8c9fae7",
    "047cbbe361c84de6b9c9c809b12a584354780b12aa89787673cfc2ca22d48bb0eb43a8aac781d333b8b91956be82840985cc90fd9ba8443589661b6aa308478ec6",
    "04768cdf5973c34f027abb68e86844eb981b3ddb5a5f11f8c079b04fe658afeccc8163cab7e97120ada6313a2c3007a948a1ea1b3d466106cf472a127974a971ce",
    "041bc1b519a2a67f14c91bc8052cc3d94a7a2824d742abb1be65c7d86085ed0b15c678ff508b01add8bc5f24295f4bfbfb0126c3bbb05ba0bb596062ba37f86c43",
    "04ec87da7c538369614ead4d3a3b359fa22468fac84a101623f2394eea10c8ab92b2f118951333a35311e11cffa2ecb9f7a9b9d5e1360efc636fc8b1be830c812b",
    "0487cb0069f2a43cd3c0be0d5e6164bb2a4d56db2bd962b25b7159bff04df286010b4e2c54982ee72f573093dede1ef7e7b337bd0a0181f270098cc3aeeb743b5a",
    "0487e18223782642f5605fbc2cab0cb3d78a35367da75bc3466aef5fce03375fb36bb24fe3653da9085fde2db75624a2283866f0d39b788ad9538a7795779cffdb",
    "04d3b453084456096bc30dd5ac28d6cbab06ca40424543fcc72f3becc198e4cb14728bbd52cc452eb7417729c0e5283277c3a17a5d2faa4e26d40880560734d19b",
    "048bf5abf82e6fd10f3516f0586c0cf091941fd17411fda4333bbe8675c97f6395b5cf4e0b6c32c21005a75e3c4c950abd0c34fb8c8722d47cf17b3fb71fafb3dd",
    "04e123e5639ae797edb389875534b223439c8b9400b32d799df3f2e3319c87a2bd527f0fbe7bed07186f78b591503abf453af5a0016984176764396ff47466616d",
    "049767f3b31fd667975831ff39964e38eda53a1a9bad3ae0807d29d3929ab379cfd27d4cb935f9c089829d6a51c783ca8e73b06cec195437ff58d80ed11879291b",
    "04e95dfd536e3ed24c55a76b55cbaf74fe1aceb8b632facfad1205d608cbd0282d77d45868ff49d31afc017ddb17ddb168535929faa0d23203da71546b9cbffef6",
    "04853455c8cf75da9e19c8ee89e73057efc9d4cd8008da4c08e2a5903deb712bef3c9d2bb0a853a3a2e2d7b10a8730254babd89639c237dc54ed649e4888fb5a8e",
    "04ee55299800e7739b5673029a1fb8d88976e81442c71e2b00ec19665c6578d33d960edd546c263614f4a4f1ddfee6c916022b85f5fe5a3f675d49b65d2899ed21",
    "04813b0d011e25ccea0a6c277d8032eaf7c4f055d89e8c4b53c1ada83554f41f0c864681c6b36112a9f47c6512e5033fbfac9c5caaad2bbca15baacbb092c07b6b",
    "04a800befd176bc49d7bba6d2ec9807ee72dea039377f7b027a4aab09ecc12a0fafe80394d346a8bf1a3a4a2c7742f9fdb8814a3d01d36d9e1dc90340fb6aa7a4e",
    "04fb15f204f7c47fa21bde4ff365938071ea402816048819bddedfca8264d020f0646ac5c0cf47df85794b4dd0a17b788bdd09d45582e8e6b9562a538769f2475d",
    "04bb7f11a51e91025681d9d329dbb1fd4ee4ea1eba6afb9c89022dd555ce442331bed3215001afe6d7bcdff5a8215a4e03f3b790a7e47182184a64ad13d0d425bf",
    "0466a3f9e7a7eb51ac22e46c972bcefc4ae1b3cfcbc4a532b4d7e51ec4bbb002ce8ed3af4a94fd6fb4fcfafa2252caf328d6a7ddf16edf76079619cbe4a24d89d5",
    "04b9f07bb4ede8aed008d65ba6baa5c8743239cc68bb7b3471e290eaaff71601453932f4f0321cb761cd8f2694ab16e405297c4ad9ede751310a09978de7b008be",
    "04949f487a41fa7d9b0368a89eb9e16c885b937b08412fe6565588837862537af37a2bc7c7009af2e921273a3133e858147509b415b2f49e9f8da1f69a49175814",
    "043548e330caaf10c4696f2a712fb5b2b69cd6316de64d4405c5f2f3d74bfa44b52a72a68a58856677d2b0fb20541766236432f0807d6c2e7e897a2d508fab8b80",
    "043aa576a8171b73b0f653532c0b0f6f49b893045b80f99e2214f207093b263f173d467c9c542e4a9cc2b0dd1f6dc46238084c329612b6a54c325fa00bbaadfc59",
    "04c982547397aab0b991bb0200336c810a7b7247fca76615012b1be8307d1763617409fcedb531d44ec83dfc25310f38a46ddb83112768dcb8e31ce34efde31d17",
    "04e45e1b9dfc8ca9a03c0126b6e07fadb38b2029b03f97ee2e3c9e7f2475aa961cbf6e8c9afbe6086b321bc225a3e44b3157185c6ebe21130cad1b346712ea1716",
    "04cd33b47eff77442eb5ab5f67869efc470c62097970b66d0d74fe7ca7fd70eb76b0adc7dbe6788ac5f42fe753750c9743e7f4d0d488963a01840c3a66aa038317",
    "043370ff050a99e431726ffee05cbc95225d096ecca1e534516e7c40e741943f6410eff44af418743a117d9b174451685a4eaad2a603645d49181369d54f81714a",
    "04cf6bd3c4bbeadfa939957aa3e0ed7ace55a030a85698a8876976a69f65e5843d9332200a242957473d3871a79e90d3e3e902cb749f999e9ba3533704bbf98c8d",
    "048b8ea186a6963aa7460cb144622daf28deecf132e38d5ec26d82464c27ebf93e16915eb953bdd1d29487be55be1a566e1a904955f5fc700e03e6bb2c55e9d30d",
    "04fb36dfe7949cbcad863b2f3c7c71b1bda01c954e8211103eca93153d44be5a4bc329df2543da1767263a2e8b6596a427a55ba735aff33249dcfec89d8fc8fb49",
    "04e8b5c26cae0c7719df23b88a80ab67cd418f929a932b4ee49a52049cce0968838c805942005006bb49431676a08b653440c857a6135b098c7f30d62162240d9d",
    "040867f9cd46ec9d0ff098303dca4d3297feee1d00b20da73d9cf2e6ba0a9e83f596a6ed882401cbfedb345c105a7c5f804d683a7714d0bae4aa7e027377fb0ca8",
    "04ceedd2c63a20ca20d9f84f83f1d27617722ecba021ef217fad0d1ad2f58b76006a32e8c7ea53f7657a5e1f6f4ea1a4a55081a3670bc7ed8fa2bde2cff465f12a",
    "049947a8d9573beb26f61f499da8435fbaa69e020145a5f1fc2efa1558db4747056cd36e299f92fbb9c98f3c7cbf04985fb7c09fac83be3bac2e4b3078129e5383",
    "04082483f5c4d03f74365fd66824bd02f7be1461c3559265de71f7702f16faccee4de0bc2e5ea8dc05461535b8ec476b31b1a447744b4e6d86b98f7a5eced629b9",
    "042b892b394e21f31de43e6aaa899d158458da5778287e50815358eb25dee9cd598e8d2071519437a9d0c253a2b6fcfbd6d9df32ed7c1df9df431c552e86caf125",
    "04ef30a5877fc417b7aa8ea21f1bf76160028a49a0cd43e524a3d9bc44496233b1c5773c0b58fec30d9652ca3ca538b20310749949d38e2d1644cd7e3809b33cc1",
    "04676f9723819f36518ad34e7b21d69f830b43fb966c0a3e8d1116bd3fa061fea5099882afbed5bf343ae4b95b4b0a13622c229ea0a555d2c478686096f568a647",
    "04abb4363bdfc5a91178ddc8a4cdc05d2e0616783594c53d5af2c2d34caa9b787e685434097fe4fff5af149acfaa9ab57a8060ef9d260c0bfba0eabdf9fad40c4b",
    "043220fddfbf5ae6bc63ff750f5f040a2a6e5cd8817a7450ae48653b6a1489fbaf86c9f42d6e31c4be25e2ed9fc1ca68114d01f001a36bde776498e70377d7327f",
    "0417a20da4ae93c3532afdef5f5a29124080eb98091214c9520dc60dd2c59d14a45561bc39247cba51edad190f34551309948100d5032afab9862b7ea0c60959c8",
    "04f378380a8aee1472449e94452ef366305abee4f797298e80398c0becc339ee9a1a3a4df34af6f10703d3816b377f0e3577ec977dc2158ab25e6aec18d1b92e45",
    "049a2763f23933d8cb5664f46a4b1c62cb55087d21a655a8cb271104a3b973c5e4b4c495a3bd834b672e98206141be46f3e823ba4e20b18b33de8352c544a9b5b9",
    "045f6f1d56a429497360a87958efb92a0a17c1921ce5b85db163aae22fc428129da8bcace8812a0e0b3f80935f4ea0c71f53c089df024906f09630cc4dcbae69d2",
    "04b397d8873b66eb2778281c0b1782e9c173de6021fe7d446de6d0aaddc3946fcd6f711c5e84d3548c28cd11bab548504ac1dd25c7960a0cfb1a09c45ecf88593b",
    "04c91160f925c710c3ba4befe7e6ab22692a633d5865e02dd49ad543ecc03d78a180b32bd1c10a1e37c0c2d8439eee0a9065113a3dc9639807306d360d3c86c639",
    "04a94517c095528cf6a7b65adbd1f6723b2840392a587630b8f1089b4a744fbf026f3f594c1b0ea7d1f4d70c7648ebde515aef4eeacacbcb46287e086baaabec42",
    "049df689158d44e061b5362fe40549fa6b2231e64d01c3fe43ccb8566bbf40178f501a9aa6a3c45dfbcb6a9212a19e68c12bf18788cab71b725d44129c5ae65d62",
    "040fead3b041184e24b1bb461c6accf1b35cf63c55bc68e2eea77060331bb14c680c8065cd8a4ee1d8af2f8f8b295c982570c9aa4995f00bf26aac3b04975aab83",
    "04fce43a145bfdb469d1e45134ff68254fe260efc9b58c3c6b367a9ec587b379c0547197b4f8865bab06cfa4f86fd94ebe31e921c76402428c94e15d448f8d0e0e",
    "04d65831029ae21c554c2ba442a55b92802a82840680b8b95cf4b939f7972f013883ba998139aae896aff41bb2eb73e1a2fb1bfaaf1958823b87a2b1830896981b",
    "048b86b0984fcc63434b12dc57f2c3896e7851cdb7ed907b18780ff75b47eff738355fc2b028dc2e16aedc63f3dd8d864fc450e141cc0f21b416676c693cf57ffd",
    "047870a256d9ac4e253c247dc71ad404c360f191cb40ecbb81004b6c8a80fbf610201bb57ded75874620a8aa1ea8cdcd6004e84242810fe4c03c0ac83dd42e570a",
    "04c6159283412ef6cfa74660565aa51d3fee4e7f852da62f9b33633f626cda4dfa8c39374940640b94fc075d1575545cc7685c969137b27e9d0d178feb2ca00623",
]


ATTESTATION_PUBKEYS_MAP: Dict[bytes, bytes] = {}
for pubkey_hex in ATTESTATION_PUBKEYS:
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    ATTESTATION_PUBKEYS_MAP[hashlib.sha256(pubkey_bytes).digest()] = pubkey_bytes


OP_ATTESTATION = b"a"
OP_UNLOCK = b"u"
OP_I_CAN_HAS_HANDSHAEK = b"h"
OP_HER_COMEZ_TEH_HANDSHAEK = b"H"
OP_I_CAN_HAS_PAIRIN_VERIFICASHUN = b"v"
OP_NOISE_MSG = b"n"

RESPONSE_SUCCESS = b"\x00"
RESPONSE_FAILURE = b"\x01"

MIN_SUPPORTED_BITBOX02_MULTI_FIRMWARE_VERSION = semver.VersionInfo(9, 0, 0)
MIN_SUPPORTED_BITBOX02_BTCONLY_FIRMWARE_VERSION = semver.VersionInfo(9, 0, 0)
MIN_UNSUPPORTED_BITBOX02_MULTI_FIRMWARE_VERSION = semver.VersionInfo(10, 0, 0)
MIN_UNSUPPORTED_BITBOX02_BTCONLY_FIRMWARE_VERSION = semver.VersionInfo(10, 0, 0)


class Platform(enum.Enum):
    """Available hardware platforms"""

    BITBOX02 = "bitbox02"
    BITBOX02PLUS = "bitbox02-plus"


class BitBox02Edition(enum.Enum):
    """Editions for the BitBox02 platform"""

    MULTI = "multi"
    BTCONLY = "btconly"


class Bitbox02Exception(Exception):
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__()

    def __str__(self) -> str:
        return f"error code: {self.code}, message: {self.message}"


class UserAbortException(Bitbox02Exception):
    pass


class AttestationException(Exception):
    pass


class FirmwareVersionOutdatedException(Exception):
    def __init__(self, version: semver.VersionInfo, required_version: semver.VersionInfo):
        super().__init__(
            "The BitBox02's firmware is not up to date. Device: {}, Required: {}".format(
                version, required_version
            )
        )


class LibraryVersionOutdatedException(Exception):
    def __init__(self, version: semver.VersionInfo):
        super().__init__(
            "The BitBox02's firmware version {} is too new for this app. Update the app".format(
                version
            )
        )


class UnsupportedException(Exception):
    def __init__(self, need_atleast: semver.VersionInfo):
        super().__init__(
            "This feature is supported from firmware version {}. Please upgrade your firmware.".format(
                need_atleast
            )
        )


class BitBoxNoiseConfig:
    """Stores Functions required setup a noise connection"""

    # pylint: disable=unused-argument
    def show_pairing(self, code: str, device_response: Callable[[], bool]) -> bool:
        """
        Returns True if the user confirms the pairing (both device and host).
        Returns False if the user rejects the pairing (either device or host).
        This function must call device_response() to invoke the pairing screen on the device.
        """
        return device_response()

    def attestation_check(self, result: bool) -> None:
        return

    def contains_device_static_pubkey(self, pubkey: bytes) -> bool:
        return False

    def add_device_static_pubkey(self, pubkey: bytes) -> None:
        pass

    def get_app_static_privkey(self) -> Optional[bytes]:
        return None

    def set_app_static_privkey(self, privkey: bytes) -> None:
        pass


class BitBoxProtocol(ABC):
    """
    Class for executing versioned BitBox operations
    (noise message transmissions, unlocks, etc).
    """

    def __init__(self, transport: TransportLayer):
        super().__init__()
        self._transport = transport
        self._noise: NoiseConnection = None

    def close(self) -> None:
        self._transport.close()

    def _raw_query(self, msg: bytes) -> bytes:
        cid = self._transport.generate_cid()
        return self._transport.query(msg, HWW_CMD, cid)

    def query(self, cmd: bytes, msg_data: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulates the given OP_* command and message data into a packet,
        and unpacks the response status code and data.
        """
        response = self._raw_query(cmd + msg_data)
        return response[:1], response[1:]

    @abstractmethod
    def _encode_noise_request(self, encrypted_msg: bytes) -> bytes:
        """Encapsulates an OP_NOISE_MSG message."""

    @abstractmethod
    def _decode_noise_response(self, encrypted_msg: bytes) -> Tuple[bytes, bytes]:
        """De-encapsulate an OP_NOISE_MSG response."""

    @abstractmethod
    def _handshake_query(self, req: bytes) -> Tuple[bytes, bytes]:
        """
        Executes a OP_HER_COMEZ_TEH_HANDSHAEK query with the given
        request data.
        Returns a pair (response status, response data).
        """

    def encrypted_query(self, msg: bytes) -> bytes:
        """
        Sends msg bytes and reads response bytes over an encrypted channel.
        """
        encrypted_msg = self._noise.encrypt(msg)
        encrypted_msg = self._encode_noise_request(encrypted_msg)

        response = self._raw_query(encrypted_msg)
        response_status, response = self._decode_noise_response(response)
        if response_status != RESPONSE_SUCCESS:
            raise Exception("Noise communication failed.")

        result = self._noise.decrypt(response)
        assert isinstance(result, bytes)
        return result

    # pylint: disable=too-many-branches
    def _create_noise_channel(self, noise_config: BitBoxNoiseConfig) -> NoiseConnection:
        if self._raw_query(OP_I_CAN_HAS_HANDSHAEK) != RESPONSE_SUCCESS:
            self.close()
            raise Exception("Couldn't kick off handshake")

        # init noise channel
        noise = NoiseConnection.from_name(b"Noise_XX_25519_ChaChaPoly_SHA256")
        noise.set_as_initiator()
        private_key = noise_config.get_app_static_privkey()
        if private_key is None:
            private_key = os.urandom(32)
            noise_config.set_app_static_privkey(private_key)
        noise.set_keypair_from_private_bytes(Keypair.STATIC, private_key)
        noise.set_prologue(b"Noise_XX_25519_ChaChaPoly_SHA256")
        noise.start_handshake()
        start_handshake_status, start_handshake_reply = self._handshake_query(noise.write_message())
        if start_handshake_status != RESPONSE_SUCCESS:
            self.close()
            raise Exception("Handshake process request failed.")
        noise.read_message(start_handshake_reply)
        remote_static_key = noise.noise_protocol.handshake_state.rs.public_bytes
        assert not noise.handshake_finished
        send_msg = noise.write_message()
        assert noise.handshake_finished
        pairing_code = base64.b32encode(noise.get_handshake_hash()).decode("ascii")
        handshake_finish_status, response = self._handshake_query(send_msg)
        if handshake_finish_status != RESPONSE_SUCCESS:
            self.close()
            raise Exception("Handshake conclusion failed.")

        # Check if we recognize the device's public key
        pairing_verification_required_by_host = True
        if noise_config.contains_device_static_pubkey(remote_static_key):
            pairing_verification_required_by_host = False

        pairing_verification_required_by_device = response == b"\x01"
        if pairing_verification_required_by_host or pairing_verification_required_by_device:

            def get_device_response() -> bool:
                device_response = self._raw_query(OP_I_CAN_HAS_PAIRIN_VERIFICASHUN)
                if device_response == RESPONSE_SUCCESS:
                    return True
                if device_response == RESPONSE_FAILURE:
                    return False
                raise Exception(f"Unexpected pairing response: f{repr(device_response)}")

            client_response_success = noise_config.show_pairing(
                "{} {}\n{} {}".format(
                    pairing_code[:5], pairing_code[5:10], pairing_code[10:15], pairing_code[15:20]
                ),
                get_device_response,
            )
            if not client_response_success:
                self.close()
                raise Exception("pairing rejected by the user")

            noise_config.add_device_static_pubkey(remote_static_key)
        return noise

    def noise_connect(self, noise_config: BitBoxNoiseConfig) -> None:
        self._noise = self._create_noise_channel(noise_config)

    @abstractmethod
    def unlock_query(self) -> None:
        """
        Executes an unlock query.
        Returns the bytes containing the response status.
        """

    @abstractmethod
    def cancel_outstanding_request(self) -> None:
        """
        Aborts/force close the outstanding request on the device.
        """


class BitBoxProtocolV1(BitBoxProtocol):
    """BitBox Protocol from firmware V1.0.0 onwards."""

    def unlock_query(self) -> None:
        raise NotImplementedError("unlock_query is not supported in BitBox protocol V1")

    def _encode_noise_request(self, encrypted_msg: bytes) -> bytes:
        return encrypted_msg

    def _decode_noise_response(self, encrypted_msg: bytes) -> Tuple[bytes, bytes]:
        """
        Until V7 of the protocol, we don't encapsulate OP_NOISE_MSG responses.
        Let's assume that if a response is empty, that means it
        contains an error.
        """
        if len(encrypted_msg) == 0:
            return RESPONSE_FAILURE, b""
        return RESPONSE_SUCCESS, encrypted_msg

    def _handshake_query(self, req: bytes) -> Tuple[bytes, bytes]:
        """
        V1-6 of the BB noise protocol doesn't encapsulate handshake requests, and don't
        send back a status code in the response.
        """
        noise_result = self._raw_query(req)
        return RESPONSE_SUCCESS, noise_result

    def cancel_outstanding_request(self) -> None:
        raise RuntimeError("cancel_outstanding_request should never be called here.")


class BitBoxProtocolV2(BitBoxProtocolV1):
    """BitBox Protocol from firmware V2.0.0 onwards."""

    def unlock_query(self) -> None:
        unlock_data = self._raw_query(OP_UNLOCK)
        if len(unlock_data) != 0:
            raise ValueError("OP_UNLOCK (V2) replied with wrong length.")


class BitBoxProtocolV3(BitBoxProtocolV2):
    """BitBox Protocol from firmware V3.0.0 onwards."""

    def unlock_query(self) -> None:
        unlock_result, unlock_data = self.query(OP_UNLOCK, b"")
        if len(unlock_data) != 0:
            raise ValueError("OP_UNLOCK (V3) replied with wrong length.")
        if unlock_result == RESPONSE_FAILURE:
            self.close()
            raise Exception("Unlock process aborted")


class BitBoxProtocolV4(BitBoxProtocolV3):
    """BitBox Protocol from firmware V4.0.0 onwards."""

    def _encode_noise_request(self, encrypted_msg: bytes) -> bytes:
        return OP_NOISE_MSG + encrypted_msg


class BitBoxProtocolV7(BitBoxProtocolV4):
    """Noise Protocol from firmware V7.0.0 onwards."""

    def __init__(self, transport: TransportLayer):
        super().__init__(transport)
        self.cancel_requested = False

    def _handshake_query(self, req: bytes) -> Tuple[bytes, bytes]:
        return self.query(OP_HER_COMEZ_TEH_HANDSHAEK, req)

    def _decode_noise_response(self, encrypted_msg: bytes) -> Tuple[bytes, bytes]:
        return encrypted_msg[:1], encrypted_msg[1:]

    def _raw_query(self, msg: bytes) -> bytes:
        """
        Starting with v7.0.0, HWW messages are encapsulated
        into an arbitration layer. The device can respond with
        RSP_NOT_READY to indicate that we should poll it later.
        """
        cid = self._transport.generate_cid()
        status = None
        payload: bytes
        while True:
            response = self._transport.query(HwwRequestCode.REQ_NEW + msg, HWW_CMD, cid)
            assert len(response) != 0, "Unexpected response of length 0 from HWW stack."
            status, payload = response[:1], response[1:]
            if status == HwwResponseCode.RSP_BUSY:
                assert (
                    len(payload) == 0
                ), "Unexpected payload of length {} with RSP_BUSY response.".format(len(payload))
                time.sleep(1)
            else:
                # We've successfully initiated our request.
                break

        if status in [HwwResponseCode.RSP_NACK]:
            # We should never receive a NACK unless some internal error occurs.
            raise Exception("Unexpected NACK response from HWW stack.")

        # The message has been sent. If we have a retry, poll the device until we're ready.
        self.cancel_requested = False
        while status == HwwResponseCode.RSP_NOT_READY:
            assert (
                len(payload) == 0
            ), "Unexpected payload of length {} with RSP_NOT_READY response.".format(len(payload))
            time.sleep(0.2)
            to_send = (
                HwwRequestCode.REQ_CANCEL if self.cancel_requested else HwwRequestCode.REQ_RETRY
            )
            response = self._transport.query(to_send, HWW_CMD, cid)
            assert len(response) != 0, "Unexpected response of length 0 from HWW stack."
            status, payload = response[:1], response[1:]
            if status not in [HwwResponseCode.RSP_NOT_READY, HwwResponseCode.RSP_ACK]:
                # We should never receive a NACK unless some internal error occurs.
                raise Exception(
                    "Unexpected response from HWW stack during retry ({}).".format(repr(status))
                )
        return payload

    def cancel_outstanding_request(self) -> None:
        self.cancel_requested = True


class BitBoxCommonAPI:
    """Class to communicate with a BitBox device"""

    # pylint: disable=too-many-public-methods,too-many-arguments
    def __init__(
        self,
        transport: TransportLayer,
        device_info: Optional[DeviceInfo],
        noise_config: BitBoxNoiseConfig,
    ):
        """
        Can raise LibraryVersionOutdatedException. check_min_version() should be called following
        the instantiation.
        If device_info is None, it is infered using the OP_INFO API call, available since
        firmware version v5.0.0.
        """
        self.debug = False

        if device_info is not None:
            version = device_info["serial_number"]
            if device_info["product_string"] in (BITBOX02MULTI, BITBOX02PLUS_MULTI):
                edition = BitBox02Edition.MULTI
            elif device_info["product_string"] in (BITBOX02BTC, BITBOX02PLUS_BTC):
                edition = BitBox02Edition.BTCONLY
            else:
                raise Exception("Invalid product string")
        else:
            version, _, edition, _, _ = self.get_info(transport)

        self.edition = edition
        try:
            self.version = parse_device_version(version)
        except:
            transport.close()
            raise

        # Delete the prelease part, as it messes with the comparison (e.g. 3.0.0-pre < 3.0.0 is
        # True, but the 3.0.0-pre has already the same API breaking changes like 3.0.0...).
        self.version = self.version.replace(prerelease=None)

        # raises exceptions if the library is out of date
        self._check_max_version()

        self._bitbox_protocol: BitBoxProtocol
        if self.version >= semver.VersionInfo(7, 0, 0):
            self._bitbox_protocol = BitBoxProtocolV7(transport)
        elif self.version >= semver.VersionInfo(4, 0, 0):
            self._bitbox_protocol = BitBoxProtocolV4(transport)
        elif self.version >= semver.VersionInfo(3, 0, 0):
            self._bitbox_protocol = BitBoxProtocolV3(transport)
        elif self.version >= semver.VersionInfo(2, 0, 0):
            self._bitbox_protocol = BitBoxProtocolV2(transport)
        else:
            self._bitbox_protocol = BitBoxProtocolV1(transport)

        if self.version >= semver.VersionInfo(2, 0, 0):
            noise_config.attestation_check(self._perform_attestation())
            self._bitbox_protocol.unlock_query()

        self._bitbox_protocol.noise_connect(noise_config)

    # pylint: disable=too-many-return-statements
    def _perform_attestation(self) -> bool:
        """Sends a random challenge and verifies that the response can be verified with
        Shift's root attestation pubkeys. Returns True if the verification is successful."""

        challenge = os.urandom(32)
        response_status, response = self._bitbox_protocol.query(OP_ATTESTATION, challenge)
        if response_status != RESPONSE_SUCCESS:
            return False

        # parse data
        bootloader_hash, response = response[:32], response[32:]
        device_pubkey_bytes, response = response[:64], response[64:]
        certificate, response = response[:64], response[64:]
        root_pubkey_identifier, response = response[:32], response[32:]
        challenge_signature, response = response[:64], response[64:]

        # check attestation
        if root_pubkey_identifier not in ATTESTATION_PUBKEYS_MAP:
            # root pubkey could not be identified.
            return False

        root_pubkey_bytes_uncompressed = ATTESTATION_PUBKEYS_MAP[root_pubkey_identifier]
        root_pubkey = ecdsa.VerifyingKey.from_string(
            root_pubkey_bytes_uncompressed[1:], ecdsa.curves.SECP256k1
        )

        device_pubkey = ecdsa.VerifyingKey.from_string(device_pubkey_bytes, ecdsa.curves.NIST256p)

        try:
            # Verify certificate
            if not root_pubkey.verify(
                certificate, bootloader_hash + device_pubkey_bytes, hashfunc=hashlib.sha256
            ):
                return False

            # Verify challenge
            if not device_pubkey.verify(challenge_signature, challenge, hashfunc=hashlib.sha256):
                return False
        except ecdsa.BadSignatureError:
            return False
        return True

    def _msg_query(
        self, request: hww.Request, expected_response: Optional[str] = None
    ) -> hww.Response:
        """
        Sends protobuf msg and retrieves protobuf response over an encrypted
        channel.
        """
        # pylint: disable=no-member
        if self.debug:
            print(request)
        response_bytes = self._bitbox_protocol.encrypted_query(request.SerializeToString())
        response = hww.Response()
        response.ParseFromString(response_bytes)
        if response.WhichOneof("response") == "error":
            if response.error.code == ERR_USER_ABORT:
                raise UserAbortException(response.error.code, response.error.message)
            raise Bitbox02Exception(response.error.code, response.error.message)
        if expected_response is not None and response.WhichOneof("response") != expected_response:
            raise Exception(
                "Unexpected response: {}, expected: {}".format(
                    response.WhichOneof("response"), expected_response
                )
            )
        if self.debug:
            print(response)
        return response

    def reboot(
        self, purpose: "system.RebootRequest.Purpose.V" = system.RebootRequest.Purpose.UPGRADE
    ) -> bool:
        """
        Sends the reboot request. If the user confirms the request on the device, the device reboots
        into the bootloader.
        The purpose defines what confirmation message the user gets to see on the device.
        """
        # pylint: disable=no-member
        request = hww.Request()
        request.reboot.CopyFrom(system.RebootRequest(purpose=purpose))
        try:
            self._msg_query(request)
        except OSError:
            # In case of reboot we can't read the response.
            return True
        except Bitbox02Exception:
            return False
        return True

    @staticmethod
    def get_info(
        transport: TransportLayer,
    ) -> Tuple[str, Platform, Union[BitBox02Edition], bool, Optional[bool]]:
        """
        Returns (version, platform, edition, unlocked, initialized).
        This is useful to get the version of the firmware or the device unlocked/initialized status
        when a usb descriptor is not available (via BitBoxBridge, etc.). The initialized status is
        supported from firmware v9.20.0 (it is None if not supported).
        This call does not use a versioned BitBoxProtocol for communication, as the version is not
        available (this call is used to get the version), so it must work for all firmware versions.
        """
        response = transport.query(HwwRequestCode.REQ_INFO, HWW_CMD, transport.generate_cid())

        version_str_len, response = int(response[0]), response[1:]
        version, response = response[:version_str_len], response[version_str_len:]
        version_str = version.rstrip(b"\0").decode("ascii")

        platform_byte, response = response[0], response[1:]
        platform = {0x00: Platform.BITBOX02, 0x02: Platform.BITBOX02PLUS}[platform_byte]

        edition_byte, response = response[0], response[1:]
        edition: Union[BitBox02Edition]
        if platform in (Platform.BITBOX02, Platform.BITBOX02PLUS):
            edition = {0x00: BitBox02Edition.MULTI, 0x01: BitBox02Edition.BTCONLY}[edition_byte]
        else:
            raise Exception("Unknown platform: {}".format(platform))

        unlocked_byte, response = response[0], response[1:]
        unlocked = {0x00: False, 0x01: True}[unlocked_byte]

        initialized = None
        if parse_device_version(version_str) >= semver.VersionInfo(9, 20, 0):
            initialized_byte = response[0]
            initialized = {0x00: False, 0x01: True}[initialized_byte]
        return (version_str, platform, edition, unlocked, initialized)

    def check_min_version(self) -> None:
        """
        Raises FirmwareVersionOutdatedException if the device has an older firmware version than
        required and the minimum required version.
        """
        if self.edition == BitBox02Edition.MULTI:
            if self.version < MIN_SUPPORTED_BITBOX02_MULTI_FIRMWARE_VERSION:
                raise FirmwareVersionOutdatedException(
                    self.version, MIN_SUPPORTED_BITBOX02_MULTI_FIRMWARE_VERSION
                )
        elif self.edition == BitBox02Edition.BTCONLY:
            if self.version < MIN_SUPPORTED_BITBOX02_BTCONLY_FIRMWARE_VERSION:
                raise FirmwareVersionOutdatedException(
                    self.version, MIN_SUPPORTED_BITBOX02_BTCONLY_FIRMWARE_VERSION
                )

    def cancel_outstanding_request(self) -> None:
        self._bitbox_protocol.cancel_outstanding_request()

    def _check_max_version(self) -> None:
        """
        Raises LibraryVersionOutdatedException if the device has an firmware which is too new
        (major version increased).
        """
        if self.edition == BitBox02Edition.MULTI:
            if self.version >= MIN_UNSUPPORTED_BITBOX02_MULTI_FIRMWARE_VERSION:
                raise LibraryVersionOutdatedException(self.version)
        elif self.edition == BitBox02Edition.BTCONLY:
            if self.version >= MIN_UNSUPPORTED_BITBOX02_BTCONLY_FIRMWARE_VERSION:
                raise LibraryVersionOutdatedException(self.version)

    def _require_atleast(self, version: semver.VersionInfo) -> None:
        """
        Raises UnsupportedException if the current firmware version is not at least the required version.
        """
        if self.version < version:
            raise UnsupportedException(version)

    def close(self) -> None:
        self._bitbox_protocol.close()
