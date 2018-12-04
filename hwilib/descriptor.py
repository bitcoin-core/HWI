import re

class Descriptor:
    def __init__(self, origin_fingerprint, origin_path, base_key, path_suffix, testnet, sh_wpkh, wpkh, is_request):
        self.origin_fingerprint = origin_fingerprint
        self.origin_path = origin_path
        self.path_suffix = path_suffix
        self.base_key = base_key
        self.testnet = testnet
        self.sh_wpkh = sh_wpkh
        self.wpkh = wpkh
        self.m_path = None
        self.is_request = is_request

        if origin_path:
            self.m_path = "m" + origin_path + (path_suffix or "")

            if is_request:
                self.m_path_base = "m" + origin_path

    @classmethod
    def parse(cls, desc, testnet = False):
        sh_wpkh = None
        wpkh = None
        origin_fingerprint = None
        origin_path = None
        base_key_and_path_match = None
        base_key = None
        is_request = False

        if desc.startswith("sh(wpkh("):
            sh_wpkh = True
        elif desc.startswith("wpkh("):
            wpkh = True

        origin_match = re.search(r"\[(.*)\]", desc)
        if origin_match:
            origin = origin_match.group(1)
            match = re.search(r"^([0-9a-fA-F]{8})(\/.*)", origin)
            if  match:
              origin_fingerprint = match.group(1)
              origin_path = match.group(2)
              # Replace h with '
              origin_path = origin_path.replace('h', '\'')

            base_key_and_path_match = re.search(r"\[.*\](\w+)([\/\)][\d'\/\*]*)", desc)
        else:
            base_key_and_path_match = re.search(r"\((\w+)([\/\)][\d'\/\*]*)", desc)

        if base_key_and_path_match:
            base_key = base_key_and_path_match.group(1)
            path_suffix = base_key_and_path_match.group(2)
            if path_suffix == ")":
                path_suffix = None
        else:
            if origin_match == None:
                return None
            else:
                # Check if this is a descriptor request, which does not contain
                # a key, must contain an origin and the last path element must be * or *'
                request_match = re.search(r"\[.*\]([\/\)][\d'\/\*]*\*[']?)", desc)
                if request_match is None:
                    return None

                path_suffix = request_match.group(1)
                is_request = True

        return cls(origin_fingerprint, origin_path, base_key, path_suffix, testnet, sh_wpkh, wpkh, is_request)


    def serialize(self):
        descriptor_open = 'pkh('
        descriptor_close = ')'
        origin = ''
        path_suffix = ''

        if self.wpkh == True:
            descriptor_open = 'wpkh('
        elif self.sh_wpkh == True:
            descriptor_open = 'sh(wpkh('
            descriptor_close = '))'

        if self.origin_fingerprint and self.origin_path:
            origin = '[' + self.origin_fingerprint + self.origin_path + ']'

        if self.path_suffix:
            path_suffix = self.path_suffix

        return descriptor_open + origin + self.base_key + path_suffix + descriptor_close
