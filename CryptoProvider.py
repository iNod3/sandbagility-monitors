from Sandbagility.Monitor import UserlandGenericMonitor as UserlandMonitor

class CryptDecodeObjectMonitor(UserlandMonitor):

    _NAME = 'DecodeObject'
    _DEPENDENCIES = ['crypt32.dll']

    def __install__(self, NotifyLoadImage=None):

        self.helper.logger.debug('Installed %s' % self.Name)
        self.SetBreakpoint('crypt32!CryptDecodeObjectEx')

class CryptoProviderMonitor(UserlandMonitor):

    _NAME = 'Crypto'
    _DEPENDENCIES = ['advapi32.dll']

    def __install__(self, NotifyLoadImage=None):

        self.SetBreakpoint('advapi32!CryptAcquireContextAStub')
        self.SetBreakpoint('advapi32!CryptAcquireContextWStub')
        self.SetBreakpoint('advapi32!CryptGenKeyStub')
        self.SetBreakpoint('advapi32!CryptCreateHashStub')
        self.SetBreakpoint('advapi32!CryptGetHashParamStub')
        self.SetBreakpoint('advapi32!CryptDecryptStub')
        self.SetBreakpoint('advapi32!CryptEncryptStub')
        self.SetBreakpoint('advapi32!CryptImportKeyStub')
        self.SetBreakpoint('advapi32!CryptExportKeyStub')

        return True

    def __notify_load_image__(self, Process, LoadImage):
        return self.__install__(NotifyLoadImage=LoadImage)

    def LookupAlgIdToString(self, id):
        ALG_ID_TO_STRING = {
            0x00006603: 'CALG_3DES',
            0x00006609: 'CALG_3DES_112',
            0x00006611: 'CALG_AES',
            0x0000660e: 'CALG_AES_128',
            0x0000660f: 'CALG_AES_192',
            0x00006610: 'CALG_AES_256',
            0x0000aa03: 'CALG_AGREEDKEY_ANY',
            0x0000660c: 'CALG_CYLINK_MEK',
            0x00006601: 'CALG_DES',
            0x00006604: 'CALG_DESX',
            0x0000aa02: 'CALG_DH_EPHEM',
            0x0000aa01: 'CALG_DH_SF',
            0x00002200: 'CALG_DSS_SIGN',
            0x0000aa05: 'CALG_ECDH',
            0x00002203: 'CALG_ECDSA',
            0x0000a001: 'CALG_ECMQV',
            0x0000800b: 'CALG_HASH_REPLACE_OWF',
            0x0000a003: 'CALG_HUGHES_MD5',
            0x00008009: 'CALG_HMAC',
            0x0000aa04: 'CALG_KEA_KEYX',
            0x00008005: 'CALG_MAC',
            0x00008001: 'CALG_MD2',
            0x00008002: 'CALG_MD4',
            0x00008003: 'CALG_MD5',
            0x00002000: 'CALG_NO_SIGN',
            0xffffffff: 'CALG_OID_INFO_CNG_ONLY',
            0xfffffffe: 'CALG_OID_INFO_PARAMETERS',
            0x00004c04: 'CALG_PCT1_MASTER',
            0x00006602: 'CALG_RC2',
            0x00006801: 'CALG_RC4',
            0x0000660d: 'CALG_RC5',
            0x0000a400: 'CALG_RSA_KEYX',
            0x00002400: 'CALG_RSA_SIGN',
            0x00004c07: 'CALG_SCHANNEL_ENC_KEY',
            0x00004c03: 'CALG_SCHANNEL_MAC_KEY',
            0x00004c02: 'CALG_SCHANNEL_MASTER_HASH',
            0x00006802: 'CALG_SEAL',
            0x00008004: 'CALG_SHA1',
            0x0000800c: 'CALG_SHA_256',
            0x0000800d: 'CALG_SHA_384',
            0x0000800e: 'CALG_SHA_512',
            0x0000660a: 'CALG_SKIPJACK',
            0x00004c05: 'CALG_SSL2_MASTER',
            0x00004c01: 'CALG_SSL3_MASTER',
            0x00008008: 'CALG_SSL3_SHAMD5',
            0x0000660b: 'CALG_TEK',
            0x00004c06: 'CALG_TLS1_MASTER',
            0x0000800a: 'CALG_TLS1PRF',
        }
        if id in ALG_ID_TO_STRING: return ALG_ID_TO_STRING[id]
        return id

    def LookupKeyTypeToString(self, wKeyType):

        KEY_TYPE_TO_STRING = {
            0x00000001: 'CRYPT_EXPORTABLE',
            0x00000002: 'CRYPT_USER_PROTECTED',
            0x00000004: 'CRYPT_CREATE_SALT',
            0x00000008: 'CRYPT_UPDATE_KEY',
            0x00000010: 'CRYPT_NO_SALT',
            0x00000040: 'CRYPT_PREGEN',
            0x00000010: 'CRYPT_RECIPIENT',
            0x00000040: 'CRYPT_INITIATOR',
            0x00000080: 'CRYPT_ONLINE',
            0x00000100: 'CRYPT_SF',
            0x00000200: 'CRYPT_CREATE_IV',
            0x00000400: 'CRYPT_KEK',
            0x00000800: 'CRYPT_DATA_KEY',
            0x00001000: 'CRYPT_VOLATILE',
            0x00002000: 'CRYPT_SGCKEY',
            0x00100000: 'CRYPT_USER_PROTECTED_STRONG',
            0x00004000: 'CRYPT_ARCHIVABLE',
            0x00008000: 'CRYPT_FORCE_KEY_PROTECTION_HIGH',
        }

        Result = []

        for Key, Value in KEY_TYPE_TO_STRING.items():
            if wKeyType & Key: Result.append(Value)

        return '|'.join(Result)

    def LookupProviderTypeToString(self, dwProvType):
        PROV_TYPE_TO_STRING = {
            1: 'PROV_RSA_FULL',
            2: 'PROV_RSA_SIG',
            3: 'PROV_DSS',
            4: 'PROV_FORTEZZA',
            5: 'PROV_MS_EXCHANGE',
            6: 'PROV_SSL',
            12: 'PROV_RSA_SCHANNEL',
            13: 'PROV_DSS_DH',
            14: 'PROV_EC_ECDSA_SIG',
            15: 'PROV_EC_ECNRA_SIG',
            16: 'PROV_EC_ECDSA_FULL',
            17: 'PROV_EC_ECNRA_FULL',
            18: 'PROV_DH_SCHANNEL',
            20: 'PROV_SPYRUS_LYNKS',
            21: 'PROV_RNG',
            22: 'PROV_INTEL_SEC',
            23: 'PROV_REPLACE_OWF',
            24: 'PROV_RSA_AES',
        }
        if dwProvType in PROV_TYPE_TO_STRING: return PROV_TYPE_TO_STRING[dwProvType]
        return dwProvType

    def LookupImportKeyFlagsToString(self, dwFlags):
        HP_TO_STRING = {
            0x00000001: 'CRYPT_EXPORTABLE',
            0x00000002: 'CRYPT_USER_PROTECTED',
            0x00000004: 'CRYPT_CREATE_SALT',
            0x00000008: 'CRYPT_UPDATE_KEY',
            0x00000010: 'CRYPT_NO_SALT',
            0x00000040: 'CRYPT_PREGEN',
            0x00000010: 'CRYPT_RECIPIENT',
            0x00000040: 'CRYPT_INITIATOR',
            0x00000080: 'CRYPT_ONLINE',
            0x00000100: 'CRYPT_SF',
            0x00000200: 'CRYPT_CREATE_IV',
            0x00000400: 'CRYPT_KEK',
            0x00000800: 'CRYPT_DATA_KEY',
            0x00001000: 'CRYPT_VOLATILE',
            0x00002000: 'CRYPT_SGCKEY',
            0x00100000: 'CRYPT_USER_PROTECTED_STRONG',
            0x00004000: 'CRYPT_ARCHIVABLE',
            0x00008000: 'CRYPT_FORCE_KEY_PROTECTION_HIGH',
        }
        if dwFlags in HP_TO_STRING: return HP_TO_STRING[dwFlags]
        return dwFlags

    def LookupHashParamToString(self, dwFlags):
        HP_TO_STRING = {
            0x0001: 'HP_ALGID',
            0x0002: 'HP_HASHVAL',
            0x0004: 'HP_HASHSIZE',
            0x0005: 'HP_HMAC_INFO',
            0x0006: 'HP_TLS1PRF_LABEL',
            0x0007: 'HP_TLS1PRF_SEED',
        }
        if dwFlags in HP_TO_STRING: return HP_TO_STRING[dwFlags]
        return dwFlags

    def LookupPublicKeyType(self, dwBlobType):

        BLOBHEADER_TYPE_TO_STRING = {

            0x000C: 'KEYSTATEBLOB ',
            0x0009: 'OPAQUEKEYBLOB',
            0x0008: 'PLAINTEXTKEYBLOB',
            0x0007: 'PRIVATEKEYBLOB',
            0x0006: 'PUBLICKEYBLOB',
            0x000A: 'PUBLICKEYBLOBEX',
            0x0001: 'SIMPLEBLOB',
            0x000B: 'SYMMETRICWRAPKEYBLOB',

            }

        return BLOBHEADER_TYPE_TO_STRING[dwBlobType]

    def __pre_process_parameters__(self, parameters, fp, this):

        if self.FunctionName == 'CryptAcquireContext':

            if fp.Name in ['pszContainer', 'pszProvider']:
                return self.helper.ReadCString(this, Ansi=self.Ansi)

            elif fp.Name == 'dwProvType':
                return self.LookupProviderTypeToString(this)

        elif self.FunctionName == 'CryptGetHashParam':
            if fp.Name == 'dwParam':
                return self.LookupHashParamToString(this)

        elif self.FunctionName == 'CryptImportKey':
            if fp.Name == 'pbData':
                dwBlobType = self.helper.ReadVirtualMemory8(this)
                parameters.dwBlobType = self.LookupPublicKeyType(dwBlobType)

        elif self.FunctionName == 'CryptExportKey':
            if fp.Name == 'dwBlobType':
                return self.LookupPublicKeyType(this)

        elif self.FunctionName == 'CryptEncrypt':
            if fp.Name == 'dwBufLen':
                parameters.DecryptedBuffer = self.helper.ReadVirtualMemory(parameters.pbData, this)

        elif fp.Name == 'Algid':
            return self.LookupAlgIdToString(this)
        
        else: return super().__pre_process_parameters__(parameters, fp, this)

    def __get_canonical_function_name__(self, FunctionName):

        if FunctionName.endswith('Stub'): return FunctionName.replace('Stub', '')
        else: return FunctionName
       
    def __post__(self, monitor):

        Action = monitor.LastOperation.Action
        Parameters = monitor.LastOperation.Detail

        if Action == 'CryptAcquireContext':
            if Parameters.Return and hasattr(Parameters, 'phProv'):
                Parameters.hProv = self.ReadVirtualMemoryPointer(Parameters.phProv)

        elif Action == 'CryptGenKey':
            if Parameters.Return and hasattr(Parameters, 'phKey'):
                Parameters.hKey = self.ReadVirtualMemoryPointer(Parameters.phKey)
            if Parameters.Return and hasattr(Parameters, 'dwFlags'):
                Parameters.KeySize = Parameters.dwFlags >> 16
                Parameters.KeyType = self.LookupKeyTypeToString(Parameters.dwFlags & 0xffff)

        elif Action == 'CryptCreateHash':
            if Parameters.Return and hasattr(Parameters, 'phHash'):
                Parameters.hHash = self.ReadVirtualMemoryPointer(Parameters.phHash)
        
        elif Action in ['CryptGetHashParam', 'CryptEncrypt', 'CryptDecrypt', 'CryptExportKey']:
            if Parameters.Return and hasattr(Parameters, 'pdwDataLen'):
               Parameters.dwDataLen = self.helper.ReadVirtualMemory32(Parameters.pdwDataLen)
   
        elif Action == 'CryptImportKey':
            if Parameters.Return and hasattr(Parameters, 'phKey'):
                Parameters.hKey = self.ReadVirtualMemoryPointer(Parameters.phKey)
                