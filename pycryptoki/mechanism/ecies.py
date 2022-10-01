"""
ECIES mechanisms. 
"""
from _ctypes import pointer, sizeof
from ctypes import cast, c_void_p

from ..attributes import to_byte_array
from ..cryptoki import CK_ECIES_PARAMS, CK_BYTE_PTR, CK_ULONG
from .helpers import Mechanism


class ECIESMechanism(Mechanism):
    """
    ECIES-specific mechanism
    """

    REQUIRED_PARAMS = ["dhPrimitive", "kdf", "sharedData1", "encScheme", "encKeyLenInBits",
                       "macScheme", "macKeyLenInBits", "macLenInBits", "sharedData2"]

    def to_c_mech(self):
        """
        Create the Param structure, then convert the data into byte arrays.

        :return: :class:`~pycryptoki.cryptoki.CK_MECHANISM`
        """
        super(ECIESMechanism, self).to_c_mech()
        params = CK_ECIES_PARAMS()
        
        params.dhPrimitive = self.params["dhPrimitive"]
        
        params.kdf = self.params["kdf"]
        
        if self.params["sharedData1"] is None:
            shared_data1 = None
            shared_data_len1 = 0
        else:
            shared_data1, shared_data_len1 = to_byte_array(self.params["sharedData1"])
        params.pSharedData1 = cast(shared_data1, CK_BYTE_PTR)
        params.ulSharedDataLen1 = shared_data_len1

        params.encScheme = self.params["encScheme"]
        
        params.ulEncKeyLenInBits = CK_ULONG(self.params["encKeyLenInBits"])
        
        params.macScheme = self.params["macScheme"]
        
        params.ulMacKeyLenInBits = CK_ULONG(self.params["macKeyLenInBits"])

        params.ulMacLenInBits = CK_ULONG(self.params["macLenInBits"])

        if self.params["sharedData2"] is None:
            shared_data2 = None
            shared_data_len2 = 0
        else:
            shared_data2, shared_data_len2 = to_byte_array(self.params["sharedData2"])
        params.pSharedData2 = cast(shared_data2, CK_BYTE_PTR)
        params.ulSharedDataLen2 = shared_data_len2
        
        self.mech.pParameter = cast(pointer(params), c_void_p)
        self.mech.usParameterLen = CK_ULONG(sizeof(params))
        return self.mech
