
from Sandbagility.Monitor import UserlandGenericMonitor as UserlandMonitor

import ctypes

class WinsockMonitor(UserlandMonitor):

    _NAME = 'Winsock2'
    _DEPENDENCIES = ['ws2_32.dll']

    class SockAddr(ctypes.Structure):       
        _fields_ = [                                                                                                              
            ('sa_len', ctypes.c_uint8),                                                                                                  
            ('sa_family', ctypes.c_uint8),                                                                                               
            ('sa_data', ctypes.c_char * 14)                                                                                                
        ]                                                                                                                         

    class SockAddr_In(ctypes.Structure):                                                                                                 
        _fields_ = [                                                                                                              
            ('sa_len', ctypes.c_uint8),                                                                                                  
            ('sa_family', ctypes.c_uint8),                                                                                               
            ('sin_port', ctypes.c_uint16),                                                                                               
            ('sin_addr', ctypes.c_uint32),                                                                                                
            ('sin_zero', ctypes.c_char * 8)                                                                                                
        ]  

        def __repr__(self):
            _d = {}
            for k, _ in self._fields_: _d[k] = getattr(self, k)
            return str(_d)

    def __pre_process_parameters__(self, parameters, fp, this):

        if fp.Function in ['connect', 'bind']:
            if (fp.Name == 'Addr'):
                return self.helper.ReadStructure(this, self.SockAddr_In)

        else: return super().__pre_process_parameters__(parameters, fp, this)

    def __install__(self, NotifyLoadImage=None):

        self.SetBreakpoint('ws2_32!connect')
        self.SetBreakpoint('ws2_32!bind')
        self.SetBreakpoint('ws2_32!send')
        self.SetBreakpoint('ws2_32!recv')
        
        return True