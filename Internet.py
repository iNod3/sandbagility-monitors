from Sandbagility.Monitor import UserlandGenericMonitor as UserlandMonitor


class InternetMonitor(UserlandMonitor):

    _NAME = 'Internet'
    _DEPENDENCIES = ['WININET.dll']

    def __install__(self, NotifyLoadImage=None):

        self.SetBreakpoint('WININET!InternetOpenA')
        self.SetBreakpoint('WININET!InternetOpenW')

        self.SetBreakpoint('WININET!InternetOpenUrlA')
        self.SetBreakpoint('WININET!InternetOpenUrlW')

        self.SetBreakpoint('WININET!InternetConnectA')
        self.SetBreakpoint('WININET!InternetConnectW')

        self.SetBreakpoint('WININET!InternetReadFile')

        self.SetBreakpoint('WININET!HttpSendRequestA')
        self.SetBreakpoint('WININET!HttpSendRequestW')

        self.SetBreakpoint('WININET!HttpOpenRequestA')
        self.SetBreakpoint('WININET!HttpOpenRequestW')
        
        return True