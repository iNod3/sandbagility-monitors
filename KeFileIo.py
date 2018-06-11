from Sandbagility.Monitor import KernelGenericMonitor


class KeFileIoMonitor(KernelGenericMonitor):

    _NAME = 'File'
    _DEPENDENCIES = ['ntoskrnl.exe']

    def __install__(self):

        self.SetBreakpoint('nt!NtReadFile')
        self.SetBreakpoint('nt!NtWriteFile')

        return True
