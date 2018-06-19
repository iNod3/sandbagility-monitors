from Sandbagility.Monitor import KernelGenericMonitor

class VirtualMemoryMonitor(KernelGenericMonitor):
    
    _NAME = 'VirtualMemory'
    _DEPENDENCIES = ['ntoskrnl.exe']

    WRITE = 1
    EXECUTE = 2

    def __install__(self):
        
        self.SetHardwareBreakpoint('nt!NtAllocateVirtualMemory', 3)
        self.SetHardwareBreakpoint('nt!NtProtectVirtualMemory', 2)
        self.SetHardwareBreakpoint('nt!NtFreeVirtualMemory', 1)
        
        self.VirtualMemory = {}

        return True

class DynamicCodeMonitor(VirtualMemoryMonitor):
    
    _NAME = 'DynamicCode'

    WRITE = 1
    EXECUTE = 2

    def InsertVirtualMemoryProtection(self, BaseAddress, Protect):

        if Protect in [ 0x4, 0x08]:
            self.VirtualMemory[BaseAddress] |= self.WRITE
        if Protect in [ 0x10, 0x20]:
            self.VirtualMemory[BaseAddress] |= self.EXECUTE
        if Protect in [ 0x40, 0x80]:
            self.VirtualMemory[BaseAddress] |= self.WRITE | self.EXECUTE

    def InsertAllocateVirtualMemory(self, Operation):

        Detail = Operation.Detail
        self.VirtualMemory[Detail.BaseAddress] = 0

        if Operation.Action == 'NtAllocateVirtualMemory':
            if not hasattr(Detail, 'Protect'): return
            self.InsertVirtualMemoryProtection(Detail.BaseAddress, Detail.Protect)
        elif Operation.Action == 'NtProtectVirtualMemory':
            if not hasattr(Detail, 'NewProtect'): return
            self.InsertVirtualMemoryProtection(Detail.BaseAddress, Detail.NewProtect)
            self.InsertVirtualMemoryProtection(Detail.BaseAddress, Detail.OldProtect)

    def RemoveAllocatedVirtualMemory(self, Operation):

        Detail = Operation.Detail
        if Detail.BaseAddress in self.VirtualMemory:
            del self.VirtualMemory[Detail.BaseAddress]

    def CheckDynamicCodeVirtualMemory(self, Operation):

        Detail = Operation.Detail
        if Detail.BaseAddress not in self.VirtualMemory: return

        if (self.WRITE | self.EXECUTE) == self.VirtualMemory[Detail.BaseAddress]:
            return True
        return False

    def __post__(self, monitor):

        if monitor.LastOperation.Action == 'NtFreeVirtualMemory':
            self.RemoveAllocatedVirtualMemory(monitor.LastOperation)
        else:
            self.InsertAllocateVirtualMemory(monitor.LastOperation)
        
        if self.CheckDynamicCodeVirtualMemory(monitor.LastOperation):
            monitor.LastOperation.Action = 'DynamicCode'
        else: monitor.LastOperation.isEmpty = True

        return True