from Sandbagility.Monitor import KernelMonitor


class SyscallMonitor(KernelMonitor):

    _NAME = 'Syscall'
    _DEPENDENCIES = ['ntoskrnl.exe']

    _SYSCALLS = {}

    _SYSCALL_BY_ADDRESS = []
    _SYSCALL_GROUP = {}

    @property
    def Syscalls(self):
        return self._SYSCALLS

    @Syscalls.setter
    def Syscalls(self, value):
        if not isinstance(value, dict): return

        for k, v in value.items():
            if k in self._SYSCALLS: del self._SYSCALLS[k]
            self._SYSCALLS[k] = v

        self.__update_syscalls__()

    def __update_syscalls__(self):

        self._SYSCALL_BY_ADDRESS = []
        self._SYSCALL_GROUP = {}

        for Logger, SyscallArray in self._SYSCALLS.items():
            for s in SyscallArray:
                a = self.LookupByName(s)
                self._SYSCALL_BY_ADDRESS.append(a)
                self._SYSCALL_GROUP[s] = Logger

    def __install__(self):
        KiSystemServiceCopyEnd = self.LookupByName('nt!KiSystemServiceCopyEnd')
        self.SetHardwareBreakpoint( KiSystemServiceCopyEnd, self.KiSystemServiceCopyEnd, dr=0, description='KiSystemServiceCopyEnd')

        KiSystemServiceExit = self.LookupByName('nt!KiSystemServiceExit')
        self.SetHardwareBreakpoint(KiSystemServiceExit, self.KiSystemServiceExit, dr=1, description='KiSystemServiceExit')

        self.__update_syscalls__()
        self.SyscallPending = {}

    def SetCurrentPendingSyscall(self, args):
        self.SyscallPending[self.ActiveProcess.Cid.Tid] = args

    def IsSyscallPending(self):
        if not self.SyscallPending: return False
        if self.ActiveProcess.Cid.Tid not in self.SyscallPending: return False

        return True

    def GetCurrentPendingSyscall(self):
        return self.SyscallPending[self.ActiveProcess.Cid.Tid]

    def RemoveCurrentPendingSyscall(self):
        del self.SyscallPending[self.ActiveProcess.Cid.Tid]

    def GetParameterByIndex(self, Index):
        if  0 <= Index < 4: return super().GetParameterByIndex(Index)
        else: return self.GetStackValueByIndex(Index)

    def PsGetReturnValue(self):
        return None

    def __post_process_parameters__(self, Parameters, Prototype):

        for Key, Value in Parameters.__dict__.items():
            if Key not in [ p.Name for p in Prototype ]: continue
            Proto = [ p for p in Prototype if p.Name == Key ][0]

            if not Proto.IsOutput: continue
            if Proto.IsPointer: Value = self.ReadVirtualMemoryPointer(Value)

            setattr(Parameters, Key, self.__pre_process_parameters__(Parameters, Proto, Value))

    def __pre_process_parameters__(self, Parameters, Proto, Value):

        if Value is None: return None

        if Proto.Type == 'OBJECT_ATTRIBUTES' and Proto.IsPointer:
            ObjectAttributes = self.helper.ReadStructure(Value, 'nt!_OBJECT_ATTRIBUTES')
            Parameters.ObjectName = self.helper.ReadUnicodeString(ObjectAttributes.ObjectName)
        elif Proto.Type == 'CLIENT_ID' and Proto.IsPointer:
            Value = self.helper.ReadStructure(Value, 'nt!_'+Proto.Type)
        elif Proto.Type == 'HANDLE' and not Proto.IsPointer:
            if Value == 18446744073709551615: # -1 for current process
                Value = 'CurrentProcess'
            elif Value == 18446744073709551614: # -2 for current thread
                Value = 'CurrentThread'
            elif Value == 18446744073709551610: 
                Value = 'CurrentToken__'
            else:
                Parameters.Object = self.ActiveProcess.ObReferenceObjectByHandle(Value)
        elif Proto.Type in ['DWORD', 'ULONG', 'LONG']: Value &= 0xffffffff
        elif Proto.Type == 'WORD': Value &= 0xffff
        elif Proto.Type == 'BYTE': Value &= 0xFF
        elif Proto.Type == 'BOOL': Value &= 0x1
            
        return Value

    @KernelMonitor._decorator
    def KiSystemServiceCopyEnd(self):

        CurrentSyscallAddress = self.helper.dbg.r10
        self.logger.debug('CurrentSyscallAddress: %x' % CurrentSyscallAddress)
        if CurrentSyscallAddress not in self._SYSCALL_BY_ADDRESS and self.Syscalls != {}:
            return True

        CurrentSyscall = self.helper.symbol.LookupByAddr(CurrentSyscallAddress)
        self.logger.debug('CurrentSyscall: %s' % CurrentSyscall)
        if CurrentSyscall is None: return True

        if CurrentSyscall.find('!') != -1: Module, CurrentSyscall = CurrentSyscall.split('!')

        Prototype = self.helper.symbol.SymGetSyscallPrototype(CurrentSyscall)
        if Prototype == None: return True

        Parameters = self.ReadParameters(Prototype, self.__pre_process_parameters__)

        self.SetCurrentPendingSyscall((CurrentSyscall, Parameters, Prototype, self.helper.dbg.rsp))

        return True

    @KernelMonitor._decorator
    def KiSystemServiceExit(self):

        if not self.IsSyscallPending(): return True

        CurrentSyscall, Parameters, Prototype, StackPointer = self.GetCurrentPendingSyscall()
        if StackPointer != self.helper.dbg.rsp: return True

        if CurrentSyscall in self._SYSCALL_GROUP:
            self.Name = self._SYSCALL_GROUP[CurrentSyscall]

        Parameters.Return = self.helper.dbg.rax

        self.__post_process_parameters__(Parameters, Prototype)

        self.RemoveCurrentPendingSyscall()
        self.LastOperation.Save(Action=CurrentSyscall, Process=self.ActiveProcess, Detail=Parameters)

        return True
