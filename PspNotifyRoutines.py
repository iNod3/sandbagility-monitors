
from Sandbagility.Monitor import KernelMonitor

import ctypes

class PspNotifyRoutineMonitor(KernelMonitor):

    _NAME = None
    _DEPENDENCIES = ['ntoskrnl.exe']
    _NOTIFY_ROUTINE = ''

    def __install__(self):

        self.PspProcessNotifyRoutineAddress = self.GetPspNotifyRoutineAddress(self._NOTIFY_ROUTINE)
        self.helper.SetBreakpoint(self.PspProcessNotifyRoutineAddress, self.PspProcessNotifyRoutine, self.cr3, self._NOTIFY_ROUTINE)

        return True

    def Uninstall(self):
        self.helper.UnsetBreakpoint(self.PspProcessNotifyRoutineAddress, cr3=None, handler=self.PspProcessNotifyRoutine)

    def PspProcessNotifyRoutine(self):
        pass

    def GetPspNotifyRoutineAddress(self, symbol):
        '''
            @brief Resolve the given symbol into its address
        '''
        PspNotifyRoutine = self.helper.SymLookupByName(symbol)
        self.logger.debug('PspNotifyRoutine: %x', PspNotifyRoutine)

        PspNotifyRoutineCountAddr = self.helper.SymLookupByName(symbol + 'Count')
        PspNotifyRoutineCount = self.helper.ReadVirtualMemory32(PspNotifyRoutineCountAddr)

        if PspNotifyRoutineCountAddr == 0:
            raise Exception('PspNotifyRoutineError: No entry...')

        for i in range(0, PspNotifyRoutineCount):
            pNotifyRoutineStructure = self.helper.ReadVirtualMemory64(PspNotifyRoutine + i * self.PointerSize)
            if pNotifyRoutineStructure != 0: break

        if pNotifyRoutineStructure == 0:
            raise Exception('PspNotifyRoutineError: No Entry found...')

        self.logger.debug('pNotifyRoutineStructure: %x', pNotifyRoutineStructure)
        pNotifyRoutineStructure &= (~0xf)
        self.logger.debug('pNotifyRoutineStructure: %x', pNotifyRoutineStructure)

        NotifyRoutine = self.helper.ReadVirtualMemory64(pNotifyRoutineStructure + 0x8)
        self.logger.debug('NotifyRoutine: %x', NotifyRoutine)

        return NotifyRoutine

class PsCreateProcessMonitor(PspNotifyRoutineMonitor):

    _NAME = 'Process'
    _NOTIFY_ROUTINE = 'PspCreateProcessNotifyRoutine'

    @KernelMonitor._decorator
    def PspProcessNotifyRoutine(self):
        '''
            @brief Monitor callback called on each process creation/termination event
        '''
        ParentId = self.helper.dbg.rcx
        self.logger.debug('ParentId: %08x', ParentId)
        Parent = self.helper.PsLookupProcessByProcessId(ParentId)

        ProcessId = self.helper.dbg.rdx
        self.logger.debug('ProcessId: %08x', ProcessId)
        Process = self.helper.PsLookupProcessByProcessId(ProcessId)

        Created = self.helper.dbg.r8
        self.logger.debug('Created: %08x', Created)

        if Created: Action = 'CreateProcess'
        else: Action = 'ExitProcess'

        self.LastOperation.Save(Action=Action, Process=Parent, Detail=Process)

        return True

class PsCreateThreadMonitor(PspNotifyRoutineMonitor):

    _NAME = 'Thread'
    _NOTIFY_ROUTINE = 'PspCreateThreadNotifyRoutine'

    @KernelMonitor._decorator
    def PspProcessNotifyRoutine(self):
        '''
            @brief Monitor callback called on each thread creation/termination event
        '''
        ProcessId = self.helper.dbg.rcx
        self.logger.debug('ProcessId: %08x', ProcessId)

        ThreadId = self.helper.dbg.rdx
        self.logger.debug('ThreadId: %08x', ThreadId)

        Created = self.helper.dbg.r8
        self.logger.debug('Created: %08x', Created)

        if Created: Action = 'CreateThread'
        else: Action = 'ExitThread'

        Process = self.helper.PsLookupProcessByProcessId(ProcessId)

        self.LastOperation.Save(Action=Action, Process=Process, Detail=ThreadId)

        return True

class PsLoadImageMonitor(PspNotifyRoutineMonitor):

    _NAME = 'Image'
    _NOTIFY_ROUTINE = 'PspLoadImageNotifyRoutine'

    @KernelMonitor._decorator
    def PspProcessNotifyRoutine(self):
        '''
            @brief Monitor callback called on each image loading event
        '''
        class NotifyLoadImage(): pass

        class _IMAGE_INFO_PROPERTIES(ctypes.Structure):

            _fields_ = [
                ('ImageAddressingMode', ctypes.c_uint32, 8),
                ('SystemModeImage', ctypes.c_uint32, 1),
                ('ImageMappedToAllPids', ctypes.c_uint32, 1),
                ('ExtentedInfoPresent', ctypes.c_uint32, 1),
                ('MachineTypeMismatch', ctypes.c_uint32, 1),
                ('ImageSignatureLevel', ctypes.c_uint32, 4),
                ('ImageSignatureType', ctypes.c_uint32, 3),
                ('ImagePartialMap', ctypes.c_uint32, 1),
                ('Reserved', ctypes.c_uint32, 12),
            ]

            def __repr__(self):
                _dict_ = dict((f, getattr(self, f)) for f, _, __ in self._fields_)
                if hasattr(self, '__dict__'): _dict_.update(self.__dict__)
                return '%s' % _dict_

        class _IMAGE_INFO_PROPERTIES_U(ctypes.Union):

            _fields_ = [
                ('Value', ctypes.c_uint32),
                ('Flag', _IMAGE_INFO_PROPERTIES),
            ]

            def __repr__(self):
                _dict_ = dict((f, getattr(self, f)) for f, _ in self._fields_)
                if hasattr(self, '__dict__'): _dict_.update(self.__dict__)
                return '%s' % _dict_

        class _IMAGE_INFO(ctypes.Structure):

            '''
                @remark Supported only from vista
            '''
            _fields_ = [
                ('Properties', _IMAGE_INFO_PROPERTIES_U),
                ('ImageBase', ctypes.c_uint64),
                ('ImageSelector', ctypes.c_uint32),
                ('ImageSize', ctypes.c_uint64),
                ('ImageSectionNumber', ctypes.c_uint32),
            ]

            def __repr__(self):
                _dict_ = dict((f, getattr(self, f)) for f, _ in self._fields_)
                if hasattr(self, '__dict__'): _dict_.update(self.__dict__)
                return '%s' % _dict_

        FullImageNameUnicodePtr = self.helper.dbg.rcx
        self.logger.debug('FullImageNameUnicodePtr: %016x', FullImageNameUnicodePtr)

        FullImageName = self.helper.ReadUnicodeString(FullImageNameUnicodePtr)
        self.logger.debug('FullImageName: %s', FullImageName)

        ProcessId = self.helper.dbg.rdx
        self.logger.debug('ProcessId: %08x', ProcessId)

        Process = self.helper.PsLookupProcessByProcessId(ProcessId)
        self.logger.debug('%s',(str(Process).strip().replace('\n', ' ')))

        ImageInfoPtr = self.helper.dbg.r8
        self.logger.debug('ImageInfoPtr: %016x', ImageInfoPtr)

        NotifyLoadImage = self.helper.ReadStructure(ImageInfoPtr, _IMAGE_INFO)

        NotifyLoadImage.FullImageName = str(FullImageName)
        self.logger.debug('NotifyLoadImage.Properties: %08x', NotifyLoadImage.Properties.Value)
        self.logger.debug('NotifyLoadImage.ImageBase: %016x', NotifyLoadImage.ImageBase)
        self.logger.debug('NotifyLoadImage.ImageSelector: %08x', NotifyLoadImage.ImageSelector)
        self.logger.debug('NotifyLoadImage.ImageSize: %08x', NotifyLoadImage.ImageSize)
        self.logger.debug('NotifyLoadImage.ImageSectionNumber: %08x', NotifyLoadImage.ImageSectionNumber)

        self.LastOperation.Save(Action='LoadImage', Process=Process, Detail=NotifyLoadImage)

        return True
