from Sandbagility.Monitor import UserlandGenericMonitor as UserlandMonitor


class ServiceMonitor(UserlandMonitor):

    _NAME = 'Service'
    _DEPENDENCIES = ['sechost.dll']

    def __install__(self, NotifyLoadImage=None):

        self.SetBreakpoint('sechost!OpenSCManagerW')
        self.SetBreakpoint('sechost!OpenSCManagerA')

        self.SetBreakpoint('sechost!OpenServiceW')
        self.SetBreakpoint('sechost!OpenServiceA')

        self.SetBreakpoint('sechost!ChangeServiceConfigW')
        self.SetBreakpoint('sechost!ChangeServiceConfigA')

        self.SetBreakpoint('sechost!CreateServiceA')
        self.SetBreakpoint('sechost!CreateServiceW')

        self.SetBreakpoint('sechost!StartServiceA')
        self.SetBreakpoint('sechost!StartServiceW')

        self.SetBreakpoint('sechost!DeleteService')

        self.SetBreakpoint('sechost!CloseServiceHandle')

        self.SetBreakpoint('sechost!StartServiceCtrlDispatcherW')
        self.SetBreakpoint('sechost!StartServiceCtrlDispatcherA')

        self.SetBreakpoint('sechost!RegisterServiceCtrlHandlerW')
        self.SetBreakpoint('sechost!RegisterServiceCtrlHandlerA')

        self.SetBreakpoint('sechost!ControlServiceExA')
        self.SetBreakpoint('sechost!ControlServiceExW')

        return True

    def __ServiceArgVectors__(self, dwNumServiceArgs, lpServiceArgVectors, Ansi):
        '''
            @brief This function is used to parse the Service arg vectors given as parameters
            to the function StartService
        '''
        ServiceArgVectorList = []

        self.logger.debug('ServiceArgVectors: dwNumServiceArgs: %x, lpServiceArgVectors: %x', dwNumServiceArgs, lpServiceArgVectors)

        for Count in range(dwNumServiceArgs):
            self.logger.debug('ServiceArgVectors: Count: %x', Count)

            ServiceArgEntry = self.ReadVirtualMemoryPointer(lpServiceArgVectors+Count*self.PointerSize)
            self.logger.debug('ServiceArgVectors: ServiceArgEntry: %x', ServiceArgEntry)

            ServiceArgString = self.helper.ReadCString(ServiceArgEntry, Ansi=Ansi)
            self.logger.debug('ServiceArgVectors: Count: %x, ServiceArgEntry: %x, ServiceArgString: %s', Count, ServiceArgEntry, ServiceArgString)

            ServiceArgVectorList.append(ServiceArgString)

        return ServiceArgVectorList

    def __pre_process_parameters__(self, parameters, fp, this):

        if fp.Name == 'lpServiceArgVectors': return self.__ServiceArgVectors__(parameters.dwNumServiceArgs, this, self.Ansi)
        else:
            value = super().__pre_process_parameters__(parameters, fp, this)
            if value and fp.Name.startswith('lp'):
                setattr(parameters, fp.Name[2:], value)
            else: return value
