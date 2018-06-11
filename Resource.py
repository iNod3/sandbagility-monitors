from Sandbagility.Monitor import UserlandGenericMonitor as UserlandMonitor


class ResourceMonitor(UserlandMonitor):

    _NAME = 'Resource'
    _DEPENDENCIES = ['kernelbase.dll', 'kernel32.dll']

    def __install__(self, NotifyLoadImage=None):

        self.logger.debug('Install: kernelbase')

        if NotifyLoadImage is None or 'kernel32' in NotifyLoadImage.FullImageName.lower():
            self.SetBreakpoint('kernel32!FindResourceA')
            self.SetBreakpoint('kernel32!FindResourceExA')

        if NotifyLoadImage is None or 'kernelbase' in NotifyLoadImage.FullImageName.lower():
            self.SetBreakpoint('kernelbase!FindResourceW')
            self.SetBreakpoint('kernelbase!FindResourceExW')
            self.SetBreakpoint('kernelbase!LoadResource')
            self.SetBreakpoint('kernelbase!SizeofResource')

        return True

    def __read_resource_name__(self, value):

        IntResource = value & 0xffff0000
        if IntResource == 0: return value
        else: return self.helper.ReadCString(value, 260, self.Ansi)

    def __pre_process_parameters__(self, parameters, fp, this):

        if fp.Function in ['FindResource', 'FindResourceEx']:
            if (fp.Name == 'lpType' or fp.Name == 'lpName') and fp.Type == 'LPCTSTR':
                return self.__read_resource_name__(this)

        else: return super().__pre_process_parameters__(parameters, fp, this)

    def __post__(self, monitor):

        Action = monitor.LastOperation.Action
        Detail = monitor.LastOperation.Detail
        monitor.LastOperation.isEmpty = True

        if Action.startswith('FindResource'):

            if Detail.Return not in self.Cache:
                if hasattr(Detail, 'lpName'):
                    self.Cache[Detail.Return] = {'lpName': Detail.lpName}
                if hasattr(Detail, 'lpType') and isinstance(Detail.lpType, str) and not isinstance(Detail.lpName, str):
                    self.Cache[Detail.Return] = {'lpName': Detail.lpType}

        elif Action == 'LoadResource':

            if not hasattr(Detail, 'hResInfo'): return True
            if Detail.Return is None: return True

            if Detail.hResInfo in self.Cache:
                self.Cache[Detail.hResInfo]['hResData'] = Detail.Return
            else:
                self.Cache[Detail.hResInfo] = {'hResData': Detail.Return, 'lpName': '%x' % Detail.Return}

        elif Action == 'SizeofResource':

            if not hasattr(Detail, 'hResInfo'): return True

            if Detail.hResInfo in self.Cache:
                resource = self.Cache[Detail.hResInfo]

                if 'hResData' in resource:

                    Data = self.helper.ReadVirtualMemory(resource['hResData'], Detail.Return)

                    del self.Cache[Detail.hResInfo]

                    monitor.LastOperation.Action = 'AcquireResource'
                    monitor.LastOperation.Detail.hResData = resource['hResData']
                    monitor.LastOperation.Detail.lpName = resource['lpName']
                    monitor.LastOperation.Detail.Data = Data
                    monitor.LastOperation.isEmpty = False