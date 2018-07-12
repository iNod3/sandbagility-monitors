from Sandbagility.Monitor import UserlandGenericMonitor as UserlandMonitor


class SynchroApiMonitor(UserlandMonitor):

    _NAME = 'Synchro'
    _DEPENDENCIES = ['kernelbase.dll']

    def __install__(self, NotifyLoadImage=None):

        self.SetBreakpoint('kernelbase!CreateMutexExW')
        self.SetBreakpoint('kernelbase!CreateEventExW')

        return True

    def __post__(self, monitor):

        if monitor.LastOperation.Detail.lpName == 0:
            monitor.LastOperation.isEmpty = True