EnableExplicit

Global PBufSize.l = 65535
Global MyImg.s = ProgramFilename()
Global MyPar.s = ProgramParameter(0)

Global _wtsapi32 = OpenLibrary(#PB_Any, "wtsapi32.dll")

Prototype.b pWTSQueryUserToken(SessionId, phToken) : Global WTSQueryUserToken.pWTSQueryUserToken = GetFunction(_wtsapi32, "WTSQueryUserToken") 
Prototype.l pWTSEnumerateSessions(hServer, Reserved, Version, *ppSessionInfo, *pCount) : Global WTSEnumerateSessions.pWTSEnumerateSessions = GetFunction(_wtsapi32, "WTSEnumerateSessionsA")

Structure WTS_SESSION_INFO
  SessionId.l
  pWinStationName.s
  State.l 
EndStructure

Procedure.s NamedPipeServer_ListenStr(PipeName$)
  Protected Result.s = ""
  Protected Recv$ = Space(PBufSize) 
  Protected BytesRead ; BytesRead
  Protected PipeHandle = CreateNamedPipe_(PipeName$, #PIPE_ACCESS_DUPLEX, #PIPE_TYPE_MESSAGE | #PIPE_READMODE_MESSAGE, 1, PBufSize, PBufSize, 3000, #Null) ; #PIPE_ACCESS_DUPLEX = 3
  If PipeHandle
    Protected Client = ConnectNamedPipe_(PipeHandle, #Null)
    If Client
      ReadFile_(PipeHandle, @Recv$, Len(Recv$), @BytesRead, 0)
      If Recv$ <> ""
        Result = Trim(Recv$)
      EndIf
      FlushFileBuffers_(PipeHandle)
      DisconnectNamedPipe_(PipeHandle)         
      CloseHandle_(PipeHandle)
    EndIf
  EndIf
  ProcedureReturn Result
EndProcedure

Procedure.s NamedPipeServerInSession_ListenStr(SessionID.l, PipeName$)
  Protected Result.s = ""
  Protected Recv$ = Space(PBufSize) 
  Protected BytesRead ; BytesRead
  
  Protected hToken, hImpersonate, pEnvironment, Res
  If SessionID  
    If WTSQueryUserToken(SessionID, @hToken)
      Protected sa.SECURITY_ATTRIBUTES 
      If DuplicateTokenEx_(hToken, #MAXIMUM_ALLOWED, @sa, 2, 1, @hImpersonate)
        If ImpersonateLoggedOnUser_(hImpersonate)
          If CreateEnvironmentBlock_(@pEnvironment, hImpersonate, #False) 
  
            Protected PipeHandle = CreateNamedPipe_(PipeName$, #PIPE_ACCESS_DUPLEX, #PIPE_TYPE_MESSAGE | #PIPE_READMODE_MESSAGE, 1, PBufSize, PBufSize, 3000, #Null) 
            If PipeHandle
              Protected Client = ConnectNamedPipe_(PipeHandle, #Null)
              If Client
                ReadFile_(PipeHandle, @Recv$, Len(Recv$), @BytesRead, 0)
                If Recv$ <> ""
                  Result = Trim(Recv$)
                EndIf
                FlushFileBuffers_(PipeHandle)
                DisconnectNamedPipe_(PipeHandle)         
                CloseHandle_(PipeHandle)
              EndIf
            EndIf
            
            DestroyEnvironmentBlock_(pEnvironment)
          EndIf 
          RevertToSelf_() 
        EndIf 
        CloseHandle_(hImpersonate) 
      EndIf
      CloseHandle_(hToken) 
    EndIf
  EndIf 
  
  ProcedureReturn Result
EndProcedure

Procedure.b NamedPipe_SendStr(PipeName$, StringData$)
  Protected Result.b = #False
  Protected Size = Len(StringData$)
  Protected BytesWritten.l
  Protected Res = WaitNamedPipe_(PipeName$, #Null)
  If Res
    Protected hFile = CreateFile_(PipeName$, #GENERIC_READ | #GENERIC_WRITE, 0, #Null, #OPEN_EXISTING,0, #Null)
    If hFile
      WriteFile_(hFile, @StringData$, Size, @BytesWritten, 0)
      If BytesWritten
        Result = #True
      EndIf
      FlushFileBuffers_(hFile)
      CloseHandle_(hFile)
    EndIf
  EndIf
  ProcedureReturn Result
EndProcedure

Procedure.b NamedPipe_SessionSendStr(SessionID, PipeName$, StringData$)
  Protected Result.b = #False
  
  Protected hToken, hImpersonate, pEnvironment, Res
  If SessionID  
    If WTSQueryUserToken(SessionID, @hToken)
      Protected sa.SECURITY_ATTRIBUTES 
      If DuplicateTokenEx_(hToken, #MAXIMUM_ALLOWED, @sa, 2, 1, @hImpersonate)
        If ImpersonateLoggedOnUser_(hImpersonate)
          If CreateEnvironmentBlock_(@pEnvironment, hImpersonate, #False) 
          
            Protected Size = Len(StringData$)
            Protected BytesWritten.l
            Res = WaitNamedPipe_(PipeName$, #Null)
            If Res
              Protected hFile = CreateFile_(PipeName$, #GENERIC_READ | #GENERIC_WRITE, 0, #Null, #OPEN_EXISTING,0, #Null)
              If hFile
                WriteFile_(hFile, @StringData$, Size, @BytesWritten, 0)
                If BytesWritten
                  Result = #True
                EndIf
                FlushFileBuffers_(hFile)
                CloseHandle_(hFile)
              EndIf
            EndIf            
          
            DestroyEnvironmentBlock_(pEnvironment)
          EndIf 
          RevertToSelf_() 
        EndIf 
        CloseHandle_(hImpersonate) 
      EndIf
      CloseHandle_(hToken) 
    EndIf
  EndIf 
  
  ProcedureReturn Result
EndProcedure

Procedure.l RunProcessAsUserInSession(Session, lpApplicationName, lpCommandLine = #Null, lpCurrentDirectory = #Null, Hide = #False) 
  Protected hToken, hImpersonate, pEnvironment, Res
  If Session  
    If WTSQueryUserToken(Session, @hToken)
      Protected sa.SECURITY_ATTRIBUTES 
      If DuplicateTokenEx_(hToken, #MAXIMUM_ALLOWED, @sa, 2, 1, @hImpersonate)
        If ImpersonateLoggedOnUser_(hImpersonate)
          If CreateEnvironmentBlock_(@pEnvironment, hImpersonate, #False) 
            #CREATE_UNICODE_ENVIRONMENT = $400
            Protected dwCreationFlags = #NORMAL_PRIORITY_CLASS | #CREATE_NEW_CONSOLE | #CREATE_UNICODE_ENVIRONMENT
            Protected si.STARTUPINFO 
            ZeroMemory_(@si, SizeOf(STARTUPINFO))
            si\cb = SizeOf(STARTUPINFO) 
            si\lpDesktop = @"WinSta0\Default"
            si\dwFlags = #STARTF_USESHOWWINDOW
            Select Hide
              Case #True 
                si\wShowWindow = #SW_HIDE 
              Case #False 
                si\wShowWindow = #SW_SHOWNORMAL 
            EndSelect
            Protected pi.PROCESS_INFORMATION
            ZeroMemory_(@pi, SizeOf(PROCESS_INFORMATION))
            Res = CreateProcessAsUser_(hImpersonate, lpApplicationName, lpCommandLine, @sa, @sa, #False, dwCreationFlags, pEnvironment, lpCurrentDirectory, @si, @pi) 
            SetLastError_(0) 
            DestroyEnvironmentBlock_(pEnvironment)
          EndIf 
          RevertToSelf_() 
        EndIf 
        CloseHandle_(hImpersonate) 
      EndIf
      CloseHandle_(hToken) 
    EndIf
  EndIf 
  ProcedureReturn Res 
EndProcedure

Procedure.s RunSystemCommandTextOutput(CommandLine.s, Directory$="", Timeout.l=0)
  Protected Result.s = ""
  If CommandLine <> ""
    Protected CaptureProgram = RunProgram("cmd.exe", "/c " + CommandLine, Directory$, #PB_Program_Open | #PB_Program_Read | #PB_Program_Error | #PB_Program_Hide)
    If ProgramRunning(CaptureProgram)
      Protected StartTime.q = ElapsedMilliseconds()
      ;WriteProgramStringN(CaptureProgram, "")
      While ProgramRunning(CaptureProgram)
        If AvailableProgramOutput(CaptureProgram)
          Define Temp$ = ReadProgramString(CaptureProgram)
          ;If Temp$ <> ""
            Result + Temp$ + #CRLF$
          ;EndIf
          Delay(5)
        EndIf
        If Timeout <> 0 And ElapsedMilliseconds() - StartTime >= Timeout
          CloseProgram(CaptureProgram)
          Result = "Program Output Stopped After Timeout (" + Str(Timeout) + "ms)." + #CRLF$ + Result
        EndIf
      Wend
    Else
      Result = "Error: Program Did Not Run."
    EndIf
  Else
    Result = "Error: No Input Given."
  EndIf
  ProcedureReturn Result
EndProcedure

Procedure.i WTSGetActiveSession() 
  Protected Result.l = -1
  Protected WTSHandle.l = 0 
  Protected Version.l = 1 
  Protected *SessionInfo 
  Protected Count.i = 0 
  Protected ReturnVal, i 
  Protected WSI.WTS_SESSION_INFO
  ReturnVal = WTSEnumerateSessions(WTSHandle, #Null, Version, @*SessionInfo, @Count)
  If ReturnVal <> 0
    For i = 0 To Count -1
      CopyMemory(*SessionInfo+SizeOf(WTS_SESSION_INFO)*i, WSI, SizeOf(WTS_SESSION_INFO)+SizeOf(Character))
      If WSI\State = 0
        Result = WSI\SessionId
      EndIf
      Delay(1)
    Next
  Else
    Result = -1
  EndIf
  ProcedureReturn Result
EndProcedure

OpenConsole()

Select UserName()
  Case "SYSTEM"
    Global ActiveSession.i = WTSGetActiveSession()
    If ActiveSession <> -1
      If RunProcessAsUserInSession(ActiveSession, @MyImg, #Null, #Null, #True)
        NamedPipeServerInSession_ListenStr(ActiveSession, "\\.\pipe\frontstage0x001")
        NamedPipe_SessionSendStr(ActiveSession, "\\.\pipe\frontstage0x744", ProgramParameter(0))
      EndIf
      Print(NamedPipeServerInSession_ListenStr(ActiveSession, "\\.\pipe\frontstage0x452"))
    EndIf
  Default 
    NamedPipe_SendStr("\\.\pipe\frontstage0x001","GO")
    Global MyParams.s = NamedPipeServer_ListenStr("\\.\pipe\frontstage0x744")
    NamedPipe_SendStr("\\.\pipe\frontstage0x452", RunSystemCommandTextOutput(MyParams))
EndSelect

CloseLibrary(_wtsapi32)
; IDE Options = PureBasic 5.31 (Windows - x86)
; ExecutableFormat = Console
; Folding = Ax
; EnableThread
; Executable = frontstage.exe