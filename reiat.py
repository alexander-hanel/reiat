from idaapi import *
import idautils
import idc

class getProcAddresser():
    def __init__(self):
        self.getProcAddressRefs = []
        self.registers = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp']

    def getRefs(self):
        'get all addresses of GetProcAddress'
        for addr in CodeRefsTo(LocByName("GetProcAddress"), 0):
            self.getProcAddressRefs.append(addr)

    def getlpProcName(self, GetProcAddress):
        'returns the address of the 2nd argument to GetProcAddress'
        pushcount = 0
        argPlacement = 2
        instructionMax = 10 + argPlacement
        currAddress = PrevHead(GetProcAddress,minea=0)
        while pushcount <= argPlacement and instructionMax != 0:
            if 'push' in GetDisasm(currAddress):
                pushcount += 1
                if pushcount == argPlacement:
                    return currAddress
            if 'GetModuleHandle' in GetDisasm(currAddress):
                    pushcount -= 1
            instructionMax -= 1
            currAddress = PrevHead(currAddress,minea=0)
        return None

    def getString(self, address):
        'reads the string value that is the second push'
        # note it will be useful to include back tracing code for variable reference. 
        api = GetString(GetOperandValue(address,ASCSTR_C), -1)
        if api == None:
            return None
        else:
            return api  

    def traceBack(self, address):
        funcStart = GetFunctionAttr(address, FUNCATTR_START)
        var = GetOpnd(address, 0)
        # return if digit is being pushed, likely an error on parsing
        if var.isdigit():
            return None
        # return, value is not being passed as a register. already checked
        # if offset in calling function
        if var not in self.registers:
            return None
        # get next address
        currentAddress = PrevHead(address)
        # get dism 
        dism = GetDisasm(currentAddress)
        # until end of function
        # Example:
        # mov ebp, offset aInternetconnec ; "InternetConnectA"
        # push    ebp
        while(currentAddress >= funcStart):
            # var = 'ebp', 
            if var in dism:
                # if operand == ebp, our tracked var is the destination
                if GetOpnd(currentAddress,0) == var:
                    mnem = GetMnem(currentAddress)
                    # if our tracked var is having something moved into it
                    if 'mov' in mnem or 'lea' in mnem:
                        # 4 scenarios on mov: string, digit, register unknown..
                        # 1. Check if destination is a string
                        # read operand 1 value, get address of "offset aInternetconnec"
                        value = GetOperandValue(currentAddress,1)
                        if value != None:
                            api = GetString(value, -1)
                            if api != None:
                                return api
                        # 2. Check if register
                        var = GetOpnd(currentAddress,1)
                        # 3. Check if digit
                        if var.isdigit() == True:
                            return None
                        # 4. Unknown
                        if var == None:
                            return None
                        
            currentAddress = PrevHead(currentAddress)
            dism = GetDisasm(currentAddress)
        return None

    def traceForwardRename(self, address, apiString):
        'address is call GetProcAddress, apiString is the API name'
        currentAddress = NextHead(address)
        funcEnd = GetFunctionAttr(address,  FUNCATTR_END)
        var = 'eax'
        while currentAddress < funcEnd:
            dism = GetDisasm(currentAddress)
            # if we are not referencing the return from GetProcAddress
            # continue to next instuction
            if var not in dism:
                currentAddress = NextHead(currentAddress)
                continue
            #   mov     dword_1000F224, eax
            #   call    esi ; GetProcAddress
            #   push    offset aHttpaddreque_0 ; "HttpAddRequestHeadersW"
            #   push    dword_1000FD08  ; hModule
            #   mov     dword_1000F228, eax 
            # if we have the above instructions after GetProcAddress the code
            # is saving off the address of HttpAddRequestHeadersW.  

            if GetMnem(currentAddress) == 'mov' and GetOpnd(currentAddress,1) == var and GetOpType(currentAddress,0) == 2:
                # rename dword address
                MakeNameEx(GetOperandValue(currentAddress,0), apiString, SN_NOWARN)
                return currentAddress
            if GetMnem(currentAddress) == 'mov' and GetOpnd(currentAddress,1) == var:
                var = GetOpnd(currentAddress,0)
            # add comments for call var
            # example:
            # call    ds:GetProcAddress
            # ...
            # call    eax
            if GetMnem(currentAddress) == 'call' and GetOpnd(currentAddress,0) == var:
                cmt = GetFunctionCmt(currentAddress,1)
                if apiString not in cmt:
                    cmt = cmt + ' ' + apiString
                    MakeComm(currentAddress, cmt)
                    return currentAddress
            # call and eax return can not be traced. 
            if GetMnem(currentAddress) == 'call' and var == 'eax':
                return None
            currentAddress = NextHead(currentAddress)
        return None
    
    def rename(self):
        self.getRefs()
        for addr in self.getProcAddressRefs:
            lpProcNameAddr = self.getlpProcName(addr)
            if lpProcNameAddr == None:
                print "ERROR: Address of lpProcName at %s was not found" % hex(addr)
                continue
            lpProcName =  self.getString(lpProcNameAddr)
            if lpProcName == None:
                lpProcName = self.traceBack(lpProcNameAddr)
            if lpProcName == None:
                print "ERROR: String of lpProcName at %s was not found" % hex(addr)
                continue
            status = self.traceForwardRename(addr, lpProcName)
            if status == None:
                print "ERROR: Could not rename address at %s " % hex(addr)
                continue
            else:
                print "RENAMED %s at %s" % ( lpProcName, hex(status))
 

if __name__ == "__main__":
    ok = getProcAddresser()
    ok.rename()
        
'''
getlpProcName notes 
Need to figure out a better way to parse to match this scenario.

.text:10005550                 mov     esi, ds:GetModuleHandleA
.text:10005556                 push    offset aGetsystemdirec ; "GetSystemDirectoryA"
.text:1000555B                 mov     edi, offset ModuleName ; "kernel32.dll"
.text:10005560                 push    edi             ; lpModuleName
.text:10005561                 mov     dword_100106F0, 1
.text:1000556B                 call    esi ; GetModuleHandleA
.text:1000556D                 mov     ebx, ds:GetProcAddress
.text:10005573                 push    eax             ; hModule
.text:10005574                 call    ebx ; GetProcAddress
.text:10005576                 push    offset aIsbadreadptr ; "IsBadReadPtr"
.text:1000557B                 push    edi             ; lpModuleName
.text:1000557C                 mov     dword_1000F47C, eax
.text:10005581                 call    esi ; GetModuleHandleA
.text:10005583                 push    eax             ; hModule
'''    
        
        # GetProcAddress
        # Retrieves the address of an exported function or variable
        # from the specified dynamic-link library (DLL).
        #
        # FARPROC WINAPI GetProcAddress(
        #  _In_  HMODULE hModule,
        #  _In_  LPCSTR lpProcName
        #);
