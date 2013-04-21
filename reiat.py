'''
Name:
        reiat.py

Version:
        0.2

Description:
        renames and add coments to apis that are are called via run-time dynamic analysis in IDA.
	To execute the script just call it in IDA 

Author:
        alexander<dot>hanel<at>gmail<dot>com

License:
reiat.py is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see
<http://www.gnu.org/licenses/>.

'''

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
	lastref = ''
	lastrefAddress = None
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
		status = True
                status = MakeNameEx(GetOperandValue(currentAddress,0), apiString, SN_NOWARN)
		if status == False:
			# some api names are already in use. Will need to be renamed to something generic. 
			# IDA will typically add a number to the function or api name. GetProcAddress_0
			status = MakeNameEx(GetOperandValue(currentAddress,0), str("__" + apiString), SN_NOWARN)
			if status == False:
				return None
                return currentAddress
	    # tracked data is being moved into another destination
            if GetMnem(currentAddress) == 'mov' and GetOpnd(currentAddress,1) == var:
		lastref = var
		lastrefAddress = currentAddress
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
            
	    # eax is usually over written by the the return value 
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
        
