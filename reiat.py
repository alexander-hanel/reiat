'''
Name:
        reiat.py

Version:
        0.5
        - 0.3 * fixed bug in regards to not exiting when a call was found.
        - 0.4 * fixed boundaries issue due to assuming the function end will be lower
                than the current address. Do not rely on FUNCATTR_END. 
              * Added function to check for data refs. If a section is not marked as
                code the 0.3 version would not see the xrefs to GetProcAddress.
                DataRefsTo(LocByName("GetProcAddress")) fixes this problem
        - 0.5 * Fixed bug to properly return address address of last mov to unnameable address
              * Added simple viewer. Can be disabled by changing - if True: Viewer(ok.log) to
                if False: Viewer(ok.log)
              * Saves a log of the results in an list Saved in class getProcAddresser object.log
                It's a list that contains tupple of
                (Original Address of GetProcAddress, lpProcName, Last address reference, type)
                The type can be xrf (for named dword), call (call eax ; ExitProcess) or the last
                operand ([esi+4]). If the values could not be found the tupple item will contain None. 

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
        self.log = [] 

    def getRefs(self):
        'get all addresses of GetProcAddress'
        for addr in CodeRefsTo(LocByName("GetProcAddress"), 0):
            self.getProcAddressRefs.append(addr)
        # If IDA does not recognize that the section as code it will
        # not have a code xref. 
        if len(self.getProcAddressRefs) == 0:
            for addr in DataRefsTo(LocByName("GetProcAddress")):
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
        funcAddress = list(FuncItems(address))
        var = 'eax'
        lastref = ''
        lastrefAddress = None
        while currentAddress in funcAddress:
            dism = GetDisasm(currentAddress)
            if GetMnem(currentAddress) == 'call' and var == 'eax' and GetOpnd(currentAddress,0) != 'eax':
                return (None, None)
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
                        return (currentAddress, GetOpnd(currentAddress,0))
                return (currentAddress, GetOperandValue(currentAddress,0))
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
                    return (True,currentAddress)
            # eax is usually over written by the the return value 
            if GetMnem(currentAddress) == 'call' and var == 'eax':
                    return (None, None)
            currentAddress = NextHead(currentAddress)

        if  GetMnem(lastrefAddress) == 'mov' and GetOpType(lastrefAddress,0) != 2:
           return (lastrefAddress, GetOpnd(lastrefAddress,0))
        return (None, None)    
    
    def rename(self):
        self.getRefs()
        for addr in self.getProcAddressRefs:
            lpProcNameAddr = self.getlpProcName(addr)
            if lpProcNameAddr == None:
                print "ERROR: Address of lpProcName at %s was not found" % hex(addr)
                self.log.append((addr, None, None, None))
                continue
            lpProcName =  self.getString(lpProcNameAddr)
            if lpProcName == None:
                lpProcName = self.traceBack(lpProcNameAddr)
            if lpProcName == None:
                print "ERROR: String of lpProcName at %s was not found" % hex(addr)
                self.log.append((addr, None, None, None))
                continue
            status = self.traceForwardRename(addr, lpProcName)
            if status[0] == None and status[1] == None:
                print "ERROR: Could not find forward variable refs for %s " % hex(addr)
                print status[0], status[1]
                self.log.append((addr, lpProcName, None, None))
            # Could not rename value, example:  mov [esi+0Ch], eax
            elif type(status[1]) == str:
                print "Unnameable %s at %s" % ( lpProcName, hex(status[0]))
                self.log.append((addr, lpProcName, status[0], status[1]))
            # added comment 
            elif status[0] == True and status[1]:
                print "Comment %s at %s" % ( lpProcName, hex(status[1]))
                self.log.append((addr, lpProcName, status[1], 'call'))
            # renamed a dword
            elif status[0] and status[1]:
                print "Renamed %s at %s" % ( lpProcName, hex(status[0]))
                self.log.append((addr, lpProcName, status[1], 'xref')) 

class Viewer(idaapi.simplecustviewer_t):
    # modified version of http://dvlabs.tippingpoint.com/blog/2011/05/11/mindshare-extending-ida-custviews
	def __init__(self, data):
		self.fourccs = data
		self.Create()
		self.Show()

	def Create(self):
		title = "Dynamic APIs"
		idaapi.simplecustviewer_t.Create(self, title)
		c = "%s%43s%11s   %s" % ("Address", "API Name", "Last xref", "Type")
		comment = idaapi.COLSTR(c, idaapi.SCOLOR_BINPREF)
		self.AddLine(comment)
		
		for item in self.fourccs:
			addy = item[0]
			api_str = item[1]
			last_ref = item[2]
                        type_ref = item[3]
			address_element = idaapi.COLSTR("0x%08x" % addy, idaapi.SCOLOR_REG)
			api_element = idaapi.COLSTR("%40s" % api_str, idaapi.SCOLOR_VOIDOP)
			if type(last_ref) == int:
                            last_element = idaapi.COLSTR("0x%08x" % last_ref, idaapi.SCOLOR_REG)
                        else:
                            last_element = idaapi.COLSTR("%10s" % last_ref, idaapi.SCOLOR_REG)
                        type_element = idaapi.COLSTR("%s" % type_ref, idaapi.SCOLOR_REG)
			line = address_element + api_element + "  " + last_element + "  " +  type_element
			self.AddLine(line)
		return True

	def OnDblClick(self, something):
		value = self.GetCurrentWord()
		if value[:2] == '0x':
                    Jump(int(value, 16))
		return True  

	def OnHint(self, lineno):
		if lineno < 2: return False
		else: lineno -= 2
		line = self.GetCurrentWord()
		if line == None: return False
		if "0x" not in line: return False
		# skip COLSTR formatting, find address
		addy = int(line, 16)
		disasm = idaapi.COLSTR(GetDisasm(addy) + "\n", idaapi.SCOLOR_DREF)
		return (1, disasm)  

if __name__ == "__main__":
    ok = getProcAddresser()
    ok.rename()
    if True:
        Viewer(ok.log)

        
