import pefile
import os
import shutil

# Find executable sections in a PE file and return the name, the virtual address, and the raw address 
def findSections(fileName):
    pe = pefile.PE(fileName)

    executableSections = []

    image_base = pe.OPTIONAL_HEADER.ImageBase

    if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040:
        pass
        # print("[*] ASLR is enabled, Virtual address might be different while program will be executed.")

    for section in pe.sections:
        if (section.Characteristics & 0x20) and section.SizeOfRawData != 0:
            rawAddr = section.PointerToRawData
            virAddr = image_base + section.VirtualAddress
        
            secName = section.Name.decode('utf-8').rstrip('\0')
            executableSections.append((secName, virAddr, rawAddr))

    pe.close()
    
    return executableSections

# produce listing file with IDAPython script
def produceListing(filePath):
    fileName = filePath.split('\\')[-1]
    idatPath = "D:\IDA.Pro.7.6\idat.exe"
    scriptPath = "D:\Projects\Dead_Code_Injector\ida_listing_script.py"
    cmd = idatPath + " -A -a- -S\"" + str(scriptPath) + "\" " + filePath
    os.system(cmd)
    return filePath + "_listing.lst"

# find 'align' locations in the listing file
# returns a list of (raw address, virtual address, size)
def findValidLocations(filePath, listing):
    sectionInfos = findSections(filePath)
    locations = []
    
    for sec in sectionInfos:
        secName, virAddr, rawAddr = sec
        print("[LOG] Check section: ", secName, hex(virAddr), hex(rawAddr))
        with open(listing) as file:
            lines = file.readlines()
            numLines = len(lines)
            idx = 0
            while idx < numLines:
                line = lines[idx]
                if line.startswith(secName):
                    if line.find('align ') != -1:
                        # print(line)
                        # split the elements
                        address, a, b = (line[len(secName)+1:]).split()
                        address = int(address, 16)
                        # print(secName, hex(address))
                        # print(hex(rawAddr + address - virAddr))
                        
                        # find the next valid address to calculate the size by subtracting
                        found = False
                        while not found:
                            if idx + 1 < numLines:
                                next_address = ((lines[idx+1]).split(' ')[0]).split(':')[1]
                                next_address = int(next_address, 16)
                                if next_address != address:
                                    found = True
                                    locations.append((rawAddr + address - virAddr, next_address - address))    
                                idx += 1
                            else:
                                break
                idx += 1
    for l in locations: print(hex(l[0]), hex(l[1]))
    return locations

def patchFile(filePath, patches):
    # path of the patched file
    newFilePath = filePath + "_patched.exe"
    dest = shutil.copyfile(filePath, newFilePath)
    
    with open(newFilePath, "rb+") as file:
        for patch in patches:
            data = patch[1] * patch[2]
            print(type(data))
            file.seek(patch[0])
            file.write(data)

if __name__ == '__main__':
    filePath = "D:\PuTTY\putty.exe"
    # produceListing(filePath)
    locations = findValidLocations(filePath, "putty.exe_listing.lst")
    patches = []
    for l in locations:
        offset = l[0]
        data = b'\x90'
        size = l[1]
        patches.append((offset, data, size))
    print(patches)
    patchFile(filePath, patches)
    
