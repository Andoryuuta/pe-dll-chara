import pefile
import sys

flags = {
    'RESERVED_0x0001': 0x0001,
    'RESERVED_0x0002': 0x0002,
    'RESERVED_0x0004': 0x0004,
    'RESERVED_0x0008': 0x0008,
    'HIGH_ENTROPY_VA': 0x0020, #Image can handle a high entropy 64-bit virtual address space.
    'DYNAMIC_BASE': 0x0040, # DLL can be relocated at load time.
    'FORCE_INTEGRITY': 0x0080, # Code Integrity checks are enforced.
    'NX_COMPAT': 0x0100, # Image is NX compatible.
    'NO_ISOLATION': 0x0200, # Isolation aware, but do not isolate the image.
    'NO_SEH': 0x0400, # Does not use structured exception (SE) handling. No SE handler may be called in this image.
    'NO_BIND': 0x0800, # Do not bind the image.
    'APPCONTAINER': 0x1000, # Image must execute in an AppContainer.
    'WDM_DRIVER': 0x2000, # A WDM driver.
    'GUARD_CF': 0x4000, #Image supports Control Flow Guard.
    'TERMINAL_SERVER_AWARE': 0x8000, # Terminal Server aware. 
}

def print_dll_characteristics(pe):
    for flag in flags.keys():
        print('\t{:21} = {}'.format(flag, pe.OPTIONAL_HEADER.DllCharacteristics & flags[flag] > 0))

def do_changes(pe, flag_changes):
    for flag, setting in flag_changes.items():
        if setting:
            pe.OPTIONAL_HEADER.DllCharacteristics |= flags[flag]
        else:
            pe.OPTIONAL_HEADER.DllCharacteristics &= ~flags[flag]

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: {} <some_pe_file.exe> [FLAG_NAME=true|false ...]'.format(sys.argv[0]))
        print('Example: {} notepad.exe DYNAMIC_BASE=false GUARD_CF=false'.format(sys.argv[0]))
        sys.exit(1)

    # Parse the args into a dict of flag_name -> bool of flags to change.
    flag_changes = {}
    for arg in sys.argv[2:]:
        # Split arg into a key/value pair from the format: 'DYNAMIC_BASE=false'
        tmp = arg.split('=', -1)
        flag_name = tmp[0]
        change_val = tmp[1]

        # Check the values given for validity
        if not flag_name.upper() in flags:
            print('[!] Unknown flag name "{}"'.format(flag_name))
            sys.exit(1)
        if change_val.lower() != 'true' and change_val.lower() != 'false':
            print('[!] Unknown value "{}"'.format(change_val))
            sys.exit(1)

        # Add the change to the dict.
        flag_changes[flag_name.upper()] = change_val.lower() == 'true'
    
    # Make the changes.
    pe = pefile.PE(sys.argv[1])
    if len(flag_changes) > 0:
        print('[+] Before changes:')
        print_dll_characteristics(pe)

        do_changes(pe, flag_changes)

        print('[+] After changes:')
        print_dll_characteristics(pe)
        
        # Write the modifications back to the original file.
        data = pe.write()
        pe.close() # Have to close the because it has our file open still.
        with open(sys.argv[1], 'wb+') as f:
            f.write(data)
    else:
        print('[+] DLL characteristics:')
        print_dll_characteristics(pe)

