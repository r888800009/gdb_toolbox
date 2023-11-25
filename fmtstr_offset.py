#!/usr/bin/env python3

import gdb

class fmtstr_offset(gdb.Command):
    """auto find offset for format string attack"""
    def __init__(self):
        super(self.__class__, self).__init__("fmtstr_offset", gdb.COMMAND_USER)
        self.verbose = False
        self.debug = False
        self.max_offset = 50

    def invoke(self, args, from_tty):
        print("for correct result, please make sure your rip in the `call` instruction") 
        # todo: check the rip in the `call` instruction and the `call` instruction is `call printf` or else
        if 'help' in args or '-h' in args:
            print("usage: fmtstr_offset [-v] [-d] [-l max_offset]")
            print("options:")
            print("\t-v: verbose")
            print("\t-d: debug")
            print("\t-l max_offset: set max offset, it would be 8 * max_offset")
            return
        
        self.debug = '-d' in args
        self.verbose = '-v' in args or self.debug
        self.max_offset = 50

        if '-l' in args:
            self.max_offset = int(args.split('-l')[1].split()[0])
            print(f"set max offset to {self.max_offset}")

        result_dict = {}

        for i in range(6, self.max_offset):
            fmtstr = f"%{i}$p"
            cmd = f'x/a $rsp+{(i - 6) * 8}'
            val = gdb.execute(cmd, to_string=True, from_tty=False).split(":")[1].strip()
            check_type = self.check_value_type(val)
            if self.verbose:
                print(f"{fmtstr : <10} {val} {check_type}")

            if check_type != "unknown":
                result_dict[check_type] = result_dict.get(check_type, []) + [fmtstr]

        print("result:")
        for k, v in result_dict.items():
            print(f"{k}:")
            print(f"\t{v}")
    
    def get_value_by_addr(self, addr):
        return gdb.execute(f'x/a {addr}', to_string=True, from_tty=False).split(":")[1].strip()
    
    def get_canary(self):
        return gdb.execute("x/a $fs_base+0x28", to_string=True, from_tty=False).split(":")[1].strip()

    def find_offset(self, addr):
        if type(addr) == str:
            addr = int(addr, 16)
        elif type(addr) != int:
            raise Exception("addr type error")
    
        image_base = {}

        vmmap = gdb.execute("i proc mappings", to_string=True, from_tty=False).splitlines()
        # drop the first four lines
        vmmap = vmmap[4:]
        for line in vmmap:
            line = line.strip().split()
            if self.debug:
                print(line)
            if len(line) < 6:
                continue

            start, end, size, offset, perm, path = line
            start = int(start, 16)
            end = int(end, 16)

            if path not in image_base:
                image_base[path] = start

            if addr >= start and addr <= end:
                return path, addr - image_base[path]
        
        if self.debug:
            for k, v in image_base.items():
                print(f"{k}: {hex(v)}")

        return None, None

    def check_value_type(self, val):

        if len(val.split()) > 1:
            val = val.split()[0]
        vmmap_path, offset = self.find_offset(val)
        if val == self.get_canary():
            return "canary"
        elif vmmap_path != None:
            return f"{vmmap_path}+{hex(offset)}"
        else:
            return "unknown"
        
    
fmtstr_offset()