def find_utf16_string(addr):
    start = SegStart(addr)
     end = SegEnd(addr)
     addr = start
     while addr < end:
         # get length
         len = 1
         while Name(addr + len) == "":
             len = len + 1
         totalstr = ""
         for i in range(0, len, 2):
             if Word(addr + i) > 0x100:
                 # read an unicode char
                 bytes = GetString(addr + i, 2)
                 try:  # some chinese character not supported by python
                     comm = bytes.decode("utf-16")
                     if type(comm) == unicode:
                         comm = comm.encode("gbk")
                     else:
                         comm = '?'
                 except Exception as e:
                     comm = '?'
             else:
                 # extract as ascii
                 comm = chr(Word(addr + i))
             totalstr = totalstr + comm
         MakeComm(addr, totalstr)
         addr = addr + len




 tofind = ["__ustring"]
 seg = FirstSeg()
 while seg != 0xffffffff:
     if SegName(seg) in tofind:
         find_utf16_string(seg)
     seg = NextSeg(seg) 