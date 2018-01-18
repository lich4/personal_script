import os
import threading

def execcmd(cmd):
    r = os.popen(cmd)
    text = r.read();
    r.close()
    return text

def execadbcmd(cmd):
    return execcmd("adb shell " + cmd)


def refreshModules(pid):
    content = execadbcmd("cat /proc/%d/maps" % (pid))
    if content.find("No such file") != -1 or content == "":
        print "pid memory empty"
        return None
    for line in content.splitlines():
        addr_range_str = None
        if line.find(" ") != -1:
            addr_range_str = line.split(" ")[0].split("-")
        if addr_range_str != None:
            addr_begin = int(addr_range_str[0], 16)
            addr_end = int(addr_range_str[1], 16)
            modname = line.split(" ")[-1]
            AddSeg(addr_begin, addr_end, 0, 1, 0, 0)
            SegRename(addr_begin, modname)
            AnalyzeArea(addr_begin, addr_end)
if __name__ == "__main__":
    pid = 3759

   refreshModule(pid)
