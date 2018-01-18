# coding=utf-8

import os
import platform
import subprocess
import tempfile
from ipykernel.kernelbase import Kernel

WIN = 0
LINUX = 1
MAC = 2


class CppKernel(Kernel):
    implementation = 'jupyter_cpp_kernel'
    implementation_version = '1.0'
    language = 'c++'
    language_info = {'name': 'cpp',
                     'mimetype': 'text/plain',
                     'file_extension': 'cpp'}
    banner = "Jupyter C++ Kernel\n"

    def __init__(self, *args, **kwargs):
        super(CppKernel, self).__init__(*args, **kwargs)
        self.compiler_path = None
        self.systype = -1  # 0:win 1:linux 2:mac
        if not self.find_compiler():
            print("Cannot find compiler!!!")
        else:
            print("Use " + self.compiler_path)

    def do_execute(self, code, silent, store_history=True,
                   user_expressions=None, allow_stdin=False):
        self.compile_and_get_output(code)
        return {'status': 'ok', 'execution_count': self.execution_count, 'payload': [], 'user_expressions': {}}

    def do_shutdown(self, restart):
        pass

    def find_compiler(self):
        '''
        Find C/C++ compiler in $PATH
        :param:
        :return:
        '''
        if self.compiler_path is not None:
            return True
        if platform.system() == "Darwin":
            filename = "clang"
            splitter = ":"
            connector = "/"
            self.systype = MAC
        elif platform.system() == "Linux":
            filename = "clang"
            splitter = ":"
            connector = "/"
            self.systype = LINUX
        elif platform.system() == "Windows":
            filename = "clang.exe"
            splitter = ";"
            connector = "\\"
            self.systype = WIN
        for path in os.environ["PATH"].split(splitter):
            if not path.endswith(connector):
                path += connector
            if not os.path.exists(path + filename):
                continue
            self.compiler_path = path + filename
            print("Select " + self.compiler_path + " as compiler")
            return True
        print("Cannot find valid C/C++ compiler in PATH env")
        return False

    def compile_and_get_output(self, code):
        print("input code: " + code)
        if self.compiler_path == None and not self.find_compiler():
            return "Cannot find compiler!!!"
        infilepath = tempfile.NamedTemporaryFile().name + ".cpp"
        outfilepath = tempfile.NamedTemporaryFile().name
        infilefd = open(infilepath, "w")
        if infilefd != -1:
            infilefd.write(code)
            infilefd.close()
        if self.systype == WIN:
            outfilepath += ".exe"
        try:
            cmdps = subprocess.Popen([self.compiler_path, infilepath, "-o", outfilepath], stderr=subprocess.PIPE)
            cmdps.wait()
            compile_result = cmdps.stderr.read()
            if compile_result != "":
                self.send_response(self.iopub_socket, 'stream', {'name': 'stderr', 'text': compile_result})
                return
            try:
                os.chmod(os.path.abspath(outfilepath), os.stat.S_IXUSR)
            except Exception as e:
                print(e.message)
            exeps = subprocess.Popen(outfilepath, stdout=subprocess.PIPE)
            exeps.wait()
            execute_result = exeps.stdout.read()
            print(execute_result)
            self.send_response(self.iopub_socket, 'stream', {'name': 'stdout', 'text': execute_result})
        except Exception as e:
            print(e.message)

            # print(CppKernel().compile_and_get_output('#include<stdio.h>\nint main(){printf("ok");return 0;}'))