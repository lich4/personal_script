from ipykernel.kernelapp import IPKernelApp
from .kernel import CppKernel
IPKernelApp.launch_instance(kernel_class=CppKernel)
