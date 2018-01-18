from setuptools import setup

setup(name='jupyter_cpp_kernel',
      version='1.2.1',
      description='Minimalistic C++ kernel for Jupyter',
      author='Lichao890427',
      author_email='lichao.890427@163.com',
      url='https://github.com/lichao890427/jupyter-cpp-kernel/',
      download_url='https://github.com/lichao890427/jupyter-cpp-kernel/',
      packages=['jupyter_cpp_kernel'],
      scripts=['jupyter_cpp_kernel/install_cpp_kernel'],
      keywords=['jupyter', 'notebook', 'kernel', 'c++']
      )
