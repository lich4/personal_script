# C/C++ kernel for Jupyter

## What is Jupyter?
It's a wonderful notebook for coder. Please goto this website and search yourself  
<https://github.com/jupyter/jupyter>

## Why I wrote this?
* Other C/C++ kernels available need Python3 and non-Windows system, while I only have Python2.7 installed
* They also need gcc to be exist while non exist in Windows system.
* I want try to development a jupyter kernel myself, and make a simplest c++ kernel for my personal use

## How do I install?
* download clang from <http://releases.llvm.org/download.html> and install to any directory in $PATH 
* git clone it
* python setup.py or pip install .
* python jupyter_cpp_kernel/install_cpp_kernel
* done

## How does it look like?
If you successfully install my kernel, then you can run following code in your Jupyter Nnotebook  

```cpp
#include <stdio.h>
int main() {
    printf("helloworld");
}
```

    helloworld


```cpp
#include <iostream>
using namespace std;

int main() {
    std::cout<<"helloworld"<<endl;
}
```

    helloworld
