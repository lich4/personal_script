# idascript    by lichao890427
These scripts are all wrote be me, when encountered with difficult tasks, also ease things for you.
<!-- TOC -->

- [idascript    by lichao890427](#idascript----by-lichao890427)
    - [1.add_xref_for_macho.py](#1add_xref_for_machopy)
    - [2.read_unicode.py](#2read_unicodepy)
    - [3.add_info_for_androidgdb.py](#3add_info_for_androidgdbpy)
    - [4.trace_instruction.py](#4trace_instructionpy)
    - [5.detect_ollvm.py](#5detect_ollvmpy)
    - [6.add_block_for_macho.py](#6add_block_for_machopy)
    - [7.ida_utils.py](#7ida_utilspy)

<!-- /TOC -->

## 1.add_xref_for_macho.py
		Description:
		  When you deal with macho file with ida, you'll find out that it's not easy to find Objc-Class 
		member function's caller and callee, (because it use msgSend instead of direct calling 
		convention), so we need to make some connection between the selector names and member function 
		pointers, it's what my script just do ^_^
		Usage: 
		  just load script from ida, after some output then you can got what you want
		Feature:	
		  1. connect seletors with member function pointer 
		  2. get current member function's caller  
![image](https://github.com/lichao890427/personal_script/blob/master/IDA_Script/screenshots/add_xref_for_macho_1.png)
		  3. get member function where current 'msgSend' lead to  
![image](https://github.com/lichao890427/personal_script/blob/master/IDA_Script/screenshots/add_xref_for_macho_2.png)

## 2.read_unicode.py
		Description:
		  When there is chinese unicode character in programe, due to python's shortage, ida could not 
		recongnized them correctly, it's what my script just do ^_^, apply to many circumstance
		Usage: 
		  When deal with macho file, you only need to run the script, and it will automatically find 
		unicode string in segment named "__ustring"; and if deal with other type, you need to  addtionally 
		call function 'find_utf16_string(addr)' to find them
![image](https://github.com/lichao890427/personal_script/blob/master/IDA_Script/screenshots/read_unicode.png)
		Notice: 
		  Due to the disadvantable of python2 itself, there still many characters could not be shown  

## 3.add_info_for_androidgdb.py
		Description:
		  When you debug android with IDA and gdbserver, you'd find that the module list and segment is
		empy, while we can read info from /proc/[pid]/, it's what my script just do ^_^  

## 4.trace_instruction.py
		Description:
		  this script is to trace instruction stream in one run   

## 5.detect_ollvm.py
		Description:
		  this script is to detect ollvm and fix it in some extent, apply to android and ios, enjoy ^_^
		  function "try_trace_fix_ollvm" used to fix ollvm
		  function "check_ollvm" used to find ollvm in android so file
		  function "find_ios_ollvm_branches" used to find ollvm in macho file  
  
## 6.add_block_for_macho.py
		Description:
		  this script is used to analysis block structure exist in macho file, target NSConcreteStackBlock/
		  NSConcreteGlobalBlock currently, also contain some wonderful skills    
![image](https://github.com/lichao890427/personal_script/blob/master/IDA_Script/screenshots/add_block_for_macho.png)
		  
## 7.ida_utils.py
		Description:
		  some useful function wrotten before