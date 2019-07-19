#-*- coding:utf-8 -*-
from tkinter import *
from tkinter.scrolledtext import ScrolledText

def parse(textin, textout):
  input = textin.get(0.0, END)
  d = dict()
  for line in input.split('\n'):
    if line.find('=') == -1:
      continue
    k, v = tuple(line.split('='))
    k = k.strip()
    v = v.strip().replace(';', '')
    try:
      if k.find('[') != -1:
        k = int(k.split('[')[1].split(']')[0])
        if v.startswith('0x') or v.startswith('0X'):
          v = int(v, base=16)
        else:
          v = int(v)
        d[k] = v
      elif k.find('_') != -1:
        k = int(k.split('_')[1], base=16)
        if v.startswith('0x') or v.startswith('0X'):
          v = int(v, base=16)
        else:
          v = int(v)
        d[k] = v
      elif k.startswith('v'):
        k = int(k.replace('v', ''))
        if v.startswith('0x') or v.startswith('0X'):
          v = int(v, base=16)
        else:
          v = int(v)
        d[k] = v
    except Exception as e:
      textout.insert(INSERT, str(e))
      return
  s = ''
  for item in sorted(d.keys()):
    v = d[item]
    while v != 0:
      s += chr(v & 255)
      v = (v >> 8)
  textout.insert(INSERT, s)

root = Tk()
textin = ScrolledText(root)
textin.pack()
btn = Button(root, text="parse")
btn.pack()
textout = ScrolledText(root)
textout.pack()
btn.bind("<Button-1>", lambda event:parse(textin, textout))
root.mainloop()