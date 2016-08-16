#!/usr/bin/env python

"""njrat_wrapper_decode.py: Stupid encoder used for wrapping some njRat samples ITW"""

__author__ = "Tim 'diff' Strazzere"
__copyright__  = "Copyright 2016, Red Naga"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "strazz@gmail.com"


# Reversed from the sqdsqdsqdqdssqdsqdsqdsqdsqdsq.MicrosoftMicrosoftMicrosoftMicrosoftMicrosoft1 function (so legit...)
# Contends that are "deobfuscated" here are piped reflectively and executed via;
# AppDomain.CurrentDomain.Load(Convert.FromBase64String(junk)).EntryPoint.Invoke((object) null, (object[]) null);

output = ''
data = 'PUT THE PAYLOAD HERE'
length = len(data)
mod_len = length % 2
half_len = length / 2
start = (mod_len + half_len)
# This isn't 1, as it is in .Net since we don't have strings/arrays starting at 1
while start >= 0:
    if mod_len == 0:
        # str += Strings.Mid(sInput, checked (Start + num2), 1);
        output += data[start + half_len:start + half_len + 1]
    output += data[start:start + 1]
    if mod_len == 1 and start != 1:
        output += data[start + half_len:start + half_len + 1]
    start += -1

print output