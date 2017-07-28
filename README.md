# 1.Summary.
Converter, which is adapted for transforming half-wpa handshakes from .cap .hccap/.hccapx format

# 2.Installation and usage.
Install python interpreter of version 3.6 from one of the following links:
* https://www.python.org/downloads/source/ (Linux)
* https://www.python.org/downloads/windows/ (Windows)
* https://www.python.org/downloads/mac-osx/ (Mac-OSx)
* https://www.python.org/download/other/ (Oter ones)
Python3 only.
You are to install the pcapfile module (via pip or by any other convenient way for you) to guarantee the correct work of the tool.
```
pip install pypcapfile
```
Then you are able to use the converter. The possible commands:
1. Create hashcat file only for specified ESSID.
```
../Scripts/python.exe converter.py inputfile.cap hccap ESSID  
```
2. Create hashcat files for each ESSID, which could be founded in input files.
```
../Scripts/python.exe converter.py inputfile.cap hccap
```
Look at launch example paragraph if you have any questions about program usage.

# 3.Tool's abilities and properties.
Format conversion:
* cap -> hccap (usage: python converter.py input.cap hccap / python converter.py input.cap hccap essid)
* cap -> hccapx (usage: python converter.py input.cap hccapx / python converter.py input.cap hccapx essid)
* hccap -> hccapx (usage: python converter.py input.hccap hccapx)

# 4.Launch example.
So you have the network dump such as following

![dump](https://pp.userapi.com/c841227/v841227628/c1f4/MNdDDHmRcBo.jpg)


Then you launch the converter as following:
```
C:/.../python.exe converter.py dump.cap hccap
```
The tool will gen file with name such as handshake_essid_smth.hccap (e.g. handshake_LOL_1501068275.2922.hccap). Then you are to run the hashcat:
```
hashcat64.exe -d 1 -a 0 -m 2500 handshake_LOL_1501068275.2922.hccap rockyou.txt
```
Result:

![result](https://pp.userapi.com/c840129/v840129682/16ced/mWGJSW5SlIo.jpg)
