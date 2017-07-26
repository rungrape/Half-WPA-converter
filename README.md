# 1.Why do I need this?
You are, if it's necessary to find AP's (which uses WPA authentication method) password with the help of hashcat, if you have only WPA half-handshake. Conversion to hccap format would be suitable for using hashcat_3.0, transformation from hccap to hccapx is for hashcat_3.6.0 users.

# 2.Install requirements.
You are to install the pcapfile module (via pip or by any other convenient way for you) to guarantee the correct work of the tool.
Ex.:
```
pip install pypcapfile
```

# 3.Tool's abilities and properties.
Format conversion:
* cap -> hccap (usage: python converter.py input.cap hccap / python converter.py input.cap hccap essid)
* cap -> hccapx (usage: python converter.py input.cap hccapx / python converter.py input.cap hccapx essid)
* hccap -> hccapx (usage: python converter.py input.hccap hccapx)

# 4.Launch.
So you have the network dump such as following

![dump](https://pp.userapi.com/c840129/v840129682/16ce6/zprZmfwFt6U.jpg)


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
