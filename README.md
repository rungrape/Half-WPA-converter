# 1.Summary.
Converter, which is adapted for transforming half-wpa handshakes from .cap to .hccap/.hccapx format. You just need to listen for WPA2 probes from any client within range, and then raise an Access Point with some ESSID. Though the authentication will fail, there is enough information in the failed handshake to run bruteforce attack with hashcat. So, you don't need the two last packets of EAPOL handshake to start bruteforce attack of the password.
![handshake](https://pp.userapi.com/c639627/v639627126/4bddb/uC0MZML0vTk.jpg)

# 2.Installation and usage.
Install python interpreter using one of the following links:
* https://www.python.org/downloads/source/ (Linux)
* https://www.python.org/downloads/windows/ (Windows)
* https://www.python.org/downloads/mac-osx/ (Mac-OSx)
* https://www.python.org/download/other/ (Other ones)

Install pip for Python3 (for Linux only).
```
sudo apt-get install python3-setuptools
sudo easy_install3 pip
```

You are to install the pcapfile module to guarantee correct work of the tool.
```
pip install -r requirements.txt
```
Then you are able to use the converter. The possible commands:
1. Create .hccap file only for specified ESSID.
```
python.exe converter.py inputfile.cap hccap ESSID  
```
2. Create .hccap files for each ESSID, which could be founded in input files.
```
python.exe converter.py inputfile.cap hccap
```
3. Create .hccapx file from .hccap.
```
python.exe converter.py inputfile.hccap hccapx
```
4. Create .hccapx file only for specified ESSID.
```
python.exe converter.py inputfile.cap hccapx ESSID
```
5. Create .hccapx files for each ESSID, which could be founded in input files.
```
python.exe converter.py inputfile.cap hccapx
```
Look at launch example paragraph if you have any doubts about program usage.

# 3.Tool's abilities and properties.
Format conversion:
* cap -> hccap (usage: python converter.py input.cap hccap / python converter.py input.cap hccap essid)
* cap -> hccapx (usage: python converter.py input.cap hccapx / python converter.py input.cap hccapx essid)
* hccap -> hccapx (usage: python converter.py input.hccap hccapx)

# 4.Launch example.
So you have the network dump such as following

![dump](https://pp.userapi.com/c639627/v639627975/35b8c/rw9vSLp1psc.jpg)


Then you launch the converter as following:
```
python.exe converter.py dump.cap hccap
```
The tool will gen file with name such as handshake_essid_smth.hccap (e.g. handshake_LOL_1501068275.2922.hccap). Then you are to run the hashcat:
```
hashcat64.exe -d 1 -a 0 -m 2500 handshake_LOL_1501068275.2922.hccap rockyou.txt
```
Result:

![result](https://pp.userapi.com/c840129/v840129682/16ced/mWGJSW5SlIo.jpg)
