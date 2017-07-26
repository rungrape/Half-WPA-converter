# 1.Why the hell do I need this?
You are, if it's necessary to crack your neighbour's WIFI (joking) with the help of hashcat. Conversion to hccap format would be suitable for fan of vintage stuff such as hashcat 3.0, transformation from hccap to hccapx is for haters of the bullshit.
Also you are, if you're interested in Half-WPA cracking with the help of hashcat.

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
```
python converter.py input.inputformat outputformat / python converter.py input.inputformat outputformat essid
```
