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
So you have the network dump such as following
```
[![Picture to Yandex](https://disk.yandex.ru/client/disk/git_conv?display=normal&groupBy=none&order=1&selected=%2Fdisk%2Fgit_conv%2Fdump.jpg&sort=name&view=list&wasAsideAnimated=true&typeClustering=geo&action=null&idAlbum=undefined&selectionSource=listing&idApp=client&dialog=slider&idDialog=%2Fdisk%2Fgit_conv%2Fdump.jpg)](https://disk.yandex.ru/client/disk/git_conv?display=normal&groupBy=none&order=1&selected=%2Fdisk%2Fgit_conv%2Fdump.jpg&sort=name&view=list&wasAsideAnimated=true&typeClustering=geo&action=null&idAlbum=undefined&selectionSource=listing&idApp=client&dialog=slider&idDialog=%2Fdisk%2Fgit_conv%2Fdump.jpg)
```
Then you launch the converter as following:
```
C:/.../python.exe converter.py dump.cap hccap
```
The tool will gen file with name such as handshake_essid_smth.hccap (e.g. handshake_LOL_1501068275.2922.hccap). Then you are to run the hashcat:
```
hashcat64.exe -d 1 -a 0 -m 2500 handshake_LOL_1501068275.2922.hccap rockyou.txt
```
Result:
```
[![Picture to Yandex](https://disk.yandex.ru/client/disk/git_conv?display=normal&groupBy=none&order=1&selected=%2Fdisk%2Fgit_conv%2Fcracked.jpg&sort=name&view=list&wasAsideAnimated=true&typeClustering=geo&action=null&idAlbum=undefined&selectionSource=listing&idApp=client&dialog=slider&idDialog=%2Fdisk%2Fgit_conv%2Fcracked.jpg)](https://disk.yandex.ru/client/disk/git_conv?display=normal&groupBy=none&order=1&selected=%2Fdisk%2Fgit_conv%2Fcracked.jpg&sort=name&view=list&wasAsideAnimated=true&typeClustering=geo&action=null&idAlbum=undefined&selectionSource=listing&idApp=client&dialog=slider&idDialog=%2Fdisk%2Fgit_conv%2Fcracked.jpg)
```
