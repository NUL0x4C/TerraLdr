
<h2 align="center">
TerraLdr: A Payload Loader Designed With Advanced Evasion Features
</h2>

</br>

### Details: 
- no crt functions imported
- syscall unhooking using [KnownDllUnhook](https://github.com/ORCx41/KnownDllUnhook)
- api hashing using Rotr32 hashing algo
- payload encryption using rc4 - payload is saved in .rsrc
- process injection - targetting 'SettingSyncHost.exe'
- ppid spoofing & blockdlls policy using NtCreateUserProcess 
- stealthy remote process injection - chunking
- using debugging & NtQueueApcThread for payload execution 


### Usage:
- use [GenerateRsrc](https://github.com/ORCx41/TerraLdr/tree/main/Helper/GenerateRsrc) to update [DataFile.terra](https://github.com/ORCx41/TerraLdr/blob/main/Terra/DataFile.terra) that'll be the payload saved in the .rsrc section of the loader


### Thanks For:
- https://offensivedefence.co.uk/posts/ntcreateuserprocess/
- https://github.com/vxunderground/VX-API



### Profit:
![image](https://user-images.githubusercontent.com/111295429/198824658-b9123d21-045a-43f7-8235-c08e14a26ff3.png)
![havoc](https://user-images.githubusercontent.com/111295429/198824884-ba516101-0b02-4ff7-94fb-65ce692e02ce.jpg)




</br>
</br>



<h4 align="center">
Tested with cobalt strike && Havoc on windows 10
</h4>
