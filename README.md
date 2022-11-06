
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


### Notes:
  - "SettingSyncHost.exe" isnt found on windows 11 machine, while i didnt tested with w11, its a *must* to change the process name to something else before testing
  - it is possibly better to compile with "ISO C++20 Standard (/std:c++20)"

### Profit:
![ph2](https://user-images.githubusercontent.com/111295429/198824933-101d0641-d8b3-4cef-812d-0834cdb8cf0f.png)
![havoc](https://user-images.githubusercontent.com/111295429/198824884-ba516101-0b02-4ff7-94fb-65ce692e02ce.jpg)


### Demo (by [@ColeVanlanding1](https://twitter.com/ColeVanlanding1)) :
[![EmpireC2 TerraLDR vs AntiVirus](https://user-images.githubusercontent.com/111295429/199412734-de802fa6-0abc-4772-91de-9ca51f565bb1.png)](https://www.youtube.com/watch?v=z8imK4YyrtE "EmpireC2 TerraLDR vs AntiVirus")


</br>
</br>



<h4 align="center">
Tested with cobalt strike && Havoc on windows 10
</h4>
