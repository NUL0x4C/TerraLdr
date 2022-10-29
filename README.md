
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



### Thanks For:
- https://offensivedefence.co.uk/posts/ntcreateuserprocess/
- https://github.com/vxunderground/VX-API



