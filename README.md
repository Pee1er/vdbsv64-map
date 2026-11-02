Title: MiTAC VdBSv64.sys physical memory access

Vendor: MiTAC Technology Corporation
Product: MiTAC System Service Provider
Component: VdBSv64.sys
SHA-256: 91afa3de4b70ee26a4be68587d58b154c7b32b50b504ff0dc0babc4eb56578f4
MD5: 4353b713487a2945b823423bbbf709bd
SHA-1: 4ffa89f8dbdade28813e12db035cf9bd8665ef72
Size: 26136 bytes
PE timestamp: 2009-07-23 07:42:31 UTC
FileVersion: 21, 1, 1, 0
ProductVersion: 21, 1, 1, 0
OriginalFilename: VdBSv64.sys
Authenticode status: Valid
Signer: CN=Mitac Technology Corporation, OU=Digital ID Class 3 - Microsoft Software Validation v2, O=Mitac Technology Corporation, L=Taipei, S=Taiwan, C=TW
Certificate thumbprint: 805E6E5FC40F9AC8CA15873A8FB7D79FA8B56DA1
Certificate not before: 2008-10-08 00:00:00 UTC
Certificate not after: 2009-10-23 23:59:59 UTC
Device: \\.\VDDev
PDB: d:\app\200905\vddev\virtualdevice\objfre_wlh_amd64\amd64\vddev.pdb

CVE:

Description:
VdBSv64.sys in MiTAC Technology Corporation MiTAC System Service Provider FileVersion 21, 1, 1, 0 (SHA-256 91afa3de4b70ee26a4be68587d58b154c7b32b50b504ff0dc0babc4eb56578f4, 26136 bytes, PE timestamp 2009-07-23 07:42:31 UTC) passes a caller-supplied 64-bit physical address and a caller-supplied length to MmMapIoSpace on buffered IOCTL 0x88892820, keeps the high 32 bits of that address, does not validate the address range, and maps the range as non-cached, which allows a local user to read and write arbitrary physical memory at a caller-chosen physical address and to escalate privileges locally via \\.\VDDev. The length is the caller-supplied access width multiplied by the caller-supplied count. The driver copies the caller byte into that mapping and unmaps it before the call returns. The same IOCTL reads that byte back when the operation selects a read. There is no HalTranslateBusAddress on this path. After the map, the same request falls through into a PCI-config handler; the tested control value made that handler return without accessing I/O ports and without copying its local buffer back over the result. VERSIONINFO CompanyName is MiTAC Technology Corporation, ProductName and FileDescription are MiTAC System Service Provider, FileVersion and ProductVersion are 21, 1, 1, 0, and OriginalFilename is VdBSv64.sys. The Authenticode status is Valid, signed by CN=Mitac Technology Corporation, OU=Digital ID Class 3 - Microsoft Software Validation v2, O=Mitac Technology Corporation, L=Taipei, S=Taiwan, C=TW, thumbprint 805E6E5FC40F9AC8CA15873A8FB7D79FA8B56DA1. On 2026-11-03, on an isolated Windows 10 Enterprise LTSC 2021 virtual machine (10.0.19044.7807), an administrator loaded this file and the service started. The administrator locked one of its own pages at physical address 0xbcd29000 and did not send IOCTL 0x88892820. Local account aida-low, a member of Users and not a member of Administrators, opened \\.\VDDev and sent IOCTL 0x88892820 for that address with width 1 and count 1, once to write and once to read. aida-low wrote 0x5A and read 0x5A back, then wrote 0xA5 and read 0xA5 back. The administrator read the first byte of that physical page and saw 0x5A, then 0xA5. The test did not show a crash. The device security descriptor was O:BAG:SYD:(A;;0x1201bf;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;RC)S:AI(ML;;NW;;;LW). Everyone (WD) has access mask 0x1201bf, which includes FILE_READ_DATA and FILE_WRITE_DATA.

Suggested fix: on IOCTL 0x88892820, map only a physical address chosen inside the driver, and limit access to \\.\VDDev to Administrators and SYSTEM.
