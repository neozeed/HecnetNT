This is the bridge program ported to Windows, version 1.0

A few notes:
The original version can always be found at:
http://www.update.uu.se/~bqt/bridge.tar

I'm using Visual Studio 2003 to build this version.  I have tested this on Windows NT 4.0 Terminal Server, Windows 2000 Professional, and Windows 7.

Setting up HECnetNT is similar to the same process as UNIX (Linux/Mac OSX/*BSD..etc) with a few extra possiblities.

First is that this version support LZSS compression, while the classical HECnet does not do any compression at all.  The next thing is that HECnetNT supports more frame types (although I only recommend using decnet&ipx as wanted).

To start you will need a configuration file.

A simple configuration will permit 2 networks to be bridged together with HECnetNT.

--HOST A------------------------------------------------------------
[bridge]
update HOSTB:5501
vmnet5	\Device\NPF_{98F44EE6-626B-48CB-952D-9C890F44A4A5}


[decnet]
update
vmnet5

--HOST B------------------------------------------------------------
[bridge]
update HOSTA:5500
vmnet5	\Device\NPF_{98F44EE6-626B-48CB-952D-9C890F44A4A5}


[decnet]
update
vmnet5
--------------------------------------------------------------------

This example requires that HOST A be able to communicate to HOST B on UDP port 5501, and HOST B to communicate with HOST A on UDP port 5500.  If the HECnetNT node is behind a firewall, you will have to forward the UDP port to the HECnetNT host.  Also if it is over the internet, you'll need to know the external IP address, or hostname relevant for that host.

The next thing you need to know is the ethernet adapter's "NPF" name.  I've included the utility ethlist (with code taken from the SIMH project) which will print out the names of available adapters installed in computer.

--sample output-----------------------------------------------------
  Number       NAME                                     (Description)
  0  \Device\NPF_{0C6D7EF7-30D4-4AB0-AB3E-AC6EAB42B9C5} (VMware Network AdapterVMnet2)
  1  \Device\NPF_{1A17F8DF-DC65-420E-9A7A-3F8D22EC0D12} (VMware Network AdapterVMnet6)
  2  \Device\NPF_{5A889C62-8180-4DB5-8FFE-3B6B8B9DFFAF} (VMware Network AdapterVMnet7)
  3  \Device\NPF_{A6B89C5C-C28C-424E-B795-F90F97FA0FE7} (VMware Network AdapterVMnet8)
  4  \Device\NPF_{21D7D0D4-1A8B-4777-B05D-284C67D94180} (Local Area Connection)
  5  \Device\NPF_{98F44EE6-626B-48CB-952D-9C890F44A4A5} (VMware Network AdapterVMnet5)
  6  \Device\NPF_{D294A70E-07B3-4CA8-A88D-D6C392696E99} (VMware Network AdapterVMnet1)
  7  \Device\NPF_{F746872D-7687-4867-958C-96A62BA5E284} (VMware Network AdapterVMnet3)
  8  \Device\NPF_{D6726593-C290-4821-8D43-D180CF5631BA} (VMware Network AdapterVMnet4)
Press Enter to continue...
--------------------------------------------------------------------

In this example you can see how vmnet5 is selected.  Also only the decnet protocol is going to be forwarded.  Additionally the traffic is going to use the legacy/uncompressed method.

To support compression, you would alter each bridge.conf from [bridge] to [cbridge].  You can even mix both types, if you are connecting to a legacy connection, but want to connect compressed connections as well.

A much more extreme example is as follows:

ntts	is a WindowsNT 4.0 server using the compressed bridge
ipx1	is an uncompressed IPX Ethernet_II client
ipx2	is a compressed IPX Ethernet_II client
legacy	is an uncompressed Linux box with the original HECnet software.
vmnet5	is another NIC in the same system, that is using another instance of HECnetNT

In this example, all traffic is going through the first bridge.  Each group is added to either bridge or cbridge depending on if they need compression.  Then they are added by requirements to either the decnet protocol or the ipx protocol.  Each of the configs is below:

-5500---------------------------------------------------------------
[cbridge]
ntts	192.168.0.233:5500
ipx2	127.0.0.1:5503

[bridge]
vmnet5	127.0.0.1:5501
ipx1	127.0.0.1:5502
vmnet4  \Device\NPF_{D6726593-C290-4821-8D43-D180CF5631BA}
legacy	192.168.0.135:5500

[decnet]
vmnet4
vmnet5
ntts
legacy

[ipx]
ipx1
ipx2

--5501--------------------------------------------------------------
[bridge]
update localhost:5500
vmnet5	\Device\NPF_{98F44EE6-626B-48CB-952D-9C890F44A4A5}


[decnet]
update
vmnet5


-5502---------------------------------------------------------------
[bridge]
vmnet6 \Device\NPF_{1A17F8DF-DC65-420E-9A7A-3F8D22EC0D12} 
update localhost:5500


[ipx]
vmnet6
update

-5503---------------------------------------------------------------
[cbridge]
vmnet7 \Device\NPF_{5A889C62-8180-4DB5-8FFE-3B6B8B9DFFAF}
update localhost:5500


[ipx]
vmnet7
update

-ntts---------------------------------------------------------------
[cbridge]
local	\Device\NPF_NDISLoop2
update	192.168.0.12:5500

[decnet]
local
update

-legacy--------------------------------------------------------------
[bridge]
local eth1
update 192.168.0.12:5500

[decnet]
local
update






*NOTES on IPX
Only the Ethernet_II frame type is supported.  In your NetWare client you'll need to specify the frame type.. IPX ODI clients have a net.cfg that needs to look something like this:

-net.cfg-------------------------------------------------------------
Link Support
	buffers 8 1600

Link Driver PCNTNW
	Frame Ethernet_II

NetWare DOS Requester
	FIRST NETWORK DRIVE = F 
--------------------------------------------------------------------


I've tested the IPX with Novell Netware 3.12, Doom v1.1 and Quake.  I HIGHLY recommend using cbridges with IPX, as an example, DOOM traffic can be compressed 80%.