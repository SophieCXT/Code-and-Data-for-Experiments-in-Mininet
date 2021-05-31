# ReplacementPolicyMininet
attack-resillence-sdn
# Modifying OpenVSwitch code to make the eviction algorithm configurable

## Tian: questions and tips

### Environment Set Up
- Ubuntu 16.04.07 VM Image
Password:ubuntu (sudo su -)
> https://www.linuxvmimages.com/images/ubuntu-1604/ 

- Install mininet via package
```
sudo apt-get install mininet

# test
sudo mn
mininet> exit

```

- clone repository
```
sudo apt-get install git
git config --global user.name "user_name"
git config --global user.email "email_id"
git clone https://github.com/SophieCXT/ReplacementPolicyMininet.git
```
Error fix: Could not get lock /var/lib/dpkg/lock – open (11: Resource temporarily unavailable)
E: Unable to lock the administration directory (/var/lib/dpkg/), is another process using it?
>https://phoenixnap.com/kb/fix-could-not-get-lock-error-ubuntu
- reinstall the openvswitch we modified
```
cd ovs
sudo ./upgrade_ovs_in_mininet.sh

# debugging
# line 81: aclocal-1.16: command not found
# make: *** [aclocal.m4] Error 127
cd openvswitch2.14.0
sudo apt-get -f install
sudo apt install libtool-bin automake texinfo
sudo apt-get install autotools-dev
autoreconf -f -i

make clean
cd ..
sudo ./u tab(shellfile.sh)
```
To solve: merged with libjpeg 2.0, which removed support for autotools. Now cmake is the only option. 
>https://github.com/mozilla/mozjpeg/issues/314
- create the topology and conduct the amulation
```
# start the switch
sudo /usr/share/openvswitch/scripts/ovs-ctl start
# create topo
cd
cd amulation
sudo mn --topo single,3
>mininet nodes
>mininet xterm h1 h1 h2 h3

## under xterm windows

```
Trick: to enlarge the font size in xterm windows, you can press ctrl and right mouth then you can choose the font size. I chose 'large'.

### Error I encountered

- installation stops with WARNING: 'aclocal-1.16' is missing on your system 
>https://github.com/apereo/mod_auth_cas/issues/97


### Structure of Code Design

- openvswich: replacement policy implementation
ofproto.c:
```
eviction_algorithm:
line 9039 table->eviction_algorithm = 1; //The value denotes which algorithm you are using: 0 as LRU, 1 as FIFO. This initial function intiate the table config





```

In folder: D:\GitHub\attack-resilience-sdn-nnambiar\openvswitch-2.14.0\ofproto\
Or link:
>https://github.com/namitha-nambiar/attack-resilience-sdn-nnambiar/blob/master/openvswitch-2.14.0/ofproto/

- amulation: send/receive pkts and calculate hit ratio
>https://github.com/namitha-nambiar/attack-resilience-scripts-nnambiar/blob/master/UDP_TRAFFIC/2.0-UDP_TRAFFIC/




This file determines which eviction algo you are using.


1.Reason why there has three versions of openvswitch?

2. configuration.m

3. sequence of 
switch

sudo mn --topo = single, 3 

5 windows  'xterm' 

window h3
badscapy.py

h2:(receiver)
capturePacket.py

h1:(sender) two xterm windows
python goodscapy.py will exit when it is done sending packets
another h1 window:
capturePacket.py

When done: one either h1 or h2
processPacket.py

calculate the hit ratio:

```
sudo apt install python-pip
pip install scapy

```

3 hours




## 2/16/2021 code reading from https://github.com/namitha-nambiar/attack-resilience-scripts-nnambiar/blob/master/UDP_TRAFFIC/2.0-UDP_TRAFFIC/packet_generation/

In trace_driven_traffic.cpp, the pcap_open_live() is used to obtain a packet capture handle to look at packets on the network.  device is a string that specifies the network device to open; on Linux systems with 2.2 or later kernels, a device argument of "any" or NULL can be used to capture packets from all interfaces.

>https://man7.org/linux/man-pages/man3/pcap_open_live.3pcap.html


Why we use 'const char *dev = "lo";' in trace driven file instead of 'const char *dev = "h18-eth0";'
and
 'const char *dev = "h17-eth0";' in attacker.

 the loopback interface (lo).

'''
char dev[]="lo"; // set the device to listen on lo, loopback interface
'''


'''

mininet> dump
<Host h1: h1-eth0:10.0.0.1 pid=7287>
<Host h2: h2-eth0:10.0.0.2 pid=7289>
<Host h3: h3-eth0:10.0.0.3 pid=7291>
<Host h4: h4-eth0:10.0.0.4 pid=7293>
<Host h5: h5-eth0:10.0.0.5 pid=7295>
<Host h6: h6-eth0:10.0.0.6 pid=7297>
<Host h7: h7-eth0:10.0.0.7 pid=7299>
<Host h8: h8-eth0:10.0.0.8 pid=7301>
<Host h9: h9-eth0:10.0.0.9 pid=7303>
<Host h10: h10-eth0:10.0.0.10 pid=7305>
<Host h11: h11-eth0:10.0.0.11 pid=7307>
<Host h12: h12-eth0:10.0.0.12 pid=7309>
<Host h13: h13-eth0:10.0.0.13 pid=7311>
<Host h14: h14-eth0:10.0.0.14 pid=7313>
<Host h15: h15-eth0:10.0.0.15 pid=7315>
<Host h16: h16-eth0:10.0.0.16 pid=7317>
<Host h17: h17-eth0:10.0.0.17 pid=7319>
<Host h18: h18-eth0:10.0.0.18 pid=7321>
<OVSSwitch s1: lo:127.0.0.1,s1-eth1:None,s1-eth2:None,s1-eth3:None,s1-eth4:None,s1-eth5:None,s1-eth6:None,s1-eth7:None,s1-eth8:None,s1-eth9:None,s1-eth10:None,s1-eth11:None,s1-eth12:None,s1-eth13:None,s1-eth14:None,s1-eth15:None,s1-eth16:None,s1-eth17:None,s1-eth18:None pid=7326>
<OVSController c0: 127.0.0.1:6633 pid=7280>

'''

[root@pepe libpcap]# /sbin/route 
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
192.168.1.0     *               255.255.255.0   U     0      0        0 eth0
127.0.0.0       *               255.0.0.0       U     0      0        0 lo
default         192.168.1.1     0.0.0.0         UG    0      0        0 eth0

>http://yuba.stanford.edu/~casado/pcap/section2.html

pcap-linux.c: Packet capture interface to the Linux kernel
'''
	/*
	 * Get the interface index of the loopback device.
	 * If the attempt fails, don't fail, just set the
	 * "handlep->lo_ifindex" to -1.
	 *
	 * XXX - can there be more than one device that loops
	 * packets back, i.e. devices other than "lo"?  If so,
	 * we'd need to find them all, and have an array of
	 * indices for them, and check all of them in
	 * "pcap_read_packet()".
	 */
	handlep->lo_ifindex = iface_get_id(sock_fd, "lo", handle->errbuf);
'''

>https://opensource.apple.com/source/libpcap/libpcap-67/libpcap/pcap-linux.c.auto.html


 If you start a controller on your local machine the IP address will be 127.0.0.1. If you want the controller to have another IP address you have to create it on a machine with its own IP address, and thereby be a "remote controller". You cant just say that the local controller should have a remote address, it doesn't work that way.

>http://mininet.org/walkthrough/

You should see the host’s h1-eth0 and loopback (lo) interfaces. Note that this interface (h1-eth0) is not seen by the primary Linux system when ifconfig is run, because it is specific to the network namespace of the host process.

In contrast, the switch by default runs in the root network namespace, so running a command on the “switch” is the same as running it from a regular terminal:


> https://www.youtube.com/watch?v=1x6hy_z84M0&ab_channel=ProwseTech

loopback/ localhost /local computer for test./reduce load don't travel on to the network.

>https://askubuntu.com/questions/247625/what-is-the-loopback-device-and-how-do-i-use-it#:~:text=The%20loopback%20device%20is%20a,running%20on%20the%20local%20machine.

The general concept of loopback is a mechanism through which a message or signal ends up (or loops) back to where it started.


You have to calculate threshold as: threshold = [max(resp times of all hits) + min(response time of all misses)] / 2.

So basically, you have to generate an array like below for sure hits. max_hit will be the largest entry in that array.

Then you have to generate a array like shown below for sure misses. min_miss will be the value of the smallest entry in the array. Then threshold = (max_hit + min_miss) / 2. I have detailed 1 possible way of generating sure hits and misses in the word document I shared with you a while back that has steps to find the average insertion delay on the particular VM you are running the experiment on.

Yes, I am not using your VM currently, thank you so much for letting me use it. It currently has FIFO version of the ovs code installed. The easiest way to uninstall it would be to check with Quinn if he took a snapshot the VM so that if you need to revert to the original state, you can do that easily.

 

Before starting the experiments, quick mention that you will have to modify the flow table size on the switch, according to what size you require for your experiment.

 

For the trace replay, you don’t have to run “craft_packet_legitimate” binary. The “trace_driven_traffic” binary has the code to read from a trace file as well as send the packets out.

 

You would also have to profile/benchmark what the response time for hits and misses are. I already set you a document regarding how to in one of our previous emails.

 

After you are done capturing the packets, you would have to run ./processPackets.py to calculate the response time for each packet sent. You will need this to calculate the hit ratio later.

 

And if you are committing any changes to either of the GitHub repositories, can you pull out a new branch? Just so that our changes don’t overlap with each other’s. I think that’s about it.


tbx5027@tbx5027-virtual-machine:packet_generation$ sudo python new_topology.py
[sudo] password for tbx5027:
Unable to contact the remote controller at 127.0.0.2:6633
*** Configuring hosts
h1 h2 h3 h4 h5 h6 h7 h8 h9 h10 h11 h12 h13 h14 h15 h16 h17 h18
*** Starting CLI:
mininet>


tbx5027@tbx5027-virtual-machine:packet_generation$ sudo python new_topology.py
*** Configuring hosts
h1 h2 h3 h4 h5 h6 h7 h8 h9 h10 h11 h12 h13 h14 h15 h16 h17 h18
*** Starting CLI:
mininet>

method:

`fsdfd`

https://linuxize.com/post/how-to-use-linux-screen/


`        --max-idle=secs|permanent
              Sets secs as the number of seconds that a flow set up by the controller will remain
              in the switch's flow table without any matching packets being seen.   If  permanent
              is specified, which is not recommended, flows will never expire.  The default is 60
              seconds.

              This option has no effect when -n (or --noflow) is in use (because  the  controller
              does not set up flows in that case).`
              


>http://manpages.ubuntu.com/manpages/trusty/man8/ovs-controller.8.html
