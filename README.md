# Attack Resilience of Cache Replacement Policies: Code and Data for Experiments in Mininet

**cite** contains a attack resilience analysis implementation for our [paper](https://nsrg.cse.psu.edu/files/2020/12/Tian21INFOCOM-Attack-Resilience-of-Cache-Policies.pdf).  If you find this code useful in your research, please consider citing:

    @INPROCEEDINGS{Xie21INFOCOM,
      author = { Tian Xie and Ting He and Patrick McDaniel and Namitha Nambiar},
      title = {Attack Resilience of Cache Replacement Policies},
      booktitle = {IEEE INFOCOM},
      year = {2021},
      month = {May}
    }

This code was tested on an Ubuntu 16.04 system using Mininet, openvswitch-2.14.0.

### Structure of Code Design
We have plenty of files in this part, details are explained as following:

Under folder `code`:
- new_topology.py: The "new_topology" custom starts all of the mininet components and the network. It is a 18-host network with one attack host, one active legitimate host, and 16 passive legitimate hosts only receiving packets, all connected through an Open vSwtich under the control of an OpenFlow-Test Controller.
- folder `calculate_hit_ratio`: 
  - calculate_hit_ratio.m: function to calculate the hit ratio of legitimate users under mice/medium/elephant flow attack by the given logs(response time of each packets).
  - hybrid_calculate_hit_ratio.m: function to calculate the hit ratio of legitimate users under hybrid attack by the given logs(response time of each packets).
  - hybrid_plot_mininet_data.m: plot (c) of   Figure Experiment results on DoS attack in Mininet with total attack rate1000(unit: packets per 100 ms) (solid: experiment; dashed: simulation) in our [paper](https://nsrg.cse.psu.edu/files/2020/12/Tian21INFOCOM-Attack-Resilience-of-Cache-Policies.pdf).
  - plot_mininet_data.m: plot (a-b) of   Figure Experiment results on DoS attack in Mininet with total attack rate1000(unit: packets per 100 ms) (solid: experiment; dashed: simulation) in our [paper](https://nsrg.cse.psu.edu/files/2020/12/Tian21INFOCOM-Attack-Resilience-of-Cache-Policies.pdf).
  
- folder `monitor`: 
  - capturePacket.py: capture packets of the designed network into pcap files.
  - processPacket.py: calculate response time for packets sent by legitimate users.
- folder `traffic_generation`: to generate the legitimate traffic and attack traffic according to the configuration in our [paper](https://nsrg.cse.psu.edu/files/2020/12/Tian21INFOCOM-Attack-Resilience-of-Cache-Policies.pdf).

  - craft_packet.h: headfile of crafting packets.
  - craft_packet_attack.cpp: generate attack trace file or send the packets according to a given attack trace file.
  - trace_driven_traffic.cpp: generate the legitimate traffic according to the trace txt file in folder `data_legitimate_traces`. (under same timestamp and flow id)
  
Under folder `data_attack_traces`: stores attack traces saved with the pattern `attack_trace_n`, where n denotes the flow rate of the trace. Each file data contains two columns: time interval(ms), flow id.

Under folder `data_legitimate_traces`: stores attack traces saved with the pattern `trace_m_n`, where m denotes the number of trace, n denotes the subtrace number subtracted from the trace. Each file data contains two columns: timestamp(ms), flow id.


- amulation: send/receive pkts and calculate hit ratio
>https://github.com/namitha-nambiar/attack-resilience-scripts-nnambiar/blob/master/UDP_TRAFFIC/2.0-UDP_TRAFFIC/




### Environment Set Up
- Ubuntu 16.04.07 VM
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
git clone https://github.com/SophieCXT/Attack-Resilience-of-Cache-Replacement-Policies-Code-and-Data-for-Experiments-in-Mininet-
```



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



In trace_driven_traffic.cpp

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
