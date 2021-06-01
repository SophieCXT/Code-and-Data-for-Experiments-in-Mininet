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
  
Under folder `data_attack_traces`: stores attack traces saved with the pattern `attack_trace_n`, where n denotes the flow rate of the trace. Each file data contains two columns: **interarrival time**(ms, time interval between consecutive packets), **flow id**.

Under folder `data_legitimate_traces`: stores attack traces saved with the pattern `trace_m_n`, where m denotes the number of trace, n denotes the subtrace number subtracted from the trace. Each file data contains two columns: timestamp(ms), flow id.


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
Then, please go to [the Configurable Rule Replacement Policies in SDN: Implementation in Open vSwitch](https://github.com/SophieCXT/Configurable-Rule-Replacement-Policies-in-SDN-Implementation-in-Open-vSwitch) for the installation of openvswitch-2.14.0 with the flow table cache replacement policies we implemented.

- clone repository
```
sudo apt-get install git
git config --global user.name "user_name"
git config --global user.email "email_id"
git clone https://github.com/SophieCXT/Attack-Resilience-of-Cache-Replacement-Policies-Code-and-Data-for-Experiments-in-Mininet-.git
```

- set insertion delay and idle timeout
> https://mailman.stanford.edu/pipermail/mininet-discuss/2014-January/003882.html

The ovs-controller is started as a blocking process. So, you will need a dedicated shell to run this process until the time that you want to stop the controller. Or you could run it in the background like you would other Linux commands using ampersand. The procedure can be done like below:
```
Add Delay:
-----------
sudo tc qdisc add dev lo root handle 1: prio
sudo tc qdisc add dev lo parent 1:3 handle 10: netem  delay 500ms
sudo tc filter add dev lo protocol ip parent 1:0 prio 3 u32 match ip dst 127.0.0.2/32 flowid 1:3

Remove the delay:
------------------
sudo tc qdisc del dev lo root netem delay 1

sudo tc qdisc add dev lo parent 1:3 handle 10: netem  delay 100ms
sudo tc qdisc del dev lo parent 1:3 netem delay 500ms

Start ovs-controller:
---------------------
sudo ovs-controller ptcp:6633:127.0.0.2
# if you want to change the idle timeout value, you can use the command below:
sudo ovs-controller --max-idle=500 ptcp:6633:127.0.0.2
```

- starts all of the mininet components and the network
```
$ sudo python new_topology.py
*** Configuring hosts
h1 h2 h3 h4 h5 h6 h7 h8 h9 h10 h11 h12 h13 h14 h15 h16 h17 h18
*** Starting CLI:
mininet>
```

### Experiment Procedure
Before starting the experiments, quick mention that you will have to modify the `flow table size `on the switch, according to what size you require for your experiment.
```
mininet> sh ovs-vsctl -- --id=@ft create Flow_Table flow_limit=1000 overflow_policy=evict -- set Bridge s1 flow_tables=0=@ft
```
 Then you xterm five windows for traffic generation and packet monitor.
 ```
mininet> xterm h17 h2 h18 h18 h1
```

For each xterm window, you enter the following commands accordingly:

- h17: generate attack traffic, run`./mice_craft_packet_attack` or `./elephant_craft_packet_attack`
```
# ./mice_craft_packet_attack 

Enter Source IP : 10.0.0.17
Enter Max Flows: 1000000
Subtraces/attack_trace_0.001000

Num flows per host: ~62500
Packets Processed for send

Press any key to start sending

Sending packets....

```
- h2:  monitor the receiver side network packets and save the captured data into pcap file.
 ```
# ./capturePacket.py 
Enter Sender/Recvr: receiver
Starting Packet Capture! Press Ctrl+C to stop
^CYou pressed Ctrl+C!
Exiting...
Check file "receiver.pcap" for results

```
- h18:  generate attack traffic, run` ./trace_driven_traffic `.
 ```
# ./trace_driven_traffic 
Enter Name of Trace File :trace_2_1.txt

```
- h18: monitor the sender side network packets and save the captured data into pcap file.
 ```
# ./capturePacket.py 
Enter Sender/Recvr: **sender**
Starting Packet Capture! Press Ctrl+C to stop
^CYou pressed Ctrl+C!
Exiting...
Check file "sender.pcap" for results
```
- h1: calculate response time for packets sent by legitimate users. After you are done capturing the packets, you would have to run ./processPackets.py to calculate the response time for each packet sent. You will need this to calculate the hit ratio later.
 ```
# ./processPacket.py 
Calculating response time for packets... 

Done
Check file "logs.txt" for results
root@tbx5027-virtual-machine:2.0-UDP_TRAFFIC# mv logs.txt mice-1-1.txt
```
 
For the trace replay, the “trace_driven_traffic” binary has the code to read from a trace file as well as send the packets out.
 
During the experiments, you can switch the cache replacement policies by the following CLI(commands):
 ```
      # For FIFO: 
mininet> sh ovs-ofctl -O OpenFlow14 mod-eviction-policy s1 FIFO

      # For Q-LRU: 
mininet> sh ovs-ofctl -O OpenFlow14 mod-eviction-policy s1 Q-LRU

      # For LRU: 
mininet> sh ovs-ofctl -O OpenFlow14 mod-eviction-policy s1 LRU
```



Friendly method/references:
Trick: to enlarge the font size in xterm windows, you can press ctrl and right mouth then you can choose the font size. I chose 'large'.

If you encountered the situation below when you want to start mininet environment with our own customized topology:
```
tbx5027@tbx5027-virtual-machine:packet_generation$ sudo python new_topology.py
ovs-vsctl: unix:/usr/var/run/openvswitch/db.sock: database connection failed (No such file or directory)
ovs-vsctl exited with code 1
*** Error connecting to ovs-db with ovs-vsctl
Make sure that Open vSwitch is installed, that ovsdb-server is running, and that
"ovs-vsctl show" works correctly.
You may wish to try "service openvswitch-switch start".
```
You can use the following commands to solve the problem.
```
tbx5027@tbx5027-virtual-machine:packet_generation$ sudo depmod -a
tbx5027@tbx5027-virtual-machine:packet_generation$
tbx5027@tbx5027-virtual-machine:packet_generation$ sudo /etc/init.d/openvswitch-switch start
tbx5027@tbx5027-virtual-machine:packet_generation$
tbx5027@tbx5027-virtual-machine:packet_generation$ sudo /etc/init.d/openvswitch-switch restart
tbx5027@tbx5027-virtual-machine:packet_generation$ sudo /usr/share/openvswitch/scripts/ovs-ctl start
```

For running via screen:
>https://linuxize.com/post/how-to-use-linux-screen/     

For idle timeout value modification:
>http://manpages.ubuntu.com/manpages/trusty/man8/ovs-controller.8.html
 ```
        --max-idle=secs|permanent
              Sets secs as the number of seconds that a flow set up by the controller will remain
              in the switch's flow table without any matching packets being seen.   If  permanent
              is specified, which is not recommended, flows will never expire.  The default is 60
              seconds.

              This option has no effect when -n (or --noflow) is in use (because  the  controller
              does not set up flows in that case).
```
 
# Citation
**cite** contains a attack resilience analysis implementation for our [paper](https://nsrg.cse.psu.edu/files/2020/12/Tian21INFOCOM-Attack-Resilience-of-Cache-Policies.pdf).  If you find this code useful in your research, please consider citing:

    @INPROCEEDINGS{Xie21INFOCOM,
      author = { Tian Xie and Ting He and Patrick McDaniel and Namitha Nambiar},
      title = {Attack Resilience of Cache Replacement Policies},
      booktitle = {IEEE INFOCOM},
      year = {2021},
      month = {May}
    }

This code was tested on an Ubuntu 16.04 system using Mininet, openvswitch-2.14.0.
