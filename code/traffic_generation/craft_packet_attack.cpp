/**
 * File: flooder.c
 *
 * Description   : Craft packets.
 * Created By    : Tian Xie, Namitha Nambiar
 * Date          : Sep 2020
 * Last Modified : May 2021
 */

/* Include Files  */
#include "craft_packet.h"
#include "math.h"
#include <unordered_map>
#include <vector>
#include <stack>
#include <algorithm>
#include <chrono>
#include <thread>
#include <signal.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <list>
#include <ctime>

using namespace std;

#define MAX_FLOWS 1000000
#define MAX_SEQ   50
#define MAX_CYCLES 6000.0 // sec
#define MAX_LEGITIMATE_HOSTS 16
#define MAX_PORT_NUM 62500
#define CONSTANT_TRAFFIC 0

/* Comment to send packets. Uncomment to generate trace and save to file  */
//#define GENERATE_TRACE 1


/* Global Variables */
packet_t packets[MAX_FLOWS][MAX_SEQ];
float lambda_background[MAX_FLOWS];
list <std::pair<uint32_t, double>> packet_send_time;
vector<uint32_t> seq_cnt(MAX_FLOWS, 0); // Maintain a counter for each flow to track next seq
bool is_attacker = true;

uint8_t mac_addrs[][6] = {{0x0a,0x55,0x76,0x65,0xcd,0xf0},
                          {0x0a,0x55,0x76,0x65,0xcd,0xf1},
                          {0x0a,0x55,0x76,0x65,0xcd,0xf2},
                          {0x0a,0x55,0x76,0x65,0xcd,0xf3},
                          {0x0a,0x55,0x76,0x65,0xcd,0xf4},
                          {0x0a,0x55,0x76,0x65,0xcd,0xf5},
                          {0x0a,0x55,0x76,0x65,0xcd,0xf6},
                          {0x0a,0x55,0x76,0x65,0xcd,0xf7},
                          {0x0a,0x55,0x76,0x65,0xcd,0xf8},
                          {0x0a,0x55,0x76,0x65,0xcd,0xf9},
                          {0x0a,0x55,0x76,0x65,0xcd,0xfa},
                          {0x0a,0x55,0x76,0x65,0xcd,0xfb},
                          {0x0a,0x55,0x76,0x65,0xcd,0xfc},
                          {0x0a,0x55,0x76,0x65,0xcd,0xfd},
                          {0x0a,0x55,0x76,0x65,0xcd,0xfe},
                          {0x0a,0x55,0x76,0x65,0xcd,0xff},
                         };

char dst_addr[][32] = {"10.0.0.1",
                       "10.0.0.2",
                       "10.0.0.3",
                       "10.0.0.4",
                       "10.0.0.5",
                       "10.0.0.6",
                       "10.0.0.7",
                       "10.0.0.8",
                       "10.0.0.9",
                       "10.0.0.10",
                       "10.0.0.11",
                       "10.0.0.12",
                       "10.0.0.13",
                       "10.0.0.14",
                       "10.0.0.15",
                       "10.0.0.16",
                       };

void craft_udp_packet(char* s_addr, char *d_addr, uint8_t *mac, uint32_t flow_id, int seq, uint32_t port);

void generate_udp_packets(char *s_addr, char *d_addr, uint32_t max_flows, int max_seq) {
    uint32_t flow = 0; int seq = 0;
    int num_flows_per_host = ((double)max_flows / (double)MAX_LEGITIMATE_HOSTS);
    printf("\nNum flows per host: ~%d", num_flows_per_host);
    //printf("\nMax flows: %u", max_flows);

    std::vector<uint32_t> port(MAX_LEGITIMATE_HOSTS, 0);
    for (flow = 0; flow < max_flows; flow++) {
        int host = (flow / num_flows_per_host) % MAX_LEGITIMATE_HOSTS;
        for (seq = 0; seq < max_seq; seq++) { 
            //craft_udp_packet(s_addr,dst_addr[host], mac_addrs[host],flow, seq);
            craft_udp_packet(s_addr,dst_addr[host], mac_addrs[host],flow, seq, port[host]);
        }
	port[host] += 1; 
    }
}

unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void craft_udp_packet(char* s_addr, char *d_addr, uint8_t *mac, uint32_t flow_id, int seq, uint32_t port) {
    packet_t *pkt = &packets[flow_id][seq];
    memset(pkt, 0, sizeof(packet_t));

    /* Ethernet header */
    pkt->eth_hdr.ether_shost[0] = 0x76;
    pkt->eth_hdr.ether_shost[1] = 0x1c;
    pkt->eth_hdr.ether_shost[2] = 0xa1;
    pkt->eth_hdr.ether_shost[3] = 0xa2;
    pkt->eth_hdr.ether_shost[4] = 0x1b;
    pkt->eth_hdr.ether_shost[5] = 0x41;

    pkt->eth_hdr.ether_dhost[0] = mac[0];
    pkt->eth_hdr.ether_dhost[1] = mac[1];
    pkt->eth_hdr.ether_dhost[2] = mac[2];
    pkt->eth_hdr.ether_dhost[3] = mac[3];
    pkt->eth_hdr.ether_dhost[4] = mac[4];
    pkt->eth_hdr.ether_dhost[5] = mac[5];
    pkt->eth_hdr.ether_type = htons(ETH_P_IP);

    /* IP Header */
    pkt->ip_hdr.ihl = 5;
    pkt->ip_hdr.version = 4;
    pkt->ip_hdr.tos = 0; // Low delay
    pkt->ip_hdr.id = htons(1);
    pkt->ip_hdr.protocol = 17; // UDP

    /* Source IP address */
    pkt->ip_hdr.saddr = inet_addr(s_addr);
    
    /* Destination IP address */
    pkt->ip_hdr.daddr = inet_addr(d_addr);

    /* UDP Header */
    //pkt->udp_hdr.source = htons(flow_id % MAX_PORT_NUM);
    pkt->udp_hdr.source = htons(port);
    //pkt->udp_hdr.dest = htons(flow_id % MAX_PORT_NUM);
    pkt->udp_hdr.dest = htons(port);
    pkt->udp_hdr.check = 0; // skip

    /* Payload */
    sprintf(pkt->payload, "%d", seq);

    pkt->len = sizeof(struct ether_header) + 
                sizeof(struct iphdr) + sizeof(struct udphdr) +
                strlen(pkt->payload);
    pkt->udp_hdr.len = htons(pkt->len - sizeof(struct ether_header) - sizeof(struct iphdr));
    pkt->ip_hdr.tot_len = htons(pkt->len - sizeof(struct ether_header));
    pkt->ip_hdr.check = csum((unsigned short *)(&pkt->ip_hdr), sizeof(struct iphdr)/2);
}

int get_next_seq(uint32_t flow_id) {
    int seq_num = seq_cnt[flow_id];
    seq_cnt[flow_id] = (seq_cnt[flow_id] + 1) % MAX_SEQ;
    return (seq_num);
}

void busy_sleep(int duration) {
    bool sleep = true;
    auto start = std::chrono::system_clock::now();
    while(sleep)
    {
        auto now = std::chrono::system_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(now - start);
        if (elapsed.count() > duration)
            sleep = false;
    }
}

static inline bool coin_toss(double inter_arrival) {
    float coin_flip_result = (float) rand()/RAND_MAX;
    double probability = (inter_arrival/70);

    // Get the outcome of the flip
    bool res = (coin_flip_result <= probability)? true : false;
    return res;
}

void send_packets() {
    char error_buf2[PCAP_ERRBUF_SIZE];
    const char *dev = "h17-eth0";
    int snaplen = BUFSIZ;
    int promisc = 0;
    int timeout_lim = 10000;

    std::cout<<"\nSending packets...."<<std::endl;

    // Open handle for flooding packets
    pcap_t *flooder_handle = pcap_open_live(dev, snaplen, promisc, timeout_lim, error_buf2);
    if (flooder_handle == NULL) {
        printf("Error finding device: %s\n", error_buf2);
    }

    // 100x slowdown rather than 1000
    for(auto it = packet_send_time.begin(); it != packet_send_time.end(); it++) {
       // Extract (flow_id, time) from the stack

       if (it->second == 0) {
            /* No sleep */
       } else if ((it->second * 100.0) <= 70.0) {
           /* No need to sleep */
           if (coin_toss(it->second * 100.0)) {
               usleep(1);
           }
       } else {
           usleep((it->second * 100.0) - 70); // micro second sleep
       }
       // Extract packet and send
       packet_t *packet = &packets[it->first][get_next_seq(it->first)];
       pcap_inject(flooder_handle, packet, packet->len);
    }

    // close this handle for the flooder
    pcap_close(flooder_handle); 
}

/*
void send_packets(uint32_t max_flows, int max_seq) {
    char error_buf2[PCAP_ERRBUF_SIZE];
    const char *dev = "h17-eth0";
    int snaplen = BUFSIZ;
    int promisc = 0;
    int timeout_lim = 10000;

    std::cout<<"\nSending packets...."<<std::endl;
    // Open handle for flooding packets
    pcap_t *flooder_handle = pcap_open_live(dev, snaplen, promisc, timeout_lim, error_buf2);
    if (flooder_handle == NULL) {
        printf("Error finding device: %s\n", error_buf2);
    }

    for(int cycle = 0; cycle < MAX_CYCLES; cycle++) {
        int curr_ts = 0;
        for (uint32_t iter = 0; iter < packet_send_time[cycle].size(); iter++) {
            // Sleep (usec) until time to send next pkt
            int x = (packet_send_time[cycle][iter].second - curr_ts); // 1000.0;
            //busy_sleep(x);
            usleep(x * 1000);
            curr_ts = packet_send_time[cycle][iter].second; // Update current timestamp
            uint32_t flow_id = packet_send_time[cycle][iter].first;
            packet_t *packet = &packets[flow_id][get_next_seq(flow_id)];
            // send packet
            pcap_inject(flooder_handle, packet, packet->len);
        }
        // After sending all pkts in the cycle, if time left,
        // Sleep till end of cycle
        if (curr_ts < 1000) { // 1 cycle duration = 1000 usec
            //busy_sleep(1000 - curr_ts);
            usleep((1000-curr_ts) * 1000);
        }
    }

    // close this handle for the flooder
    pcap_close(flooder_handle); 
}
*/

bool comparator(std::pair<uint32_t, double> i, std::pair<uint32_t, double> j) {
    return (i.second < j.second); 
}

void calculate_constant_traffic_pattern(uint32_t max_flows, double lambda_a) {
    //double lambda_max = (lambda_a * max_flows); // 1000 packets per 0.1sec
    //double = interarrival_time = (1 / lambda_max) * 0.1; // ms
    double interarrival_time = 0.1; // milli seconds
    double ts_sum = 0.0; // sec
    uint32_t flow_id = 0;

    while (ts_sum < MAX_CYCLES) {
        packet_send_time.push_back(std::make_pair(flow_id, interarrival_time));
        flow_id = (flow_id + 1) % max_flows;
        ts_sum += (interarrival_time / 1000.0); // in seconds (msec might overflow)
    }
}

void calculate_interarrival_times(uint32_t max_flows, double lambda_a) {
    double lambda_max = (lambda_a * max_flows); // packets per second
    double ts_sum = 0.0;

    std::default_random_engine generator;
    std::uniform_int_distribution<uint32_t> distribution(0,max_flows); 

    std::default_random_engine exponential_generator;
    std::exponential_distribution<double> exponential_distribution(lambda_max);

    while (ts_sum < MAX_CYCLES) {
        // Calculate the time at which each pkt is sent 
        uint32_t flow_id = distribution(generator);

        // save ts in ms.
        double ts = exponential_distribution(exponential_generator) * 1000.0;
        //std::cout<<ts<<std::endl;

        packet_send_time.push_back(std::make_pair(flow_id, ts));
        ts_sum += (ts / 1000.0); // in seconds (msec might overflow)
    }
}

/*
void calculate_interarrival_times(uint32_t max_flows) {
    // ############POISSON DISTRIBUTION##############/
    // timestamps ==> (key, value) = (flow, hash_map) 
    // where hash_map(key, value) = (cycle, vector(timestamps))
    std::unordered_map<uint32_t, std::unordered_map<int, vector<int>>> timestamps;

    std::cout<<"\nCalcuating the timestamps"<<std::endl;
    for (uint32_t flow_id = 0; flow_id < max_flows; flow_id++) {
        double lambda_l = lambda_background[flow_id];
        //printf("\nFlow ID: %d lambda_l = %f\n", flow_id, lambda_l);
        double ts_sum = 0.0;
        for (int cycle = 0; cycle < MAX_CYCLES; cycle++) {
            //printf("Cycle: %d ---> ", cycle);
            // Calculate the time at which each of the pkts 
            while(ts_sum < 1000) { // less that 1000 ms = 1 cycle (1 msec)
                if (ts_sum > 0.000000) { 
                    timestamps[flow_id][cycle].push_back(ts_sum);
                    //printf("%f, ", ts_sum);
                }
                double rand_num = ((double) rand() / (RAND_MAX));
                double ts = (-log(1.0 - rand_num) / lambda_l) * 1000.0; //msec
                ts_sum = roundf(((ts_sum + ts) * 10000)/10000); // Round to 4 places.
            } // End of while
            ts_sum = ts_sum - 1000;
        } // End of for
    } // End of for

    // Order timestamps as (timestamp, packet) per time cycle /
    std::cout<<"\nDone"<<std::endl;
    std::cout<<"\nOrder timestamps"<<std::endl;
    for (int cycle = 0; cycle < MAX_CYCLES; cycle++) {
        for (uint32_t flow_id = 0; flow_id < max_flows; flow_id++) {
            for (uint32_t time = 0; time < timestamps[flow_id][cycle].size(); time++) {
                packet_send_time[cycle].push_back(make_pair(flow_id, timestamps[flow_id][cycle][time]));        
            } // End of for
        } // End of for
    } // End of for

    //printf("[");
    std::cout<<"\nSort timestamps"<<std::endl;
    for (int cycle = 0; cycle < MAX_CYCLES; cycle++) {
        // Sort the vector
        //printf("\nCycle: %d\n", cycle);
        std::sort(packet_send_time[cycle].begin(), packet_send_time[cycle].end(), comparator);
        //printf("%lu, ", packet_send_time[cycle].size());
        //for (int i = 0; i < packet_send_time[cycle].size(); i++) {
            //printf("(%d, %f), ", packet_send_time[cycle][i].first, packet_send_time[cycle][i].second);
        //}
    } // End of for
    //printf("]");
    return;
}
*/

/*
void calculate_flow_rates(uint32_t max_flows) {
    if (is_attacker) {
        double lambda_a = 0.0167; // Rate of each attack flow
        for (uint32_t flow_id = 0; flow_id < max_flows; flow_id++) {
            lambda_background[flow_id] = lambda_a;
        }
        return;
    }
}
*/

void save_trace_to_file(char *file_name) {
    std::ofstream fd; 
    fd.open(file_name);


    /* Open the file for write*/
    if(!fd) {
        std::cout<<"Cannot open trace file.\n";
        return;
    }
    fd << "time difference(ms) \tflowid\n";

    for(auto it = packet_send_time.begin(); it != packet_send_time.end(); it++) {
       std::string str = std::to_string(it->second) + "\t" 
                            + std::to_string(it->first) + "\n";
       fd << str;
    }

    fd.close();
}

void process_string(string str, double *timestamp, uint32_t *flow_id) {
    char *pch;
    char temp[128];
    
    strcpy(temp, str.c_str());
    // Get timestamp
    pch = strtok(temp, "\t\n");
    sscanf(pch, "%lf", timestamp);

    // Get FlowID
    pch = strtok(NULL, "\t\n");
    sscanf(pch, "%u", flow_id);
    //*flow_id = atoi(pch); 
}

void get_traffic_from_trace(char *file_name) {
    std::ifstream fd; 
    fd.open(file_name);

    if(!fd) {
        std::cout<<"Cannot open trace file.\n";
        exit(0);
        //return;
    }

    std::string str;

    // We don't need the first line
    std::getline(fd, str);
    while (std::getline(fd, str)) {
        double timestamp; uint32_t flow_id;
        process_string(str, &timestamp, &flow_id);
        packet_send_time.push_back(std::make_pair(flow_id, timestamp));
        //std::cout<<"TS = "<<timestamp<<" #Flow = "<<flow_id<<std::endl;
    }
    //printf("\nNo. of entries: %d", traffic.size());
}

void craft_packets(_protocol_t protocol, char *s_addr, char *d_addr, uint32_t max_flows, int max_seq) {
    switch(protocol) {
        case UDP:
            generate_udp_packets(s_addr, d_addr, max_flows, max_seq);
            break;
        default:
            printf("\n%s(): Unknown protocol, cannot craft packets", __func__);
    }
}

#if 0
void profile_time() {
    list <std::chrono::nanoseconds> times;

    struct timespec ts = {0, 1};
    struct timespec ts2;

    for (int i = 0; i < 15; i++) {
        std::chrono::time_point<std::chrono::system_clock> now1 = std::chrono::system_clock::now();
        auto duration1 = now1.time_since_epoch();
        //usleep(1);
        nanosleep(&ts, &ts2);
        std::chrono::time_point<std::chrono::system_clock> now2 = std::chrono::system_clock::now();
        auto duration2 = now2.time_since_epoch();
        auto nano1 = std::chrono::duration_cast<std::chrono::nanoseconds>(duration1);
        auto nano2 = std::chrono::duration_cast<std::chrono::nanoseconds>(duration2);
        times.push_back(nano2 - nano1); 
        auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds> (nano2 -nano1);
        //std::cout<<"\n"<<nano1.count()<<" - "<<nano2.count();
        std::cout<<"\n"<<nanoseconds.count() / 1000.0 <<" us";
    }
    
    //for (auto it = times.begin(); it != times.end(); it++) {
      //  std::cout<<"\n"<<*it;
        //std::cout<<"\n"<<*it.count();
   // }
}
#endif

void run() {
    char s_addr[32] = "10.0.0.17";
    char d_addr[32] = "10.0.0.2";
    uint32_t user_max_flows = 1000000;
    double lambda_a = 1;
    char ATTACK_TRACE_FILE[64];

    srand(time(NULL));
    printf( "\nEnter Source IP : %s", s_addr);
    printf( "\nEnter Max Flows: %u", user_max_flows);

    if (CONSTANT_TRAFFIC) {
        sprintf(ATTACK_TRACE_FILE, "Subtraces/contant_attack_trace_%f", lambda_a);
    } else {
        sprintf(ATTACK_TRACE_FILE, "Subtraces/attack_trace_%f", lambda_a);
    }
    std::cout<<"\n"<<ATTACK_TRACE_FILE<<std::endl;
    craft_packets(UDP, s_addr, d_addr, user_max_flows, MAX_SEQ);

#ifdef GENERATE_TRACE
    if (CONSTANT_TRAFFIC) {
        calculate_constant_traffic_pattern(user_max_flows, lambda_a);
    } else {
        calculate_interarrival_times(user_max_flows, lambda_a);
    }
    save_trace_to_file(ATTACK_TRACE_FILE);
#else
    get_traffic_from_trace(ATTACK_TRACE_FILE);
    printf("\nPackets Processed for send\n");
    printf("\nPress any key to start sending");
    getchar();
    send_packets();
#endif
    printf("\nDone...\n");
}

void signal_callback_handler(int signum) {
    std::cout<<"\nCaught signal"<<signum<<std::endl;
    std::cout<<"Exiting..."<<std::endl;
    exit(0);
}

int main() {
    // Catch the user interrupt
    signal(SIGINT, signal_callback_handler);
   
    run();

    return 0;
}
