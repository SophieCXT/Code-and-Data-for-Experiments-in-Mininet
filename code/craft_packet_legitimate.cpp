/**
 * File: flooder.c
 *
 * Description   : Craft packets.
 * Created By    : Namitha Nambiar
 * Date          : Sept 2020
 * Last Modified : Sept 2020
 */

/* Include Files  */
#include "craft_packet.h"
#include "math.h"
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <chrono>
#include <thread>

using namespace std;

#define MAX_FLOWS 100
#define MAX_SEQ   100
#define MAX_CYCLES 10000 // sec

/* Global Variables */
packet_t packets[MAX_FLOWS][MAX_SEQ];
float lambda_background[MAX_FLOWS];
std::unordered_map<int, vector<std::pair<int, double>>>packet_send_time;
vector<int> seq_cnt(MAX_FLOWS, 0); // Maintain a counter for each flow to track next seq

void craft_udp_packet(char* s_addr, char *d_addr, int flow_id, int seq);

void generate_udp_packets(char *s_addr, char *d_addr, int max_flows, int max_seq) {
    int flow = 0, seq = 0;

    for (flow = 0; flow < max_flows; flow++) {
        for (seq = 0; seq < max_seq; seq++) {
            craft_udp_packet(s_addr,d_addr, flow, seq);
        }
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

void craft_udp_packet(char* s_addr, char *d_addr, int flow_id, int seq) {
    packet_t *pkt = &packets[flow_id][seq];
    memset(pkt, 0, sizeof(packet_t));

    /* Ethernet header */
    pkt->eth_hdr.ether_shost[0] = 0x76;
    pkt->eth_hdr.ether_shost[1] = 0x1c;
    pkt->eth_hdr.ether_shost[2] = 0xa1;
    pkt->eth_hdr.ether_shost[3] = 0xe2;
    pkt->eth_hdr.ether_shost[4] = 0x1b;
    pkt->eth_hdr.ether_shost[5] = 0x42;

    pkt->eth_hdr.ether_dhost[0] = 0x0a;
    pkt->eth_hdr.ether_dhost[1] = 0x55;
    pkt->eth_hdr.ether_dhost[2] = 0x76;
    pkt->eth_hdr.ether_dhost[3] = 0x65;
    pkt->eth_hdr.ether_dhost[4] = 0xcd;
    pkt->eth_hdr.ether_dhost[5] = 0xf1;
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
    pkt->udp_hdr.source = htons(flow_id);
    pkt->udp_hdr.dest = htons(flow_id);
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

int get_next_seq(int flow_id) {
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

void send_packets(int max_flows, int max_seq) {
    char error_buf2[PCAP_ERRBUF_SIZE];
    const char *dev = "h18-eth0";
    int snaplen = BUFSIZ;
    int promisc = 0;
    int timeout_lim = 10000;

    // Open handle for flooding packets
    pcap_t *flooder_handle = pcap_open_live(dev, snaplen, promisc, timeout_lim, error_buf2);
    if (flooder_handle == NULL) {
        printf("Error finding device: %s\n", error_buf2);
    }

    for(int cycle = 0; cycle < MAX_CYCLES; cycle++) {
        int curr_ts = 0;
        for (uint32_t iter = 0; iter < packet_send_time[cycle].size(); iter++) {
            // Sleep (usec) until time to send next pkt
            int x = (packet_send_time[cycle][iter].second - curr_ts); /*/ 1000.0; */
            //busy_sleep(x);
            curr_ts = packet_send_time[cycle][iter].second; // Update current timestamp
            int flow_id = packet_send_time[cycle][iter].first;
            packet_t *packet = &packets[flow_id][get_next_seq(flow_id)];
            // send packet
            pcap_inject(flooder_handle, packet, packet->len);
        }
    }

    // close this handle for the flooder
    pcap_close(flooder_handle); 
}

bool comparator(std::pair<int, double> i, std::pair<int, double> j) {
    return (i.second < j.second); 
}

void calculate_interarrival_times(int max_flows) {
    /*############POISSON DISTRIBUTION##############*/
    // timestamps ==> (key, value) = (flow, hash_map) 
    // where hash_map(key, value) = (cycle, vector(timestamps))
    std::unordered_map<int, std::unordered_map<int, vector<int>>> timestamps;

    for (int flow_id = 0; flow_id < max_flows; flow_id++) {
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

    /*** Order timestamps as (timestamp, packet) per time cycle ***/
    for (int cycle = 0; cycle < MAX_CYCLES; cycle++) {
        for (int flow_id = 0; flow_id < max_flows; flow_id++) {
            for (uint32_t time = 0; time < timestamps[flow_id][cycle].size(); time++) {
                packet_send_time[cycle].push_back(make_pair(flow_id, timestamps[flow_id][cycle][time]));        
            } // End of for
        } // End of for
    } // End of for

    //printf("[");
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

void calculate_flow_rates(int max_flows) {
    //int C = 50; // Cache size
    int lm_background = 10; // Total Legitimate Flow Rate
    int alpha = 1; // For Zipf Distribution
    int F = max_flows; // Max No. of Legitimate Flows

    // Calculate the Zipf Popularity Distribution
    double p[F];
    double sum_p = 0.0;

    for (int i = 0; i < F; i++) {
        p[i] = 1 / pow(i+1, alpha);
        sum_p += p[i];
    }

    for (int i = 0; i < F; i++) {
        p[i] = p[i] / sum_p;
        lambda_background[i] = p[i] * lm_background;
        lambda_background[i] = roundf(lambda_background[i] * 10000) / 10000;
    }
}

void craft_packets(_protocol_t protocol, char *s_addr, char *d_addr, int max_flows, int max_seq) {
    switch(protocol) {
        case UDP:
            generate_udp_packets(s_addr, d_addr, max_flows, max_seq);
            break;
        default:
            printf("\n%s(): Unknown protocol, cannot craft packets", __func__);
    }
}

int main() {
    char s_addr[32] = "10.0.0.18";
    char d_addr[32] = "10.0.0.2";
    int max_flows = 0;
    
    srand(time(NULL));
    //printf( "Enter Source IP :");
    //scanf("%s", s_addr);
    //printf( "Enter Destination IP :");
    //scanf("%s", d_addr);
    max_flows = 1;
    craft_packets(UDP, s_addr, d_addr, max_flows, MAX_SEQ);
    calculate_flow_rates(max_flows);
    calculate_interarrival_times(max_flows);
    send_packets(max_flows, MAX_SEQ);
    printf("\nDone...\n");
    return 0;
}
