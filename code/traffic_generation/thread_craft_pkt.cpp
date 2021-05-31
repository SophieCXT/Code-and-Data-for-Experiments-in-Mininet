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
#include <iostream>
#include <thread>

using namespace std;

#define MAX_FLOWS 100
#define MAX_SEQ   100
#define MAX_CYCLES 10000 // msec
#define MAX_THREADS 8

/* Global Variables */
packet_t packets[MAX_FLOWS][MAX_SEQ];
float lambda_background[MAX_FLOWS];
vector<std::unordered_map<int, vector<std::pair<int, double>>>>packet_send_time(MAX_THREADS);
vector<int> seq_cnt(MAX_FLOWS, 0); // Maintain a counter for each flow to track next seq
pthread_mutex_t sequence_lock;

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

static inline int get_next_seq(int flow_id) {
    //pthread_mutex_lock(&sequence_lock);
    int seq_num = seq_cnt[flow_id];
    seq_cnt[flow_id] = (seq_cnt[flow_id] + 1) % MAX_SEQ;
    //pthread_mutex_unlock(&sequence_lock);
    return (seq_num);
}

void* send_packets(void *arg) {
    char error_buf2[PCAP_ERRBUF_SIZE];
    const char *dev = "lo";
    int snaplen = BUFSIZ;
    int promisc = 0;
    int timeout_lim = 10000;
    
    int thread_id = (int)*(int*)arg;
    printf("\nThread ID: %d\n", thread_id);
    // Open handle for flooding packets
    pcap_t *flooder_handle = pcap_open_live(dev, snaplen, promisc, timeout_lim, error_buf2);
    if (flooder_handle == NULL) {
        printf("Error finding device: %s\n", error_buf2);
    }

    for(int cycle = 0; cycle < MAX_CYCLES; cycle++) {
        double curr_ts = 0;
        for (int iter = 0; iter < packet_send_time[thread_id][cycle].size(); iter++) {
            // Sleep (usec) until time to send next pkt
            int x = (packet_send_time[thread_id][cycle][iter].second - curr_ts);
            usleep(x);
            curr_ts = packet_send_time[thread_id][cycle][iter].second; // Update current timestamp
            int flow_id = packet_send_time[thread_id][cycle][iter].first;
            packet_t *packet = &packets[flow_id][get_next_seq(flow_id)];
            // send packet
            pcap_inject(flooder_handle, packet, packet->len);
        }
        // After sending all pkts in the cycle, if time left,
        // Sleep till end of cycle
        if (curr_ts < 1000) { // 1 cycle duration = 1000 usec
            usleep(1000 - curr_ts);
        }
    }

    // close this handle for the flooder
    pcap_close(flooder_handle); 
    return NULL;
}

void send_p() {
    char error_buf2[PCAP_ERRBUF_SIZE];
    const char *dev = "lo";
    int snaplen = BUFSIZ;
    int promisc = 0;
    int timeout_lim = 10000;

    // Open handle for flooding packets
    pcap_t *flooder_handle = pcap_open_live(dev, snaplen, promisc, timeout_lim, error_buf2);
    if (flooder_handle == NULL) {
        printf("Error finding device: %s\n", error_buf2);
    }
    
    int num_packet = 0;
    while(num_packet < 100000) {
        packet_t *packet = &packets[0][get_next_seq(0)];
        pcap_inject(flooder_handle, packet, packet->len);
        usleep(10);
        num_packet++;
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
            while(ts_sum < 1000) { // less that 1000 us = 1 cycle (1 msec)
                if (ts_sum > 0.000000) { 
                    timestamps[flow_id][cycle].push_back(ts_sum);
                    //printf("%f, ", ts_sum);
                }
                double rand_num = ((double) rand() / (RAND_MAX));
                double ts = (-log(1.0 - rand_num) / lambda_l) * 1000.0; //usec
                ts_sum = roundf(((ts_sum + ts) * 10000)/10000); // Round to 4 places.
            } // End of while
            ts_sum = ts_sum - 1000;
        } // End of for
    } // End of for

    /*** Order timestamps as (timestamp, packet) per time cycle ***/
    int thread = 0;
    for (int cycle = 0; cycle < MAX_CYCLES; cycle++) {
        for (int flow_id = 0; flow_id < max_flows; flow_id++) {
            for (int time = 0; time < timestamps[flow_id][cycle].size(); time++) {
                packet_send_time[thread][cycle].push_back(make_pair(flow_id, timestamps[flow_id][cycle][time]));        
                thread = (++thread) % MAX_THREADS;
            } // End of for
        } // End of for
    } // End of for

    //printf("[");
    for (int thread = 0; thread < MAX_THREADS; thread++) {
        for (int cycle = 0; cycle < MAX_CYCLES; cycle++) {
            // Sort the vector
            //printf("\nCycle: %d\n", cycle);
            std::sort(packet_send_time[thread][cycle].begin(), 
                            packet_send_time[thread][cycle].end(), comparator);
            //printf("%lu, ", packet_send_time[cycle].size());
            //for (int i = 0; i < packet_send_time[cycle].size(); i++) {
            //printf("(%d, %f), ", packet_send_time[cycle][i].first, packet_send_time[cycle][i].second);
            //}
        } // End of for
    }
    return;
}

void calculate_flow_rates(int max_flows) {
    int C = 50; // Cache size
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
    char s_addr[32] = "127.0.0.1";
    char d_addr[32] = "127.0.0.1";
    int max_flows = 0;

    srand(time(NULL));

    //printf( "Enter Source IP :");
    //scanf("%s", s_addr);
    //printf( "Enter Destination IP :");
    //scanf("%s", d_addr);
    //printf( "Enter Max Flows :");
    //scanf("%d", &max_flows);
    max_flows = 100;

    if (pthread_mutex_init(&sequence_lock, NULL) != 0) {
        printf("Error initializing sequence lock");
        return -1;
    }

    craft_packets(UDP, s_addr, d_addr, max_flows, MAX_SEQ);
    calculate_flow_rates(max_flows);
    calculate_interarrival_times(max_flows);
    send_p();
    return 0;
    
    /*
    pthread_t threads[MAX_THREADS];
    int thread_arg[MAX_THREADS];
    for (int i = 0; i < MAX_THREADS; i++) {
        thread_arg[i] = i;
        pthread_create(&threads[i], NULL, send_packets, &thread_arg[i]);
    }
    
    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    */
    return 0;
}
