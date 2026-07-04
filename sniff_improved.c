#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

/*--------------------------------------------------
 * 패킷 수신 시 호출되는 콜백 함수
 * packet : 수신한 패킷의 시작 주소
 *-------------------------------------------------*/
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    /*--------------------------------------------------
     * 1. Ethernet Header 분석
     *-------------------------------------------------*/
    struct ethheader *eth = (struct ethheader *)packet;

    printf("\n=============================\n");
    printf("Ethernet Header\n");

    printf("Source MAC      : %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->ether_shost[0], eth->ether_shost[1],
           eth->ether_shost[2], eth->ether_shost[3],
           eth->ether_shost[4], eth->ether_shost[5]);

    printf("Destination MAC : %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->ether_dhost[0], eth->ether_dhost[1],
           eth->ether_dhost[2], eth->ether_dhost[3],
           eth->ether_dhost[4], eth->ether_dhost[5]);

    /*--------------------------------------------------
     * 2. Ethernet Type 확인
     * IPv4(0x0800)인 경우에만 IP Header 분석
     *-------------------------------------------------*/
    if (ntohs(eth->ether_type) == 0x0800)
    {
        /*--------------------------------------------------
         * 3. IP Header 분석
         * Ethernet Header(14Byte) 이후부터 IP Header 시작
         *-------------------------------------------------*/
        struct ipheader *ip =
            (struct ipheader *)(packet + sizeof(struct ethheader));

        printf("\nIP Header\n");

        printf("Source IP      : %s\n",
               inet_ntoa(ip->iph_sourceip));

        printf("Destination IP : %s\n",
               inet_ntoa(ip->iph_destip));

        /* IP Header의 실제 길이(Byte) 계산 */
        int ip_header_len = ip->iph_ihl * 4;

        /*--------------------------------------------------
         * 4. 상위 프로토콜 확인
         * TCP, UDP, ICMP 구분
         *-------------------------------------------------*/
        switch (ip->iph_protocol)
        {

        /*==================================================
         * TCP Protocol 분석
         *=================================================*/
        case IPPROTO_TCP:
        {
            printf("Protocol : TCP\n");

            /* TCP Header 시작 위치 계산 */
            struct tcpheader *tcp =
                (struct tcpheader *)(packet +
                                     sizeof(struct ethheader) +
                                     ip_header_len);

            printf("\nTCP Header\n");

            printf("Source Port      : %d\n",
                   ntohs(tcp->tcp_sport));

            printf("Destination Port : %d\n",
                   ntohs(tcp->tcp_dport));

            /* TCP Header 길이(Byte) 계산 */
            int tcp_header_len = TH_OFF(tcp) * 4;

            /*--------------------------------------------------
             * 5. HTTP(Application Data) 시작 위치 계산
             *-------------------------------------------------*/
            const u_char *payload =
                packet +
                sizeof(struct ethheader) +
                ip_header_len +
                tcp_header_len;

            /* HTTP 데이터의 길이 계산 */
            int payload_len =
                ntohs(ip->iph_len)
                - ip_header_len
                - tcp_header_len;

            printf("\nHTTP Message\n");

            /* HTTP 데이터 출력 */
            if (payload_len > 0)
            {
                for (int i = 0; i < payload_len; i++)
                {
                    printf("%c", payload[i]);
                }

                printf("\n");
            }

            return;
        }

        /* UDP Protocol */
        case IPPROTO_UDP:
            printf("Protocol : UDP\n");
            return;

        /* ICMP Protocol */
        case IPPROTO_ICMP:
            printf("Protocol : ICMP\n");
            return;

        /* 기타 프로토콜 */
        default:
            printf("Protocol : Others\n");
            return;
        }
    }
}

/*--------------------------------------------------
 * 프로그램 시작
 *-------------------------------------------------*/
int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    /* TCP 패킷만 캡처 */
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0;

    /*--------------------------------------------------
     * 1. 네트워크 인터페이스(Open Live)
     *-------------------------------------------------*/
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL)
    {
        printf("pcap_open_live failed: %s\n", errbuf);
        return -1;
    }

    /*--------------------------------------------------
     * 2. BPF 필터 컴파일 및 적용
     *-------------------------------------------------*/
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        printf("pcap_compile failed\n");
        return -1;
    }

    if (pcap_setfilter(handle, &fp) != 0)
    {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    /*--------------------------------------------------
     * 3. 패킷 캡처 시작
     * got_packet() 함수가 패킷 수신 시마다 호출됨
     *-------------------------------------------------*/
    pcap_loop(handle, -1, got_packet, NULL);

    /*--------------------------------------------------
     * 4. 리소스 해제
     *-------------------------------------------------*/
    pcap_close(handle);

    return 0;
}