#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include "pcap-headers.h"

#define MAX_PAYLOAD_SIZE 20

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

// 주어진 데이터의 바이트 배열을  16진수로 출력하는 함수
void print_hex(const u_char *data, int size) {
    for (int i = 0; i < size; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}

// 캡처된 패킷의 정보를 파싱하여 Ethernet, IP, TCP 헤더 정보를 출력하는 함수
// pkthdr: 패킷의 메타데이터를 포함하는 pcap_pkthdr 구조체 포인터
// packet: 실제 패킷 데이터의 포인터 : 연속된 바이트 배열
void packet_parser(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	struct libnet_ethernet_hdr *eth_hdr;
	struct libnet_ipv4_hdr *ip_hdr;
	struct libnet_tcp_hdr *tcp_hdr;
	const u_char *payload;
	int ethernet_size = sizeof(struct libnet_ethernet_hdr);
	int ip_size, tcp_size;

	// 이더넷 헤더 구조체 포인터 선언
	eth_hdr = (struct libnet_ethernet_hdr *) packet;

	// Src/Dst MAC 주소 출력
	printf("Ethernet Header:\n");
	printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		eth_hdr->ether_shost[0], eth_hdr->ether_shost[1],eth_hdr->ether_shost[2],
		eth_hdr->ether_shost[3], eth_hdr->ether_shost[4],eth_hdr->ether_shost[5]
	);
	printf("Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n\n",
		eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1],eth_hdr->ether_dhost[2],
		eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4],eth_hdr->ether_dhost[5]
	);

	// ntohs 함수: network byte order -> host byte order 로 변환
	// ETHERTYPE_IP: net/ethernet.h 헤더파일에 포함된 상수. IP프로토콜을 나타냄.
	// 이더넷 타입 필드 -> IP 패킷인지 확인
	if(ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
		printf("IP 패킷이 아닙니다. 생략합니다.\n\n");
		return;
	}

	// 이더넷 헤더 다음 부분(+ehternet_size)을  libnet_ipv4_hdr 구조체의 포인터로 선언
	ip_hdr = (struct libnet_ipv4_hdr *)(packet + ethernet_size);
	
	// ip_hl: ip header length: 가변적임 & 4bit 단위임
	// 4를 곱함으로써 byte 로 바꿔줌
	ip_size = ip_hdr->ip_hl * 4;

	printf("IP Header:\n");
	printf("Src IP: %s\n", inet_ntoa(ip_hdr->ip_src));
	printf("Dst IP: %s\n\n", inet_ntoa(ip_hdr->ip_dst));


	// IPPROTO_TCP: netinet/in.h 헤더파일에 포함된 상수. TCP 프로토콜을 나타냄.
	// 이더넷 타입 필드 -> TCP 패킷인지 확인
	if(ip_hdr->ip_p != IPPROTO_TCP) {
		printf("TCP 패킷이 아닙니다. 생략합니다.\n\n");
		return;
	}

	//  IP 헤더 다음 부분(+ ehternet_size + ip_size)을  libnet_tcp_hdr 구조체의 포인터로 선언
	tcp_hdr = (struct libnet_tcp_hdr *)(packet + ethernet_size + ip_size);

	// th_off: tcp 데이터 오프셋: 가변적임 & 4bit 단위임
	// 4를 곱함으로써 byte 로 바꿔줌
	tcp_size = tcp_hdr->th_off*4;

	printf("TCP Header:\n");
	printf("Src Port: %d\n", ntohs(tcp_hdr->th_sport));
	printf("Dst Port: %d\n\n", ntohs(tcp_hdr->th_dport));

	//  TCP 헤더 다음 부분(+ ehternet_size + ip_size + tcp_size)이 payload 임
	payload = packet + ethernet_size + ip_size + tcp_size;
	// payload 크기 = 전체 패킷 길이 - 이더넷 헤더 크기 - IP 헤더 크기 - TCP 헤더 크기
	int payload_size = pkthdr->caplen - (ethernet_size + ip_size + tcp_size);
	// 20 바이트로 제한
	if (payload_size > MAX_PAYLOAD_SIZE) {
		payload_size = MAX_PAYLOAD_SIZE;
	}

	// payload가 없으면 pass
	if (payload_size < 1) {
		printf("Payload가 없습니다. 생략합니다.\n\n\n");
		return;
	}

	// payload 출력
	printf("Payload (20 bytes):\n");
	print_hex(payload, payload_size);
	printf("\n\n\n");

}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];

	// 미리 capture한 pcap 파일로 진행하여 pcap_open_offline 함수 활용
	// pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	pcap_t* pcap = pcap_open_offline(param.dev_, errbuf);

	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
	int cnt = 1; 
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("#%d packet\n", cnt++);
		printf("%u bytes captured\n", header->caplen);
		packet_parser(header, packet);
	}

	pcap_close(pcap);
	return 0;
}
