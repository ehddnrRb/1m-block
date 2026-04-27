#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <set>
#include <string>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "ip.h"
#include <cstring>
#include <strings.h>

static std::string block_host;

struct IpHdr final {
    uint8_t  version_;	// version(4비트) + IHL(4비트)
    uint8_t  tos_;
    uint16_t tot_len_;
    uint16_t id_;
    uint16_t frag_off_;
    uint8_t  ttl_;
    uint8_t  protocol_;
    uint16_t check_;
    Ip       sip_;
    Ip       dip_;
};

struct TcpHdr final {
    uint16_t sport_;        // Source Port (출발지 포트)
    uint16_t dest_;         // Destination Port (목적지 포트)
    uint32_t seq_;          // Sequence Number (시퀀스 번호)
    uint32_t ack_;          // Acknowledgment Number (응답 번호)
    uint8_t  data_offset_;  // 상위 4비트: Data Offset, 하위 4비트: Reserved
    uint8_t  flags_;        // 플래그 (URG, ACK, PSH, RST, SYN, FIN 등)
    uint16_t win_;          // Window Size
    uint16_t check_;        // Checksum
    uint16_t urg_ptr_;      // Urgent Pointer
};

/* returns packet id */
static uint32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	uint32_t mark, ifi, uid, gid;
	int ret;
	unsigned char *data, *secdata;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	if (nfq_get_uid(tb, &uid))
		printf("uid=%u ", uid);

	if (nfq_get_gid(tb, &gid))
		printf("gid=%u ", gid);

	ret = nfq_get_secctx(tb, &secdata);
	if (ret > 0)
		printf("secctx=\"%.*s\" ", ret, secdata);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d ", ret);

	fputc('\n', stdout);

	return id;
}

static int check_host(unsigned char *data, int len){
	
	if (len < sizeof(struct IpHdr)){
		return 0;
	}

	struct IpHdr *ip = (struct IpHdr *)data;
	if (ip->protocol_ != 6){ // TCP
		return 0;
	}

	int ip_hdr_len = (ip->version_ & 0x0F) * 4;
	if (len < ip_hdr_len + sizeof(struct TcpHdr)){
		return 0;
	}

	struct TcpHdr *tcp = (struct TcpHdr *)(data + ip_hdr_len);
	if (tcp->dest_ != htons(80)){
		return 0;
	}

	int tcp_hdr_len = (tcp->data_offset_ >> 4) * 4;

	int http_offset = ip_hdr_len + tcp_hdr_len;
	int http_len = len - http_offset;
	if (http_len <= 0){
		return 0;
	}

	char * http = (char *) (data + http_offset);
	std::string http_str(http, http_len);	
	if (strncmp(http, "GET ", 4) != 0 && strncmp(http, "POST ", 5) != 0){
		return 0;
	}

	std::string host;

	for(int i=0; i< http_len; i++){
		if(strncasecmp(http + i, "\r\nHost: ", 7)==0){
			int j = i + 7;
			while(j < http_len && http[j] == ' ') j++;

            while (j < http_len - 1 &&
                   !(http[j] == '\r' && http[j+1] == '\n')) {
                host += http[j];
                j++;
            }
			break;
		}
	}
    if (host.empty())
        return 0;
	
    printf(">> HTTP Host: %s\n", host.data());

	if (host == block_host){
		printf(">> Blocking host: %s\n", host.data());
		return 1;
	}

	return 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	uint32_t id = print_pkt(nfa);

	unsigned char *pkt_data; // 패킷 데이터 가져오기
    int pkt_len = nfq_get_payload(nfa, &pkt_data);

	int verdict = NF_ACCEPT; // 기본은 허용

	if(pkt_len >= 0 && check_host(pkt_data, pkt_len)){
		verdict = NF_DROP;
	}
	
	printf("verdict = %s\n", verdict == NF_ACCEPT ? "NF_ACCEPT" : "NF_DROP");

	return nfq_set_verdict(qh, id, verdict, 0, NULL);

	
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	uint32_t queue = 0;
	char buf[4096] __attribute__ ((aligned));

	if (argc == 2) {
		queue = atoi(argv[1]);
		if (queue > 65535) {
			fprintf(stderr, "Usage: %s [<0-65535>]\n", argv[0]);
        	fprintf(stderr, "Example: %s test.gilgil.net\n", argv[0]);
			exit(EXIT_FAILURE);
		}
		block_host = argv[1];
    	printf("Blocking host: %s\n", block_host.data());
	}
	else {
        fprintf(stderr, "syntax : netfilter-test <host>\n");
        fprintf(stderr, "sample : netfilter-test test.gilgil.net\n");
        exit(EXIT_FAILURE);
	}

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '%d'\n", queue);
	qh = nfq_create_queue(h, 0, &cb, NULL); // 큐 번호 고정 -> 표준이라고 한다.
	// iptable -A INPUT -j NFQUEUE --queue-num 0 (--queue-num 을 하지 않으면 0으로 설정)
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	printf("setting flags to request UID and GID\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve process UID/GID.\n");
	}

	printf("setting flags to request security context\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve security context.\n");
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
