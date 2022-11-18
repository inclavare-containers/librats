#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <librats/api.h>
#include <librats/evidence.h>
#include <librats/log.h>

#define DEFAULT_PORT	1234
#define DEFAULT_IP	"127.0.0.1"
#define DEFAULT_HASH	"12345678123456781234567812345678"
#define MAX_HASH_LENGTH 32

int librats_client_startup(char *ip, int port, char *hash_value, bool mutual)
{
	const char *hash = hash_value;

	/* Create a socket */
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		RATS_ERR("failed to call socket()\n");
		return -1;
	}

	struct sockaddr_in s_addr;
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(port);

	/* Get the server IPv4 address from the command line call */
	if (inet_pton(AF_INET, ip, &s_addr.sin_addr) != 1) {
		RATS_ERR("invalid server address\n");
		return -1;
	}

	/* Connect to the server */
	int connd = connect(sockfd, (struct sockaddr *)&s_addr, sizeof(s_addr));
	if (connd < 0) {
		RATS_ERR("failed to call connect()\n");
		return -1;
	}

	/* Receive evidence from server */
	int len_evidence = sizeof(attestation_evidence_t);
	char buffer[len_evidence];
	attestation_evidence_t evidence_server;
	int len_recv = recv(sockfd, buffer, sizeof(buffer), 0);
	if (len_recv < 0) {
		RATS_ERR("Failed to reveice evidence\n");
		return -1;
	} else {
		RATS_INFO("Successfully receive a evidence of size %d from server\n", len_recv);
	}
	memcpy(&evidence_server, buffer, sizeof(buffer));

	/* Verify evidence from server */
	rats_verifier_err_t ver_ret = librats_verify_evidence(&evidence_server, hash, NULL, NULL);
	if (ver_ret != RATS_VERIFIER_ERR_NONE) {
		RATS_ERR("Failed to verify evidence. Return code: %#x\n", ver_ret);
		return -1;
	} else {
		RATS_INFO("Evidence from the server is trusted\n");
	}

	if (mutual) {
		/* Collect evidence on the client side */
		attestation_evidence_t evidence_client;
		rats_attester_err_t ret = librats_collect_evidence(&evidence_client, hash);
		if (ret != RATS_ATTESTER_ERR_NONE) {
			RATS_ERR("Librats collect evidence failed. Return code: %#x\n", ret);
			return -1;
		} else {
			RATS_INFO("Successfully collect a evidence form client\n");
		}

		/* Send evidence to server */
		int len_send =
			send(sockfd, (char *)&evidence_client, sizeof(attestation_evidence_t), 0);
		if (len_send < 0) {
			RATS_ERR("Failed to send evidence\n");
			return -1;
		} else {
			RATS_INFO("Successfully send a evidence form client of size %d to server\n",
				  len_send);
		}
	}

	close(connd);
	return 0;
}

int main(int argc, char **argv)
{
	char *const short_options = "i:p:H:mh";
	// clang-format off
	struct option long_options[] = {
		{ "ip", required_argument, NULL, 'i' },
		{ "port", required_argument, NULL, 'p' },
		{ "hash", required_argument, NULL, 'H' },
		{ "mutual", no_argument, NULL, 'm' },
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 }
	};
	// clang-format on

	/* Set default command line arguments */
	char *srv_ip = DEFAULT_IP;
	int port = DEFAULT_PORT;
	char *hash_value = DEFAULT_HASH;
	bool mutual = false;

	int opt;
	do {
		opt = getopt_long(argc, argv, short_options, long_options, NULL);
		switch (opt) {
		case 'i':
			srv_ip = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'H':
			hash_value = optarg;
			break;
		case 'm':
			mutual = true;
			break;
		case -1:
			break;
		case 'h':
			puts("    Usage:\n\n"
			     "        librats-client   <options>   [arguments]\n\n"
			     "    Options:\n\n"
			     "        --ip/-i               set the listening ip address\n"
			     "        --port/-p             set the listening tcp port\n"
			     "        --hash/-H             set the hash value\n"
			     "        --mutual/-m           set to enable mutual attestation\n"
			     "        --help/-h             show the usage\n");
			exit(1);
		default:
			exit(1);
		}
	} while (opt != -1);

	return librats_client_startup(srv_ip, port, hash_value, mutual);
}
