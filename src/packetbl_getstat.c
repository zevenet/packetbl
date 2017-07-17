#include "packetbl.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


#ifdef USE_SOCKSTAT
int main(int argc, char **argv) {
	struct sockaddr_un sockinfo;
	char *socketpath = SOCKSTAT_PATH;
	char buf[1024];
	int sockfd;
	int connectret;
	ssize_t readret;

	/* Process command line arguments, if any. */
	if (argc > 1) {
		if (argv[1] != NULL) {
			socketpath = argv[1];
		}
	}

	/* Create a UNIX domain socket. */
	sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	/* Connect to our predetermined socket. */
	sockinfo.sun_family = AF_UNIX;
	strncpy(sockinfo.sun_path, socketpath, sizeof(sockinfo.sun_path));

	connectret = connect(sockfd, (struct sockaddr *) &sockinfo, sizeof(sockinfo));
	if (connectret < 0) {
		perror("connect");
		exit(EXIT_FAILURE);
	}

	/* Read all the data available. */
	while (1) {
		readret = read(sockfd, buf, sizeof(buf));
		if (readret <= 0) break;
		write(STDOUT_FILENO, buf, readret);
	}

	/* All done! */
	close(sockfd);

	return 0;
}

#else
int main() {
	fprintf(stderr, "PacketBL was not compiled with socket statistics support!\n");
	return 1;
}
#endif

