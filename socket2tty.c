#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <assert.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <termios.h>
#include <linux/serial.h>
#include <asm-generic/ioctls.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <uci.h>

#define LISTENQ     	5
#define MAX_FD_SIZE 	128
#define LOCAL_TO_REMOTE		0
#define REMOTE_TO_LOCAL		1
#define MAX_BUF_SIZE 10240
#define STATUS_RECONNECTED (-5656)

#define GPIO_RS485_PIN "17"
#define GPIO_RS485_SET_HIGH "1"
#define GPIO_RS485_SET_LOW 	"0"

#define TCP_SERVER 0x1
#define TCP_CLIENT 0x2
#define UDP 	   0x3

#define RS485 0x4
#define RS232 0x5

#define TTY_BUF_MAX (255)
#define TTY_BUF_MAX_X2 (510)
#define TTY_BUF_MAX_X4 (1020)
#define TTY_BUF_MAX_X8 (2040)

#define LOG_SIZE (1024*128)

#define TTY_STATUS_IDLE (0)
#define TTY_STATUS_SEND (1)
#define TTY_STATUS_RECV (2)

int socket_log(char *filename, const char *format, ...);
#define socket_printf(fmt, args...)	do {	\
		socket_log("/tmp/serial.log", fmt, ##args); \
	} while(0)

struct tcp_server_fdset
{
    int client_cnt;
    int socket_fd[MAX_FD_SIZE];
    fd_set allfds;
    int maxfd;
};

struct global_para {
	FILE* log_fp;
	int baudrate;
	int bits;
	int stop;
	int flow_ctrl;
	char parity;
	int tty_mode;
	int tty_max_len;
	int tty_fd;
	int tty_status;
	char tty_name[32];
	char remote_ip[32];
	int remote_port;
	int local_port;
	int tcp_port;
	int socket_mode;
	int socket_fd;
	char* socket_buf;
	char* tty_buf;
	struct tcp_server_fdset *tcp_srv_fdset;
};

static struct global_para *global = NULL;

int tty_open(char* dev_name);
static int udp_write(int socket_fd, char *buf, int len);
static int udp_read(int socket_fd, char *buf, int len);

int socket_log(char *filename, const char *format, ...)
{
    char buf[256] = {0};
    int filesize = 0;
    struct stat statbuff;
    va_list args;

    if(!filename || !format || !global->log_fp) {
    	printf("socket_log null paras\n");
        return -1;
    }

    if((stat(filename, &statbuff) < 0) || (statbuff.st_size >= LOG_SIZE)) {
		fclose(global->log_fp);
		global->log_fp = fopen(filename, "w+");
		if(global->log_fp == NULL) {
			printf("fopen log file %s error\n", filename);
	        return -1;
		}
    }

    va_start(args, format);
    memset(buf, 0,sizeof(buf));
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    printf("%s",buf);

    fwrite(buf, strlen(buf), 1, global->log_fp);
	fflush(global->log_fp);

    return 0;
}

static char* uci_get(char* section, char* option)
{
	struct uci_context *uci_ctx;
	struct uci_ptr uci_p;
	char uci_options[64] = {0};

	snprintf(uci_options, sizeof(uci_options), "serial.@%s[0].%s", section, option);
	uci_ctx = uci_alloc_context();
	if(UCI_OK != uci_lookup_ptr(uci_ctx, &uci_p, uci_options, true))
	{
		uci_perror(uci_ctx, "no found!\n");
		return NULL;
	}

	uci_free_context(uci_ctx);
	return uci_p.o->v.string;
}

static int tcp_server_fdset_alloc(void)
{
	int i;

	global->socket_buf = malloc(MAX_BUF_SIZE);
	if(!global->socket_buf) {
		socket_printf("tcpServer global->socket_buf malloc fail!\n");
        return -1;
	}
	memset(global->socket_buf, 0, MAX_BUF_SIZE);

	global->tty_buf = malloc(MAX_BUF_SIZE);
	if(!global->tty_buf) {
		socket_printf("tcpServer global->tty_buf malloc fail!\n");
        return -1;
	}
	memset(global->tty_buf, 0, MAX_BUF_SIZE);

	if(global->socket_mode == TCP_SERVER) {
	    global->tcp_srv_fdset = (struct tcp_server_fdset *)malloc(sizeof(struct tcp_server_fdset));
	    if (!global->tcp_srv_fdset) {
			socket_printf("malloc tcp_server_fdset fail!\n");
	        return -1;
	    }

	    memset(global->tcp_srv_fdset, 0, sizeof(struct tcp_server_fdset));
	    for (i=0; i < MAX_FD_SIZE; i++) {
			global->tcp_srv_fdset->socket_fd[i] = -1;
	    }
	}
    return 0;
}

static void tcp_server_fdset_free(void)
{
	free(global->socket_buf);
	free(global->tty_buf);

    if (global->tcp_srv_fdset) {
        free(global->tcp_srv_fdset);
        global->tcp_srv_fdset = NULL;
    }
}

int global_deinit()
{
	fclose(global->log_fp);
	close(global->tty_fd);
	tcp_server_fdset_free();
	free(global);
	global = NULL;
}

int global_init()
{
	int socket_mode, tcp_port, remote_port, local_port, direction, ret=0;
	int baudrate=9600, bits=8, stop=1, flow_ctrl=0;
	char *tcp_protocol, *tty_mode;

	global = (struct global_para*)malloc(sizeof(struct global_para));
	if(!global) {
		printf("malloc global fail!\n");
		return -1;
	}
	memset(global, 0, sizeof(struct global_para));

	global->log_fp = fopen("/tmp/serial.log", "a+");
	if(global->log_fp == NULL) {
		printf("fopen log file error\n");
		goto fail;
	}

	global->baudrate = atoi(uci_get("serial", "baudrate"));
	global->bits = atoi(uci_get("serial", "databits"));
	global->stop = atoi(uci_get("serial", "stopbits"));
	global->parity = (uci_get("serial", "parity"))[0];
	global->flow_ctrl = atoi(uci_get("serial", "flowcontrol"));

	global->tty_max_len = atoi(uci_get("serial", "tty_max_len"));
	if(global->tty_max_len > MAX_BUF_SIZE) {
		global->tty_max_len = MAX_BUF_SIZE;
	} else if(global->tty_max_len < 0) {
		global->tty_max_len = TTY_BUF_MAX;
	}

	tty_mode = uci_get("serial", "mode");
	if(!strcmp(tty_mode, "rs232")) {
		global->tty_mode = RS232;
		strcpy(global->tty_name, "/dev/ttyACM1");
	} else if(!strcmp(tty_mode, "rs485")){
		global->tty_mode = RS485;
		strcpy(global->tty_name, "/dev/ttyACM0");
	} else {
		socket_printf("tty_mode %s error\n", global->tty_mode);
		goto fail;
	}

	socket_printf("[serial paras]tty_name %s, tty_mode %d, baudrate %d, databits %d, stopbits %d, flow_ctrl %d, parity %c\n",
		global->tty_name, global->tty_mode, global->baudrate, global->bits, global->stop, global->flow_ctrl, global->parity);

	global->socket_fd = -1;
	tcp_protocol = uci_get("network", "protocol");
	if(!strcmp(tcp_protocol, "tcpServer")) {
		global->socket_mode = TCP_SERVER;
		global->tcp_port = atoi(uci_get("network", "tcpPORT"));
	} else if(!strcmp(tcp_protocol, "tcpClient")) {
		global->socket_mode = TCP_CLIENT;
		global->tcp_port = atoi(uci_get("network", "tcpPORT"));
		strcpy(global->remote_ip, uci_get("network", "remoteIP"));
	} else if(!strcmp(tcp_protocol, "udp")) {
		global->socket_mode = UDP;
		strcpy(global->remote_ip, uci_get("network", "remoteIP"));
		global->remote_port = atoi(uci_get("network", "remotePORT"));
		global->local_port = atoi(uci_get("network", "localPORT"));
	} else {
		socket_printf("tcp_protocol %s error\n", tcp_protocol);
		goto fail;
	}

	socket_printf("tcp_protocol %s, socket_mode %d, remote_ip %s, remote_port %d, local_port %d, tcp_port %d\n",
		tcp_protocol, global->socket_mode, global->remote_ip, global->remote_port, global->local_port, global->tcp_port);

	global->tty_fd = tty_open(global->tty_name);
	if(global->tty_fd < 0) {
		socket_printf("open %s error\n", global->tty_name);
		goto fail;
	}

	if(tcp_server_fdset_alloc()) {
		socket_printf("tcp_server_fdset_alloc fail!\n");
		goto fail;
	}

	return 0;
fail:
	global_deinit();
	return -1;

}

void tcdrain_delay(void)
{
	int usec = 0, baudrate = 0;
	baudrate = global->baudrate;
	usec = (1 / (float)(baudrate / 10)) * 128 * 1000000 + 10000;
	usleep(usec);
}

int tty_set_rs485_mode()
{
	int export_fd, direction_fd;

	if(global->tty_mode != RS485) return 0;

	export_fd = open("/sys/class/gpio/export", O_WRONLY);
	if(-1 != export_fd) {
		if(-1 == write(export_fd, GPIO_RS485_PIN, sizeof(GPIO_RS485_PIN))) {
			close(export_fd);
		} else {
			close(export_fd);
		}
	}

	direction_fd = open("/sys/class/gpio/gpio17/direction", O_WRONLY);
	if(-1 == direction_fd) {
		socket_printf("open gpio direction file error\r\n");
		return -1;
	}
	if(-1 == write(direction_fd, "out", sizeof("out"))) {
		socket_printf("write operation direction error\n");
		close(direction_fd);
		return -1;
	}
	close(direction_fd);

	return 0;
}

int tty_set_gpio_value(char *set_value)
{
	int gpiovalue_fd;

	if(global->tty_mode != RS485) return 0;

	gpiovalue_fd = open("/sys/class/gpio/gpio17/value", O_WRONLY);
	if(-1 == gpiovalue_fd) {
		socket_printf("open value file error\r\n");
		return -1;
	}

	if(-1 == write(gpiovalue_fd, set_value, sizeof(set_value))) {
		socket_printf("write value %s operation value error\n", set_value);
		close(gpiovalue_fd);
		return -1;
	}
	close(gpiovalue_fd);

	return 0;
}

int tty_open(char* dev_name)
{
	int fd;
	fd = open(dev_name, O_RDWR|O_NOCTTY);
	if (fd < 0) {
		socket_printf("can`t open tty %s\n", dev_name);
		return -1;
	}

	if(fcntl(fd, F_SETFL, 0) < 0) {
		socket_printf("fcntl failed!\n");
		close(fd);
		return -1;
	} else {
		socket_printf("fcntl=%d\n",fcntl(fd, F_SETFL,0));
	}

	socket_printf("open tty success!\n");
	return fd;
}

int tty_send(int fd, char* buf, int len)
{
	int ret;

	tty_set_gpio_value(GPIO_RS485_SET_HIGH);
	ret = write(fd,buf,len);
	tcdrain(fd);
	tcdrain_delay();
	tty_set_gpio_value(GPIO_RS485_SET_LOW);

	if (len == ret ) {
		return ret;
	} else {
		socket_printf("tty send fail, TCOFLUSH\n");
		tcflush(fd,TCOFLUSH);
		return -1;
	}
	return -1;
}

int tty_recv(int fd, char* buf, int len)
{
	int fs_sel, baudrate, act_len=0, count;
	fd_set fs_read;
	struct timeval time;
	float usec = 0;

	tty_set_gpio_value(GPIO_RS485_SET_LOW);

	baudrate = global->baudrate;
	usec = (1 / (float)(baudrate / 10)) * 128 * 1000000;
	time.tv_sec = (int)usec / 1000000;
	time.tv_usec = (int)usec % 1000000 + 10000;

	while(1) {
		FD_ZERO(&fs_read);
		FD_SET(fd,&fs_read);

		if(act_len == 0) {
			time.tv_sec = 5;
			time.tv_usec = 0;
		} else {
			time.tv_sec = (int)usec / 1000000;
			time.tv_usec = (int)usec % 1000000 + 10000;
		}

		fs_sel = select(fd+1, &fs_read, NULL, NULL, &time);
		if (fs_sel == -1) {
			socket_printf("select error:%s.\n", strerror(errno));
			return act_len;
		}else if (fs_sel == 0) {
			return act_len;
		} else {
			if (FD_ISSET(fd, &fs_read)) {
				count = read(fd, buf+act_len, len-act_len);
				act_len = (count > 0) ? (act_len+count) : act_len;
				if(act_len >= len) {
					return act_len;
				}
			}
		}
	}
}

int tty_set_attr(void)
{
	struct termios options;
	struct serial_rs485 rs485conf;
	int baudrate_macro[] = {B460800, B115200, B38400, B19200, B9600, B4800};
	int baudrate_num[] =   { 460800,  115200,  38400,  19200,  9600,  4800};
	int i;

	if(tcgetattr(global->tty_fd,&options) != 0) {
		socket_printf("tcgetattr fail");
		return -1;
	}

	options.c_cflag|=(CLOCAL|CREAD ); /*CREAD 开启串行数据接收，CLOCAL并打开本地连接模式*/
	options.c_cflag &=~CSIZE;/*设置数据位*/

	options.c_iflag &= ~(IXON | IXOFF | IXANY);
	options.c_iflag &= ~(ICRNL | INLCR);
	options.c_oflag &= ~(OCRNL | ONLCR);

	//设置数据流控制
	switch(global->flow_ctrl)
	{
	case 0 ://不使用流控制
		options.c_cflag &= ~CRTSCTS;
		break;
	case 1 ://使用硬件流控制
		options.c_cflag |= CRTSCTS;
		  break;
	case 2 ://使用软件流控制
		options.c_cflag |= IXON | IXOFF | IXANY;
		break;
	}

	if(global->tty_mode == RS485) {
		tty_set_rs485_mode();
	}

	switch(global->bits) {
		case 7:
			options.c_cflag |=CS7;
			break;
		case 8:
			options.c_cflag |=CS8;
			break;
		default:
			break;
	}

	switch(global->parity) {
		case 'o':  /*奇校验*/
		case 'O':
			options.c_cflag |= PARENB;/*开启奇偶校验*/
			options.c_iflag |= (INPCK | ISTRIP);/*INPCK打开输入奇偶校验；ISTRIP去除字符的第八个比特  */
			options.c_cflag |= PARODD;/*启用奇校验(默认为偶校验)*/
			break;
		case 'e':/*偶校验*/
		case 'E':
			options.c_cflag |= PARENB; /*开启奇偶校验  */
			options.c_iflag |= ( INPCK | ISTRIP);/*打开输入奇偶校验并去除字符第八个比特*/
			options.c_cflag &= ~PARODD;/*启用偶校验*/
			break;
		case 'n': /*无奇偶校验*/
		case 'N':
			options.c_cflag &= ~PARENB;
			break;
		default:
			break;
	}

	for(i= 0; i < sizeof(baudrate_num) / sizeof(int); i++) {
		if	(global->baudrate == baudrate_num[i]) {
			cfsetispeed(&options, baudrate_macro[i]);
			cfsetospeed(&options, baudrate_macro[i]);
		}
	}

	if(global->stop == 1){/*设置停止位；若停止位为1，则清除CSTOPB，若停止位为2，则激活CSTOPB*/
		options.c_cflag &= ~CSTOPB;/*默认为一位停止位； */
	}
	else if(global->stop == 2) {
		options.c_cflag |= CSTOPB;/*CSTOPB表示送两位停止位*/
	}
	//只是串口传输数据，而不需要串口来处理，那么使用原始模式(Raw Mode)方式来通讯
	options.c_lflag  &= ~(ICANON | ECHO | ECHOE | ISIG);  /*Input*/
	options.c_oflag  &= ~OPOST;   /*Output*/

	/*设置最少字符和等待时间，对于接收字符和等待时间没有特别的要求时*/
	options.c_cc[VTIME] = 0;/*非规范模式读取时的超时时间；*/
	options.c_cc[VMIN]  = 0; /*非规范模式读取时的最小字符数*/
	tcflush(global->tty_fd ,TCIFLUSH);/*tcflush清空终端未完成的输入/输出请求及数据；TCIFLUSH表示清空正收到的数据，且不读取出来 */

	/*激活配置使其生效*/
	if((tcsetattr(global->tty_fd, TCSANOW, &options))!=0) {
		socket_printf("com set error");
		return -1;
	}

    return 0;
}

int tcp_server_socket_init(int port)
{
	int  socket_fd, reuse = 1;
	struct sockaddr_in srvaddr;
	struct timeval timeout = {5,0};

	socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_fd == -1) {
		socket_printf("create socket fail,erron:%d,reason:%s\n", errno, strerror(errno));
		goto err;
	}

	setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	bzero(&srvaddr,sizeof(srvaddr));
	srvaddr.sin_family = AF_INET;
	//inet_pton(AF_INET, ip, &srvaddr.sin_addr);
	srvaddr.sin_port = htons(port);
	srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(socket_fd, (struct sockaddr*)&srvaddr, sizeof(srvaddr)) == -1) {
		socket_printf("bind socket fail,erron:%d,reason:%s\n", errno, strerror(errno));
		goto err;
	}

	if(listen(socket_fd, LISTENQ)) {
		socket_printf("listen socket fail,erron:%d,reason:%s\n", errno, strerror(errno));
		goto err;
	}

	setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval));
	setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

	socket_printf("tcp server socket init srv_fd %d\n", socket_fd);
	return socket_fd;
err:
	close(socket_fd);
	socket_printf("tcp server socket init fail\n");
	return -1;
}

int tcp_server_accept(void)
{
    struct sockaddr_in client_addr;
    socklen_t client_addrlen = sizeof(client_addr);
    int client_fd=-1, i=0;
	fd_set *srvfds = &(global->tcp_srv_fdset->allfds);
	struct tcp_server_fdset *tcp_srv_fdset = global->tcp_srv_fdset;
	struct timeval tv;
	int socket_fd = global->socket_fd;

	FD_ZERO(srvfds);
	FD_SET(socket_fd, srvfds);
	tcp_srv_fdset->maxfd = socket_fd;
	tv.tv_sec = 0;
	tv.tv_usec = 0;

	select(tcp_srv_fdset->maxfd + 1, srvfds, NULL, NULL, &tv);
	if (FD_ISSET(socket_fd, srvfds)) {
		ACCEPT:
		client_fd = accept(socket_fd, (struct sockaddr*)&client_addr, &client_addrlen);
		if (client_fd == -1) {
			if (errno == EINTR) {
				goto ACCEPT;
			} else {
				socket_printf("accept fail,error:%s\n", strerror(errno));
				return -1;
			}
		}

		socket_printf("tcp server accept a new client: %s:%d fd %d\n",
			inet_ntoa(client_addr.sin_addr),  ntohs(client_addr.sin_port), client_fd);

		for (i = 0; i < MAX_FD_SIZE; i++) {
			if (tcp_srv_fdset->socket_fd[i] < 0) {
				tcp_srv_fdset->socket_fd[i] = client_fd;
				tcp_srv_fdset->client_cnt++;
				break;
			}
		}

		if (i == MAX_FD_SIZE) {
			socket_printf("too many clients.\n");
			return -1;
		}
	}

	return 0;
}

static int __tcp_write(int socket_fd, char *buf, int len)
{
	int ret, count, tmp_len=0, maxfd=0;
	fd_set writefds;
    struct timeval tv;

	FD_ZERO(&writefds);
	FD_SET(socket_fd, &writefds);
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	maxfd = socket_fd;
	ret = select(maxfd + 1, NULL, &writefds, NULL, &tv);
	if (ret == -1) {
		socket_printf("__tcp write select error -1, tmp_len 0x%x.\n", tmp_len);
		return 0;
	} else if (ret == 0) {
		return 0;
	}

	if (FD_ISSET(socket_fd, &writefds)) {
		if(tmp_len >= len) {
			socket_printf("__tcp write tmp_len 0x%x >= len 0x%x\n!", tmp_len, len);
			return tmp_len;
		}

		count = send(socket_fd, buf+tmp_len, len-tmp_len, MSG_NOSIGNAL);
		if(count <= 0) {
			 socket_printf("__tcp write send %d 0x%x 0x%x, errno %s\n!", count, tmp_len, len, strerror(errno));
			 return 0;
		}

		tmp_len += count;
	}

	return tmp_len;
}

static int tcp_read(int socket_fd, char *buf, int len)
{
	int ret, count, maxfd=0, tmp_len=0, prev=0, next=0;
	fd_set readfds;
    struct timeval tv;

	FD_ZERO(&readfds);
	FD_SET(socket_fd, &readfds);
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	maxfd = socket_fd;
	ret = select(maxfd + 1, &readfds, NULL, NULL, &tv);
	if (ret == -1) {
		socket_printf("tcp read select error %s.\n", strerror(errno));
		return 0;
	} else if (ret == 0) {
		return 0;
	}

	if (FD_ISSET(socket_fd, &readfds)) {
		count = recv(socket_fd, buf+tmp_len, len-tmp_len, 0);
		if(count <= 0) {
			socket_printf("tcp read recv errno %s! tmp_len %d, len %d\n", strerror(errno), tmp_len, len);
			return 0;
		}
		tmp_len += count;
	}

	return tmp_len;
}

static int tcp_write(int socket_fd, char *buf, int len)
{
	int i, client_fd, count=0, ret=-1;

	if(global->socket_mode == TCP_SERVER) {
		for (i = 0; i < global->tcp_srv_fdset->client_cnt; i++) {
			client_fd = global->tcp_srv_fdset->socket_fd[i];
			if (client_fd != -1) {
				count = __tcp_write(client_fd, buf, len);
				if(count != len) {
					socket_printf("mode %d tcp write len 0x%x != count 0x%x\n", global->socket_mode, len, count);
					ret = -1;
					continue;
				}
				ret = count;
			}
		}
	} else {
		if(socket_fd != -1) {
			count = __tcp_write(socket_fd, buf, len);
			if(count != len) {
				socket_printf("mode %d tcp write len 0x%x != count 0x%x\n", global->socket_mode, len, count);
				ret = -1;
			}
		}
		ret = count;
	}

	return ret;
}

int tcp_update_netstatus(void)
{
	int i, client_fd;
	struct tcp_info info;
	int info_len = sizeof(info);

	if(global->socket_mode == TCP_SERVER) {
		for (i = 0; i < global->tcp_srv_fdset->client_cnt; i++) {
			client_fd = global->tcp_srv_fdset->socket_fd[i];
			if (client_fd != -1) {
				getsockopt(client_fd, IPPROTO_TCP, TCP_INFO, &info, (socklen_t *)&info_len);
				if(info.tcpi_state != TCP_ESTABLISHED) {
					socket_printf("[%d] fd %d tcp status %d != TCP_ESTABLISHED! delete fd!\n",
						i, client_fd, info.tcpi_state);
					global->tcp_srv_fdset->socket_fd[i] = -1;
					global->tcp_srv_fdset->client_cnt--;
					close(client_fd);
				}
			}
		}
		return 0;
	} else {
		getsockopt(global->socket_fd, IPPROTO_TCP, TCP_INFO, &info, (socklen_t *)&info_len);
		if(info.tcpi_state != TCP_ESTABLISHED) {
			global->socket_fd = -1;
			socket_printf("tcp client status %d, try reconnet server...\n", info.tcpi_state);
			close(global->socket_fd);
			return -1;
    	} else {
			return 0;
		}
	}
}

int tcp_client_socket_init(char* ip, int port)
{
	int client_fd, ret, reuse=1;
	struct sockaddr_in srvaddr;
	struct timeval timeout = {5,0};

	client_fd = socket(AF_INET,SOCK_STREAM,0);

	bzero(&srvaddr,sizeof(srvaddr));
	srvaddr.sin_family = AF_INET;
	srvaddr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &srvaddr.sin_addr);

reconnect:
	ret = connect(client_fd,(struct sockaddr*)&srvaddr,sizeof(srvaddr));
	if (ret < 0) {
		socket_printf("connect fail,error:%s\n", strerror(errno));
		sleep(1);
		goto reconnect;
	}

	setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval));
	setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

	socket_printf("[tcp client] client_fd %d success connect server ip %s port %d\n",
		client_fd, inet_ntoa(srvaddr.sin_addr), ntohs(srvaddr.sin_port));
	return client_fd;
}

void *thread_tcp_connect(void *arg)
{
	int socket_fd = -1;

	reconnected:
	if(global->socket_mode == TCP_SERVER) {
		socket_fd = tcp_server_socket_init(global->tcp_port);
		if(socket_fd < 0) {
			goto reconnected;
		}
	} else {
		socket_fd = tcp_client_socket_init(global->remote_ip, global->tcp_port);
		if(socket_fd < 0) {
			goto reconnected;
		}
	}

	global->socket_fd = socket_fd;
	socket_printf("tcp connect socket_mode %d, socket_fd %d\n", global->socket_mode, global->socket_fd);

	while (1) {
		usleep(500);

		if(global->socket_mode == TCP_SERVER) {
			tcp_server_accept();
		}

		if(tcp_update_netstatus()) {
			goto reconnected;
		}
	}

	return NULL;
}

static int udp_write(int socket_fd, char *buf, int len)
{
	int count;
    struct sockaddr_in remote_addr;
	socklen_t addrlen = sizeof(remote_addr);

	memset(&remote_addr, 0, sizeof(remote_addr));
	remote_addr.sin_family = AF_INET;
	inet_pton(AF_INET, global->remote_ip, &remote_addr.sin_addr);
	remote_addr.sin_port = htons(global->remote_port);

	count = sendto(socket_fd, buf, len, 0, (struct sockaddr *)&remote_addr, addrlen);
	if(count <= 0) {
		socket_printf("udp write sendto fd %d %d != 0x%x fail, errno %d!\n", socket_fd, count, len, errno);
		return -1;
	}
	return count;
}

static int udp_read(int socket_fd, char *buf, int len)
{
	int count;
    struct sockaddr_in remote_addr;
	socklen_t addrlen = sizeof(remote_addr);

	memset(&remote_addr, 0, sizeof(remote_addr));
	remote_addr.sin_family = AF_INET;
	inet_pton(AF_INET, global->remote_ip, &remote_addr.sin_addr);
	remote_addr.sin_port = htons(global->remote_port);

	count = recvfrom(socket_fd, buf, len, 0, (struct sockaddr *)&remote_addr, &addrlen);
	if(count <= 0){
		socket_printf("udp_read read fd %d count %d fail, errno %d!\n", socket_fd, count, errno);
		return -1;
	}

	return count;
}

void* thread_udp_connect(void* args)
{
    int local_fd, ret;
    struct sockaddr_in remote_addr;
    struct sockaddr_in local_addr;
	socklen_t addrlen = sizeof(remote_addr);
	struct timeval timeout = {5,0};
	char* remote_ip = global->remote_ip;
	int remote_port = global->remote_port;
	int local_port = global->local_port;

    local_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(local_fd < 0) {
        socket_printf("create socket fail!\n");
		return NULL;
    }

	memset(&local_addr, 0, sizeof(local_addr));
	local_addr.sin_family = AF_INET;
	//inet_pton(AF_INET, ip, &local_addr.sin_addr);
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	local_addr.sin_port = htons(local_port);

	setsockopt(local_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval));
	setsockopt(local_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

	ret = bind(local_fd, (struct sockaddr*)&local_addr, sizeof(local_addr));
	if(ret < 0) {
		socket_printf("udp socket2tty socket bind fail!\n");
		close(local_fd);
		return NULL;
	}

	memset(&remote_addr, 0, sizeof(remote_addr));
	remote_addr.sin_family = AF_INET;
	inet_pton(AF_INET, remote_ip, &remote_addr.sin_addr);
	remote_addr.sin_port = htons(remote_port);

	global->socket_fd = local_fd;
	return NULL;
}

int socket_request_xfer(int socket_fd)
{
	int rd_len, wr_len, i=0;
	int socket_mode = global->socket_mode;
	char* socket_buf = global->socket_buf;
	struct timeval begin_tv, end_tv;
	float interval_tv;

	gettimeofday(&begin_tv, NULL);

	if(socket_mode == UDP) {
		rd_len = udp_read(socket_fd, socket_buf, MAX_BUF_SIZE);
	} else {
		rd_len = tcp_read(socket_fd, socket_buf, MAX_BUF_SIZE);
	}

	if(rd_len <= 0) {
		return -1;
	}

	while (global->tty_status == TTY_STATUS_RECV) {
		if(i++ >= 5000){
			socket_printf("socket request tty status != TTY_STATUS_IDLE!\n");
			return -1;
		}
		usleep(1000);
	};

	global->tty_status = TTY_STATUS_SEND;
	wr_len = tty_send(global->tty_fd, socket_buf, rd_len);
	global->tty_status = TTY_STATUS_IDLE;

	gettimeofday(&end_tv, NULL);
	interval_tv = 1000000*(end_tv.tv_sec-begin_tv.tv_sec) + (end_tv.tv_usec-begin_tv.tv_usec);
	socket_printf("[%fus]request socket read %d, tty write %d\n", interval_tv, rd_len, wr_len);
	if(wr_len != rd_len) {
		return -1;
	}

	return 0;
}

void *thread_socket_request(void *arg)
{
	int rd_len, wr_len, ret, i;

	while (1)
	{
		usleep(5000);

		if(global->socket_mode == TCP_SERVER) {
			for (i = 0; i < global->tcp_srv_fdset->client_cnt; i++) {
				if(global->tcp_srv_fdset->socket_fd[i] == -1) {
					continue;
				}
				ret = socket_request_xfer(global->tcp_srv_fdset->socket_fd[i]);
			}
		} else {
			if(global->socket_fd == -1) {
				continue;
			}
			ret = socket_request_xfer(global->socket_fd);
		}
	}

	return NULL;
}

void *thread_tty_report(void *arg)
{
	struct timeval begin_tv, end_tv;
	float interval_tv;
	int rd_len, wr_len;

	while(1) {
		usleep(1000);
		gettimeofday(&begin_tv, NULL);

		if(global->tty_status == TTY_STATUS_SEND) {
			continue;
		}

		global->tty_status = TTY_STATUS_RECV;
		rd_len = tty_recv(global->tty_fd, global->tty_buf, global->tty_max_len);
		global->tty_status = TTY_STATUS_IDLE;
		if(rd_len <= 0) {
			continue;
		}

		if (global->socket_mode == UDP) {
			wr_len = udp_write(global->socket_fd, global->tty_buf, rd_len);
		} else {
			wr_len = tcp_write(global->socket_fd, global->tty_buf, rd_len);
		}

		gettimeofday(&end_tv, NULL);
		interval_tv = 1000000*(end_tv.tv_sec-begin_tv.tv_sec) + (end_tv.tv_usec-begin_tv.tv_usec);
		socket_printf("[%fus] report tty read %d, socket write %d\n", interval_tv, rd_len, wr_len);
	}

	return NULL;
}

int main(int argc, char** argv)
{
	pthread_t accept_pd, request_pd, report_pd;
	int *join_val;
	void* (*accept_fn) (void*);

	if(global_init()) {
		return -1;
	}

	if (tty_set_attr() < 0) {
		return -1;
	}

	if(global->socket_mode == UDP) {
		accept_fn = thread_udp_connect;
	} else {
		accept_fn = thread_tcp_connect;
	}

	if (pthread_create(&accept_pd, NULL, accept_fn, NULL) != 0) {
		socket_printf("Error creating thread_tcp_accept\n");
	}

	if (pthread_create(&request_pd, NULL, thread_socket_request, NULL) != 0) {
		socket_printf("Error creating thread_tcp_request\n");
	}

	if (pthread_create(&report_pd, NULL, thread_tty_report, NULL) != 0) {
		socket_printf("Error creating thread_tty_report\n");
	}

	if (pthread_join(accept_pd, (void **)&join_val)) {
		socket_printf("Failed to join accept_pd\n");
	}
	if (pthread_join(request_pd, (void **)&join_val)) {
		socket_printf("Failed to join request_pd\n");
	}
	if (pthread_join(report_pd, (void **)&join_val)) {
		socket_printf("Failed to join report_pd\n");
	}

	global_deinit();
	return 0;
}

