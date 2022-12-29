#include "cmu_packet.h"
#include "cmu_tcp.h"
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>


int window_init(window_t *win,  
                    cmu_socket_t *sock){
    /* 握手和挥手的时候会处理好 */
    // win->last_ack_received = last_ack_received;
    // win->last_seq_received = last_seq_received;
    win->next_seq_expected = win->last_seq_read;
    win->ack_num = 0;
    win->send_window_size = WINDOW_INITIAL_WINDOW_SIZE;
    win->recv_window_size = WINDOW_INITIAL_WINDOW_SIZE;
    win->last_ack_recv = 0;
    win->last_byte_send = 0;
    win->max_index = 0;
    /* 初始化窗口大小在握手中进行 */
    // win->adv_window = get_window_size(WINDOW_INITIAL_ADVERTISED);
    // win->my_adv_window = get_window_size(WINDOW_INITIAL_ADVERTISED);
    win->timeout_interval = WINDOW_INITIAL_RTT;
    win->estimate_rtt = WINDOW_INITIAL_RTT;
    /* 未开始采样 */
    win->send_seq = -1;
    /* 设定初始RTT */
    win->recv_header.next = NULL;

    /* 初始化信号处理函数，以便超时能够访问window */
    time_out(0,win);
    
    /* 初始化信号处理函数，以便超时能够访问socket */
    last_time_wait(0,sock);
    return EXIT_SUCCESS;
}


void slide_window_activate(window_t *win, cmu_socket_t *sock){
    /* 检查缓冲区是否有数据，如果有数据转移至发送窗口内 */
    int buf_len = sock->sending_len;
    if(buf_len > 0 && (win->max_index == win->last_ack_recv)){
        copy_string_to_buffer(win,sock->sending_buf,sock->sending_len);
        sock->sending_len = 0;
        free(sock->sending_buf);
		sock->sending_buf = NULL;
    }
    // fprintf(win->log,"activate %d, %d(DATA), %d(LAR), %d(LFS)\n",sock->state,win->DAT,win->LAR,win->LFS);

    /* 有数据需要发送 */
    if(win->DAT > win->LAR){
        slide_window_send(win,sock);
    }
    if(win->DAT == win->LAR && sock->state == TCP_CLOSE_WAIT){
        char *rsp = create_packet_buf(sock->my_port, sock->their_port, 
                sock->window.last_ack_received,
                sock->window.last_seq_received, 
                DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK|FIN_FLAG_MASK,
                        /*TODO*/win->my_adv_window, 0, NULL, NULL, 0);
        sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, 
                    (struct sockaddr*) &(sock->conn), sizeof(sock->conn));
        free(rsp);
        sock->state = TCP_LAST_ACK;
    }
}