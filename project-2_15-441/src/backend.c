/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the TCP in the Wild course project developed for the
 * Computer Networks course (15-441/641) taught at Carnegie Mellon University.
 *
 * No part of the project may be copied and/or distributed without the express
 * permission of the 15-441/641 course staff.
 *
 *
 * This file implements the CMU-TCP backend. The backend runs in a different
 * thread and handles all the socket operations separately from the application.
 *
 * This is where most of your code should go. Feel free to modify any function
 * in this file.
 */

#include "backend.h"

#include <math.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define MIN3(A,B,C) ((A)>(B)?(B):(A))>C?C:((A)>(B)?(B):(A))
bool timer_on = false;
// int last_advertised_window=MAX_RCV_BUFFER;

/**
 * Tells if a given sequence number has been acknowledged by the socket.
 *
 * @param sock The socket to check for acknowledgements.
 * @param seq Sequence number to check.
 *
 * @return 1 if the sequence number has been acknowledged, 0 otherwise.
 */
int has_been_acked(cmu_socket_t *sock, uint32_t seq) {
  int result;
  while (pthread_mutex_lock(&(sock->window.ack_lock)) != 0) {
  }
  result = after(sock->window.last_acked_recv, seq);
  pthread_mutex_unlock(&(sock->window.ack_lock));
  return result;
}
void handshake_send(cmu_socket_t *sock, uint8_t *data, int buf_len, int flag);


int deliver_data(cmu_socket_t *sock, char *pkt){
    if(sock->received_buf == NULL){
        sock->received_buf = malloc(get_payload_len(pkt));
    }
    else{
        sock->received_buf = realloc(sock->received_buf, sock->received_len + get_payload_len(pkt));
    }
    memcpy(sock->received_buf + sock->received_len, get_payload(pkt), get_payload_len(pkt));
    sock->received_len += get_payload_len(pkt);
    return MAX_RCV_BUFFER - sock->received_len;
}


void insert_pkt_into_list(recv_slot *header, char *pkt){
    recv_slot *cur = header;
    recv_slot *prev;
    recv_slot *slot = (recv_slot *)malloc(sizeof(recv_slot));
    int myseq = get_seq(pkt);
    uint8_t* p = (uint8_t*)malloc(get_plen(pkt));
    memcpy(p, pkt, get_plen(pkt));
    slot->msg = p;
    while(1){
        if(cur->next == NULL){
            cur->next = slot;
            slot->next = NULL;
            break;
        }
        prev = cur;
        cur = cur->next;
        int seq = get_seq(cur->msg);
        if(myseq > seq)
            continue;
        else{
            slot->next = cur;
            prev->next = slot;
            break;
        }
    }
    return;
    
}

uint32_t get_time_gap(send_slot* slot){
    struct timeval now;
    struct timeval gap;
    gettimeofday(&now, NULL);
    if ((now.tv_usec - slot->timeout.tv_usec)<0) {
      gap.tv_sec = now.tv_sec - slot->timeout.tv_sec - 1;
      gap.tv_usec = 1000000 + now.tv_usec - slot->timeout.tv_usec;
    }
    else {
      gap.tv_sec = now.tv_sec - slot->timeout.tv_sec;
      gap.tv_usec = now.tv_usec - slot->timeout.tv_usec;
    }
    return 1000000 * gap.tv_sec + gap.tv_usec;
}

void update_rtt(window_t* window, send_slot* slot) {
    uint32_t time_gap = get_time_gap(slot);
    window->RTT = (uint32_t)((window->RTT)*0.875 + time_gap*0.125);//更新RTT
    window->DevRTT = (uint32_t)((window->DevRTT)*0.75 + (abs(time_gap - window->RTT))*0.25);//更新DevRTT
    window->RTO = (window->RTT) + (window->DevRTT) * 4;//更新RTO
}


void check_timeout(cmu_socket_t *sock){
  printf("check timeout\n");
    window_t* window = &sock->window;
    send_slot* ss = &window->send_header;
    send_slot* next = NULL;
    uint32_t rto = window->RTO;
    while((next = ss->next)!=NULL){
      ss->next = next->next;
      if(get_time_gap(next) > rto){
        printf("timeout resend\n");
        send_header(next->msg);
        sendto(sock->socket, next->msg, get_plen(next->msg), 0, (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
        gettimeofday(&next->timeout, NULL);
      }
    }
}

/**
 *
 * Updates the socket information to represent the newly received packet.
 *
 * In the current stop-and-wait implementation, this function also sends an
 * acknowledgement for the packet.
 *
 * @param sock The socket used for handling packets received.
 * @param pkt The packet data received by the socket.
 */
void handle_message_sw(cmu_socket_t *sock, uint8_t *pkt) {
  printf("in_func: handle_message_sw\n");
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  window_t *window = &sock->window;
  read_header(hdr);
  uint8_t flags = get_flags(hdr);
  uint32_t ack = get_ack(pkt);
  uint32_t seq = get_ack(pkt);
  switch (flags) {
    case ACK_FLAG_MASK: {
      window->adv_win_size = get_advertised_window(pkt);
      if(ack > window->last_acked_recv){
        window->ack_num = 0;
        window->last_acked_recv = ack;
        send_slot* ss = &window->send_header;
        send_slot* next = NULL;
        while((next = ss->next)!=NULL && get_seq(next->msg) < ack){
          if(next == window->send_header.next) update_rtt(window, next);
          ss->next = next->next;
          window->send_length -= (get_payload_len(next->msg));
          free(next->msg);
          free(next);
        }
      }else if(ack == window->last_acked_recv){
        window->ack_num++;
        if(window->ack_num == 3){
          send_slot* ss = &window->send_header;
          send_slot* next = ss->next;
          sendto(sock->socket, next->msg, get_plen(next->msg), 0, (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
          gettimeofday(&next->timeout, NULL);
          window->ack_num = 0;
        }
      }
      show_window(&sock->window);
      break;
    }
    // beginning of handshake in server. - wgy
    case SYN_FLAG_MASK: {
      if (get_hlen(hdr) != get_plen(hdr)) break;
      sock->window.last_seq_read = get_seq(hdr);
      sock->window.next_seq_expected = get_seq(hdr) + 1;
      window->adv_win_size = get_advertised_window(hdr);
      printf("recver told sender adv_win_size:%d\n", window->adv_win_size);
      handshake_send(sock, NULL, 0, (SYN_FLAG_MASK | ACK_FLAG_MASK));
      show_window(&sock->window);
      break;
    }

    default: {
      uint32_t seq = get_seq(hdr);
      show_window(&sock->window);
      if (seq == window->next_seq_expected) {
        printf("accept data seq == window->next_seq_expected");
        uint32_t received_num = 0;
      
        window->last_seq_read = seq;
        window->next_seq_expected = (seq + get_payload_len(pkt));
        

        deliver_data(sock, pkt);

        recv_slot* slot = window->recv_header.next;
        recv_slot* prev = &window->recv_header;
        //! we can't ensure the seq always increment because uint32 is limited, so maybe we should find a better method to resolve it later
        while(slot != NULL && (window->next_seq_expected == get_seq(slot->msg))){
          // Make sure there is enough space in the buffer to store the payload.
          deliver_data(sock, slot->msg);
          window->last_seq_read = window->next_seq_expected;
          window->next_seq_expected = (window->next_seq_expected + get_payload_len(slot->msg));
          prev->next = slot->next;
          free(slot->msg);
          free(slot);
          slot = prev->next;
        }
      }else{
        printf("cache data seq != window->next_seq_expected");
        insert_pkt_into_list(&window->recv_header, pkt);
      }


      socklen_t conn_len = sizeof(sock->conn);
      // No payload.
      uint8_t *payload = NULL;
      uint16_t payload_len = 0;
      uint8_t flags = ACK_FLAG_MASK;
      uint16_t adv_window = WINDOW_INITIAL_WINDOW_SIZE - sock->received_len;
      printf("rcver send adv_win_size:%d\n", adv_window);
      uint8_t *response_packet = create_packet(sock->my_port, ntohs(sock->conn.sin_port), window->last_acked_recv, window->next_seq_expected, 
                                  sizeof(cmu_tcp_header_t), sizeof(cmu_tcp_header_t) + payload_len, flags, adv_window, 
                                  0, NULL, payload, payload_len);
      send_header((cmu_tcp_header_t *)response_packet);
      sendto(sock->socket, response_packet, sizeof(cmu_tcp_header_t) + payload_len, 0, (struct sockaddr *)&(sock->conn), conn_len);
      free(response_packet);
    }
  }
  printf("    out_func: handle_message_sw\n");
}

/**
 * Checks if the socket received any data.
 *
 * It first peeks at the header to figure out the length of the packet and then
 * reads the entire packet.
 *
 * @param sock The socket used for receiving data on the connection.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information.
 * MSG_PEEK: still retain data in stream after reading it.
 */
bool check_for_data(cmu_socket_t *sock, cmu_read_mode_t flags) {
  bool time_out = false;
  cmu_tcp_header_t hdr;
  uint8_t *pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {}
  switch (flags) {
    case NO_FLAG:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), MSG_PEEK, (struct sockaddr *)&(sock->conn), &conn_len);
      break;
    case TIMEOUT: {
      // Using `poll` here so that we can specify a timeout.
      struct pollfd ack_fd;
      ack_fd.fd = sock->socket;
      ack_fd.events = POLLIN;
      // Timeout after 3 seconds.
      if (poll(&ack_fd, 1, 3000) <= 0) {
        time_out = true;
        break;
      }
    }
    // Fallthrough.
    case NO_WAIT:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),&conn_len);
      break;
    default:
      perror("ERROR unknown flag");
  }

  if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
    plen = get_plen(&hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0, (struct sockaddr *)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    handle_message_sw(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  sleep(1);

  return time_out;
}

/**
 * Breaks up the data into packets and sends a single packet at a time.
 * You should most certainly update this function in your implementation.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
void sw_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  printf("in sw_send: buf_len: %d\n", buf_len);
  uint8_t *msg;
  uint8_t *data_offset = data;
  size_t conn_len = sizeof(sock->conn);
  window_t *window = &sock->window;
  uint32_t seq;
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint16_t adv_window = 1;  // no usage
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;
  uint8_t flags = 0;
  int sockfd = sock->socket;
  uint32_t ack = sock->window.next_seq_expected;
  while (buf_len != 0) {
    printf("in sender:adv_win_size:%d, last_seq_sent:%d, last_acked_recv:%d\n", window->adv_win_size, window->last_acked_recv, window->last_acked_recv);
    seq = window->last_byte_send + 1;

    uint32_t send_len = MIN3(window->adv_win_size - window->send_length, MAX_LEN, buf_len);

    if(send_len <= 0) send_len = 1;

    uint16_t plen = hlen + send_len;
    uint8_t *payload = data_offset;
    buf_len -= send_len;
  
    msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window, ext_len, ext_data, payload, send_len);
    sendto(sockfd, msg, get_plen(msg), 0, (struct sockaddr *)&(sock->conn), conn_len);
    send_header(msg);
    show_window(window);
    window->last_byte_send += send_len;
    window->send_length += send_len;

    send_slot *slot = malloc(sizeof(send_slot));
    slot->msg = msg;
    gettimeofday(&slot->timeout, NULL);

    send_slot* ss = &window->send_header;
    send_slot* next = NULL;
    while((next = ss->next)!=NULL){
      ss = next;
    }
    ss->next = slot;
    slot->next = NULL;
    
    data_offset += send_len;    
    seq += send_len;

    check_for_data(sock, NO_WAIT);//!!!检查并更新window
  }
}


bool handle_handshake(cmu_socket_t *sock, uint8_t *data, int buf_len,
                      uint8_t *pkt) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  if (pkt == NULL) return false;
  read_header(hdr);
  int flag = get_flags(hdr);
  bool this_flag = true;
  switch (flag) {
    case (SYN_FLAG_MASK | ACK_FLAG_MASK): {
      printf("ack:%d,last_acked_recv:%d,last_byte-send:%u\n", get_ack(hdr), sock->window.last_acked_recv,sock->window.last_byte_send+2);
      if (get_hlen(hdr) != get_plen(hdr)) {
        this_flag = false;
        break;
      }
      //show_window(&sock->window);
      //exit(0);
      if (get_ack(hdr) != sock->window.last_acked_recv+1) {
        this_flag = false;
        break;
      }
      sock->window.last_acked_recv = get_ack(hdr);
      sock->window.last_byte_send = get_ack(hdr)-1;
      sock->window.last_seq_read = get_seq(hdr);
      sock->window.next_seq_expected = get_seq(hdr) + 1;
      sock->window.ack_num = 0;
      sock->window.adv_win_size = get_advertised_window(hdr);
      sock->window.RTT = WINDOW_INITIAL_RTT*1000;//初始化在握手过程中建立
      sock->window.DevRTT = 0;
      sock->window.RTO = sock->window.RTT;
      show_window(&sock->window);
      handshake_send(sock, data, buf_len, ACK_FLAG_MASK);
      break;
    }
    // when server receive the third handshake package, they regard it as normal
    // data package. when server receive, they send an ack package, so the block
    // should also handle it when in initiator.
    case ACK_FLAG_MASK: {
      if (sock->type == TCP_LISTENER &&
          get_ack(hdr) != sock->window.last_acked_recv+1) {
        this_flag = false;
        break;
      }
      if (sock->type == TCP_LISTENER) {
        set_flags(hdr, 0);
        sock->window.last_acked_recv = get_ack(hdr);
        sock->window.last_byte_send = get_ack(hdr)-1;
        sock->window.last_seq_read = get_seq(hdr);
        //sock->window.next_seq_expected = get_seq(hdr) + get_payload_len(hdr) - 1;  
        sock->window.ack_num = 0;
        sock->window.adv_win_size = get_advertised_window(hdr);
        sock->window.RTT = WINDOW_INITIAL_RTT*1000;//初始化在握手过程中建立
        sock->window.DevRTT = 0;
        sock->window.RTO = sock->window.RTT;
      }
      show_window(&sock->window);
      handle_message_sw(sock, pkt);

      break;
    }
    default:
      this_flag = false;
      break;
  }
  free(pkt);
  return this_flag;
}

/**
 * if return value is not null, we should release pkt after using.
 * in handshake procedure, we use timeout check to vetify
 */
uint8_t *wait_check(cmu_socket_t *sock) {
  cmu_tcp_header_t hdr;
  uint8_t *pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;
  struct pollfd ack_fd;
  ack_fd.fd = sock->socket;
  ack_fd.events = POLLIN;
  if (poll(&ack_fd, 1, 3000) <= 0) {
    return NULL;
  }
  len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
                 MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
                 &conn_len);

  if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
    plen = get_plen(&hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                   (struct sockaddr *)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    return pkt;
  }
  return NULL;
}

void handshake_send(cmu_socket_t *sock, uint8_t *data, int b_len, int flag) {
  uint8_t *msg;
  uint8_t *data_offset = NULL;
  int buf_len = 0;
  if (flag == ACK_FLAG_MASK) {
    data_offset = data;
    buf_len = b_len;
  }

  size_t conn_len = sizeof(sock->conn);
  int sockfd = sock->socket;
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint32_t seq = sock->window.last_acked_recv;
  uint32_t ack = sock->window.next_seq_expected;
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t adv_window = WINDOW_INITIAL_WINDOW_SIZE;
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;
  uint16_t payload_len = MIN3(sock->window.adv_win_size-sock->window.send_length, (uint16_t)buf_len, (uint16_t)MSS);
  uint8_t *payload = data_offset;
  uint16_t plen = hlen + payload_len;
  uint8_t flags = flag;

  msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                      ext_len, ext_data, payload, payload_len);
  sock->window.last_byte_send = seq + payload_len - 1;
  sock->window.send_length = payload_len;
  
  while (1) {
    // for all three handshakes send and handle.
    send_header((cmu_tcp_header_t *)msg);
    sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn), conn_len);
    if (handle_handshake(sock, data, b_len, wait_check(sock))) {
      break;
    }else if(flag == SYN_FLAG_MASK || flag == (SYN_FLAG_MASK|ACK_FLAG_MASK)){
      break;
    }
  }
  if (data_offset != NULL && (buf_len - payload_len) > 0)
    sw_send(sock, data_offset + payload_len, buf_len - payload_len);
}

void *begin_backend(void *in) {
  printf("    in_func: begin_background\n");
  cmu_socket_t *sock = (cmu_socket_t *)in;
  // int adv_win_size = MAX_RCV_BUFFER;
  int death, buf_len, send_signal;
  uint8_t *data = NULL;

  // Here we prepare initaitor to start the handshake transaction
  if (sock->type == TCP_INITIATOR) {
    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    buf_len = sock->sending_len;
    if (buf_len != 0) {
      data = malloc(buf_len);
      memcpy(data, sock->sending_buf, buf_len);
      sock->sending_len = 0;
      free(sock->sending_buf);
      sock->sending_buf = NULL;
    }
    pthread_mutex_unlock(&(sock->send_lock));
    handshake_send(sock, data, buf_len, SYN_FLAG_MASK);
    printf("    handshake done!\n");
    free(data);
  }

  while (1) {
    while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
    }
    death = sock->dying;
    pthread_mutex_unlock(&(sock->death_lock));

    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    buf_len = sock->sending_len;

    if (death && buf_len == 0) {
      break;
    }
    check_timeout(sock);

    if (buf_len > 0) {
      data = malloc(buf_len);
      memcpy(data, sock->sending_buf, buf_len);
      sock->sending_len = 0;
      free(sock->sending_buf);
      sock->sending_buf = NULL;
      pthread_mutex_unlock(&(sock->send_lock));
      sw_send(sock, data, buf_len);
      free(data);
    } else {
      pthread_mutex_unlock(&(sock->send_lock));
    }
    check_for_data(sock, NO_WAIT);

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }

    send_signal = sock->received_len > 0;

    pthread_mutex_unlock(&(sock->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(sock->wait_cond));
    }
  }

  pthread_exit(NULL);
  printf("    out_func: begin_background\n");
  return NULL;
}
