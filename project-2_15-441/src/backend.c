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

#include "cmu_packet.h"
#include "cmu_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

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
  printf("    in_func: has_been_acked\n");
  int result;
  while (pthread_mutex_lock(&(sock->window.ack_lock)) != 0) {
  }
  result = after(sock->window.last_ack_received, seq);
  pthread_mutex_unlock(&(sock->window.ack_lock));
  printf("    out_func: has_been_acked\n");
  return result;
}
void handshake_send(cmu_socket_t *sock, uint8_t *data, int buf_len, int flag);

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
void handle_message(cmu_socket_t *sock, uint8_t *pkt) {
  printf("    in_func: handle_message\n");
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  read_header(hdr);
  uint8_t flags = get_flags(hdr);

  switch (flags) {
    case ACK_FLAG_MASK:{
      uint32_t ack = get_ack(hdr);
      if (after(ack, sock->window.last_ack_received)) {
        sock->window.last_ack_received = ack;
        sock->adv_win_size = get_advertised_window(hdr);
        sock->window.last_seq_read = get_seq(hdr);      
      }
      break;
    }

    // beginning of handshake in server. - wgy
    case SYN_FLAG_MASK:{
      if(get_hlen(hdr) != get_plen(hdr)) break;
      sock->window.next_seq_expected = get_seq(hdr) + 1;
      handshake_send(sock, NULL, 0, (SYN_FLAG_MASK | ACK_FLAG_MASK));
      break;
    }
    
    default: {
      socklen_t conn_len = sizeof(sock->conn);
      uint32_t seq = sock->window.last_ack_received;

      // No payload.
      uint8_t *payload = NULL;
      uint16_t payload_len = 0;

      // No extension.
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      
      uint32_t ack = get_seq(hdr) + get_payload_len((uint8_t*)hdr);
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = ACK_FLAG_MASK;
      uint16_t adv_window = 1;
      uint8_t *response_packet =
          create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                        ext_len, ext_data, payload, payload_len);
      send_header((cmu_tcp_header_t *)response_packet);
      sendto(sock->socket, response_packet, plen, 0,
             (struct sockaddr *)&(sock->conn), conn_len);
      free(response_packet);
      seq = get_seq(hdr);

      //todo You may need to modify this to accommodate TCP cache or something. to ssr
      if (seq == sock->window.next_seq_expected) {
        sock->window.next_seq_expected = seq + get_payload_len(pkt);
        payload_len = get_payload_len(pkt);
        payload = get_payload(pkt);
        // Make sure there is enough space in the buffer to store the payload.
        sock->received_buf =
            realloc(sock->received_buf, sock->received_len + payload_len);
        memcpy(sock->received_buf + sock->received_len, payload, payload_len);
        sock->window.last_seq_read = seq+payload_len-1;
        sock->received_len += payload_len;
      }
    }
  }
  printf("    out_func: handle_message\n");
}


void msgSaveCopy(cmu_tcp_header_t* slot_msg,cmu_tcp_header_t* frame){
  *slot_msg = *frame;
}

void msgDestroy (cmu_tcp_header_t* slot_msg){
  bzero(slot_msg,sizeof(cmu_tcp_header_t));
}

int evSchedule(){
}

void evCancel(Event timeout){
}


void handle_message_sw(cmu_socket_t *sock, uint8_t *pkt) {
  printf("in_func: handle_message_sw\n");
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  window_t* window = &sock->window;
  read_header(hdr);
  uint8_t flags = get_flags(hdr);

  switch (flags) {
    case ACK_FLAG_MASK:{
      if (between(get_ack(hdr), window->last_ack_received+1, window->last_seq_sent+1)) {
      do {
        struct sendQ_slot* slot;
        // window->last_ack_received = 
        slot = &window->sendQ[++window->last_ack_received%get_advertised_window(hdr)];
        evCancel(slot->timeout);
        msgDestroy(&slot->msg);
        // pthread_cond_signal(&window->sendWindowNotFull);
      }while (window->last_ack_received != get_ack(hdr));
      window->last_seq_read = get_seq(hdr);      
    }
      break;
    }
    // beginning of handshake in server. - wgy
    case SYN_FLAG_MASK:{
      if(get_hlen(hdr) != get_plen(hdr)) break;
      sock->window.next_seq_expected = get_seq(hdr) + 1;
      handshake_send(sock, NULL, 0, (SYN_FLAG_MASK | ACK_FLAG_MASK));
      break;
    }
    
    default: {
      uint32_t seq = get_seq(hdr);
      struct recvQ_slot* slot;
      // 接收窗口的大小：由自己决定
      uint16_t rcv_win_size = MAX_RCV_BUFFER - ((window->next_seq_expected-1)-window->last_seq_read);
      slot=&window->recvQ[seq % rcv_win_size];
      if (!between(seq, window->next_seq_expected, window->next_seq_expected+get_advertised_window(hdr)-1)) {
        return;
      }
      msgSaveCopy(&slot->msg,hdr);//应该没事吧
      slot->received = true;
      if (seq==window->next_seq_expected) {

        while (slot->received) {
          uint8_t* pkt = (uint8_t*)&slot->msg;
          uint16_t payload_len = get_payload_len(pkt);
          uint8_t * payload = get_payload(pkt);
          // Make sure there is enough space in the buffer to store the payload.
          sock->received_buf =
              realloc(sock->received_buf, sock->received_len + payload_len);
          memcpy(sock->received_buf + sock->received_len, payload, payload_len);
          sock->received_len += payload_len;
          window->last_seq_read = seq+payload_len-1;
          msgDestroy(&slot->msg);
          slot->received=false;
          window->next_seq_expected = seq + payload_len;
          slot = &window->recvQ[window->next_seq_expected%get_advertised_window(hdr)];
        }
        socklen_t conn_len = sizeof(sock->conn);
        seq = sock->window.last_ack_received;
        // No payload.
        uint8_t *payload = NULL;
        uint16_t payload_len = 0;

        // No extension.
        uint16_t ext_len = 0;
        uint8_t *ext_data = NULL;

        uint16_t src = sock->my_port;
        uint16_t dst = ntohs(sock->conn.sin_port);
        uint32_t ack = window->next_seq_expected;
        uint16_t hlen = sizeof(cmu_tcp_header_t);
        uint16_t plen = hlen + payload_len;
        uint8_t flags = ACK_FLAG_MASK;
        uint16_t adv_window = MAX_RCV_BUFFER - ((window->next_seq_expected - 1) - window->last_seq_read);
        uint8_t *response_packet =
            create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);
        send_header((cmu_tcp_header_t *)response_packet);
        sendto(sock->socket, response_packet, plen, 0,
              (struct sockaddr *)&(sock->conn), conn_len);
        free(response_packet);
      }
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

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  switch (flags) {
    case NO_FLAG:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), MSG_PEEK,
                     (struct sockaddr *)&(sock->conn), &conn_len);
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
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
                     MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
                     &conn_len);
      break;
    default:
      perror("ERROR unknown flag");
  }

  if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
    plen = get_plen(&hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                   (struct sockaddr *)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
      // sock->window.last_seq_read= sock->window.last_seq_read +n;
    }
    handle_message_sw(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
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
void single_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  printf("    in_func: signal_send\n");
  uint8_t *msg;
  uint8_t *data_offset = data;
  size_t conn_len = sizeof(sock->conn);

  int sockfd = sock->socket;

  if (buf_len > 0) {
    while (buf_len != 0) {
      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t seq = sock->window.last_ack_received;
      uint32_t ack = sock->window.next_seq_expected;
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t adv_window = 1;
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;
      uint8_t flags = 0;
      uint16_t payload_len = MIN((uint16_t)buf_len, (uint16_t)MSS);
      uint16_t plen = hlen + payload_len;
      uint8_t *payload = data_offset;
      msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);
      buf_len -= payload_len;

      while (1) {
        //TODO: This is using stop and wait, can we do better?
        //todo you should receive data disorderly: sending all data and timing the last one. or timing the correct ack optionally.
        //todo you may set another cache to storage the data or ack before the correct data coming.
        send_header((cmu_tcp_header_t*)msg);
        sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn),
               conn_len);
        check_for_data(sock, TIMEOUT);
        if (has_been_acked(sock, seq)) {
          break;
        }
      }
      data_offset += payload_len;
    }
  }
  printf("    out_func: signal_send\n");
}

int sendSWP (cmu_socket_t* sock,cmu_tcp_header_t* frame){
  struct sendQ_slot* slot;
  window_t* window = &sock->window;
  size_t conn_len = sizeof(sock->conn);
  int sockfd = sock->socket;
  while (pthread_mutex_lock(&window->window_full_lock)!=0) {
  }
  pthread_cond_wait(&window->sendWindowNotFull, &window->window_full_lock);
  pthread_mutex_unlock(&window->window_full_lock);
  uint32_t seq = ++window->last_seq_sent;
  slot=&window->sendQ[seq % get_advertised_window(frame)];
  msgSaveCopy(&slot->msg, frame);
  // TODO:set timeout and then?
  slot->timeout= evSchedule();
  check_for_data(sock, TIMEOUT);
  send_header(frame);
  int res = sendto(sockfd,frame, get_plen(frame), 0, (struct sockaddr *)&(sock->conn),
          conn_len);
  return res;
}

void sw_send(cmu_socket_t *sock,uint8_t *data, int buf_len){

  uint8_t *msg;
  uint8_t *data_offset = data;
  window_t* window=&sock->window;
  uint32_t seq = sock->window.last_ack_received;

  if (buf_len > 0) {
    while (buf_len != 0) {
      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t ack = sock->window.next_seq_expected;
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t adv_window = 1;//no usage
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;
      uint8_t flags = 0;

      uint16_t effective_win_size = sock->adv_win_size - (window->last_seq_sent-window->last_ack_received);
      uint16_t payload_len = MIN((uint16_t)buf_len, (uint16_t)MSS);
      if (effective_win_size < payload_len) {
          while (1) {
            if (has_been_acked(sock, window->last_ack_received+1)) {
              payload_len = MIN(effective_win_size, payload_len);
              break;
            }
          }
      }
      //  =  effective_win_size>=MSG_SYN ? MIN((uint16_t)buf_len, (uint16_t)MSS);
      uint16_t plen = hlen + payload_len;
      uint8_t *payload = data_offset;

      buf_len -= payload_len;
      msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);
      struct sendQ_slot* slot;
      cmu_tcp_header_t* frame = (cmu_tcp_header_t*)msg;
      
      window_t* window = &sock->window;
      size_t conn_len = sizeof(sock->conn);
      int sockfd = sock->socket;
      // while (pthread_mutex_lock(&window->window_full_lock)!=0) {
      // }
      // pthread_cond_wait(&window->sendWindowNotFull, &window->window_full_lock);
      // pthread_mutex_unlock(&window->window_full_lock);
      seq += payload_len;
      slot=&window->sendQ[seq % get_advertised_window(frame)];
      msgSaveCopy(&slot->msg, frame);
      // TODO:set timeout and then?
      slot->timeout= evSchedule();
      check_for_data(sock, TIMEOUT);
      send_header(frame);
      sendto(sockfd,frame, get_plen(frame), 0, (struct sockaddr *)&(sock->conn),conn_len);
        // 什么时候检查ack？什么时候不发送？
        // 不发送：一个packet大小就是MSS和data的最小值，
      data_offset += payload_len;
    }
  }
}

bool handle_handshake(cmu_socket_t*sock, uint8_t *data, int buf_len, uint8_t* pkt){
  cmu_tcp_header_t* hdr = (cmu_tcp_header_t*)pkt;
  read_header(hdr);
  int flag = get_flags(hdr);
  bool this_flag = true;
  if(pkt == NULL){
    return false;
  }
  switch (flag)
  {
    case (SYN_FLAG_MASK|ACK_FLAG_MASK):{
      if(get_hlen(hdr) != get_plen(hdr)) {this_flag = false; break;}
      if(get_ack(hdr) != sock->window.last_ack_received + 1) {this_flag = false; break;}
      sock->window.last_ack_received = get_ack(hdr);
      sock->window.next_seq_expected = get_seq(hdr) + 1;
      handshake_send(sock, data, buf_len, ACK_FLAG_MASK);
      break;
    }
    //when server receive the third handshake package, they regard it as normal data package.
    //when server receive, they send an ack package, so the block should also handle it when in initiator.
    case ACK_FLAG_MASK:{
      if(sock->type == TCP_LISTENER && get_ack(hdr) != sock->window.last_ack_received + 1) {this_flag = false; break;}
      if(sock->type == TCP_LISTENER){
        set_flags(hdr, 0);
        sock->window.last_ack_received = get_ack(hdr);
      }
      handle_message(sock, pkt);
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
uint8_t* wait_check(cmu_socket_t* sock){
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

void handshake_send(cmu_socket_t *sock, uint8_t *data, int b_len, int flag){
  uint8_t *msg;
  uint8_t *data_offset = NULL;
  int buf_len = 0;
  if(flag == ACK_FLAG_MASK){
    data_offset = data;
    buf_len = b_len;
  }

  size_t conn_len = sizeof(sock->conn);
  int sockfd = sock->socket;

  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint32_t seq = sock->window.last_ack_received;
  uint32_t ack = sock->window.next_seq_expected;
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t adv_window = MAX_RCV_BUFFER;
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;
  uint16_t payload_len = MIN((uint16_t)buf_len, (uint16_t)MSS);
  uint8_t *payload = data_offset;
  uint16_t plen = hlen + payload_len;
  uint8_t flags = flag;

  msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window, ext_len, ext_data, payload, payload_len);
  while (1) {
    //for all three handshakes send and handle.
    send_header((cmu_tcp_header_t*)msg);
    sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn), conn_len);
    if (handle_handshake(sock, data, b_len, wait_check(sock))) {
      break;
    }
  }
  if(data_offset != NULL && (buf_len - payload_len) > 0) sw_send(sock, data_offset + payload_len, buf_len - payload_len);     
}

void *begin_backend(void *in) {
  printf("    in_func: begin_background\n");
  cmu_socket_t *sock = (cmu_socket_t *)in;
  uint8_t adv_win_size = MAX_RCV_BUFFER;
  int death, buf_len, send_signal;
  uint8_t *data = NULL;

  //Here we prepare initaitor to start the handshake transaction
  if(sock->type == TCP_INITIATOR){
    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    buf_len = sock->sending_len;
    if(buf_len != 0){
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
    // printf("in while recv\n");
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
