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

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

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
    // it's acknowledge message from listener.
    case ACK_FLAG_MASK: {
      uint32_t ack = get_ack(hdr);
      if (after(ack, sock->window.last_ack_received)) {
        sock->window.last_ack_received = ack;
      }
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
      //! what we want next.
      uint32_t ack = get_seq(hdr) + get_payload_len(pkt);
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = ACK_FLAG_MASK;//! seems like acknowledge with each other.
      //todo here, here we send a packet which should contain data.
      uint16_t adv_window = 1;
      uint8_t *response_packet =
          create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                        ext_len, ext_data, payload, payload_len);
      send_header(response_packet);
      sendto(sock->socket, response_packet, plen, 0,
             (struct sockaddr *)&(sock->conn), conn_len);
      free(response_packet);

      //! get sequence number
      seq = get_seq(hdr);


      //yes which is indeed what we want about data.
      if (seq == sock->window.next_seq_expected) {
        sock->window.next_seq_expected = seq + get_payload_len(pkt);
        payload_len = get_payload_len(pkt);
        payload = get_payload(pkt);

        // 确保buffer中有足够的空间存储负载。Make sure there is enough space in the buffer to store the payload.
        sock->received_buf =
            realloc(sock->received_buf, sock->received_len + payload_len);
        memcpy(sock->received_buf + sock->received_len, payload, payload_len);
        sock->received_len += payload_len;
      }
    }
  }
  printf("    out_func: handle_message\n");
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
void check_for_data(cmu_socket_t *sock, cmu_read_mode_t flags) {
  //printf("    in_func: check_for_data\n");
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

  //! if data is not empty, we storage it on pkt.
  if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
    plen = get_plen(&hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                   (struct sockaddr *)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }

    //! here we use func handle_message.
    handle_message(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  // printf("    out_func: check_for_data\n");
}

/**
 * todo Breaks up the data into packets and sends a single packet at a time.
 *! here we use check_data(). but signle_send only used in begin_backend().
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


void client_first_handshake(cmu_socket_t* sock){
  printf("    in_func: client_first_handshake\n");
  uint8_t *msg;
  size_t conn_len = sizeof(sock->conn);
  int sockfd = sock->socket;
  uint16_t payload_len = 0;
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint32_t seq = sock->window.last_ack_received;
  uint32_t ack = sock->window.next_seq_expected;
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + payload_len;
  uint16_t adv_window = 0;
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;
  uint8_t *payload = NULL;
  uint8_t flags = SYN_FLAG_MASK;
  msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                      ext_len, ext_data, payload, payload_len);
    send_header((cmu_tcp_header_t*)msg);
    sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn),
            conn_len);
  printf("    out_func: client_first_handshake\n");
}

bool handle_first_handshake(cmu_socket_t *sock){
  bool satisfy = true;
  cmu_tcp_header_t hdr;
  uint8_t *pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;
  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  struct pollfd ack_fd;
  ack_fd.fd = sock->socket;
  ack_fd.events = POLLIN;
  if (poll(&ack_fd, 1, 3000) <= 0) {
    pthread_mutex_unlock(&(sock->recv_lock));
    printf("ssssssssssssssssssssssssssss\n");
    return false;
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
    cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
    read_header(hdr);
    if(get_hlen(hdr) != get_plen(hdr)) {
      printf("111\n");
      satisfy = false;
    }
    if(get_flags(hdr)!= SYN_FLAG_MASK) {
      satisfy = false;
      printf("222\n");
    }
    if(satisfy) {
      sock->window.next_seq_expected = get_seq(hdr) + 1;
    }
    free(pkt);
  }else{
    satisfy = false;
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  printf("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
  if(!satisfy) return false;
  uint32_t seq = sock->window.last_ack_received;
  uint8_t *payload = NULL;
  uint16_t payload_len = 0;
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint32_t ack = sock->window.next_seq_expected;
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen_ = hlen + payload_len;
  uint8_t flags = ACK_FLAG_MASK + SYN_FLAG_MASK;
  uint16_t adv_window = 1;
  uint8_t *response_packet =
  create_packet(src, dst, seq, ack, hlen, plen_, flags, adv_window,
                ext_len, ext_data, payload, payload_len);
  send_header(response_packet);
  sendto(sock->socket, response_packet, plen, 0,
    (struct sockaddr *)&(sock->conn), conn_len);
  free(response_packet);
  return true;
}

bool handle_second_handshake(cmu_socket_t *sock){
    bool satisfy = true;
  cmu_tcp_header_t hdr;
  uint8_t *pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;
  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  struct pollfd ack_fd;
  ack_fd.fd = sock->socket;
  ack_fd.events = POLLIN;
  if (poll(&ack_fd, 1, 3000) <= 0) {
    pthread_mutex_unlock(&(sock->recv_lock));
    return false;
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
    cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
    read_header(hdr);
    if(get_hlen(hdr) != get_plen(hdr)){
      satisfy = false;
    }
    if(get_flags(hdr)!= (SYN_FLAG_MASK | ACK_FLAG_MASK)) {
      satisfy = false;
    }
    if(satisfy){
      sock->window.next_seq_expected = get_seq(hdr) + 1;
      sock->window.last_ack_received = get_ack(hdr);
    }
    free(pkt);
  }else{
    satisfy = false;
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  printf("satisfy:%d\n",satisfy);
  return satisfy;
}

void client_third_handshake(cmu_socket_t *sock){
  int death, buf_len, send_signal;
  uint8_t *data;
  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
  }
  buf_len = sock->sending_len;
  if (buf_len > 0) {
      data = malloc(buf_len);
      memcpy(data, sock->sending_buf, buf_len);
      sock->sending_len = 0;
      free(sock->sending_buf);
      sock->sending_buf = NULL;
      pthread_mutex_unlock(&(sock->send_lock));
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
      uint8_t flags = ACK_FLAG_MASK;
      uint16_t payload_len = MIN((uint16_t)buf_len, (uint16_t)MSS);
      uint16_t plen = hlen + payload_len;
      uint8_t *payload = data_offset;
      msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);
      buf_len -= payload_len;

      while (1) {
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
      free(data);
    } else {
      pthread_mutex_unlock(&(sock->send_lock));
    }
}

void handle_third_handshake(cmu_socket_t *sock){
  bool satisfy = true;
  uint8_t *pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;
  cmu_tcp_header_t hdr;
  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  // Using `poll` here so that we can specify a timeout.
  struct pollfd ack_fd;
  ack_fd.fd = sock->socket;
  ack_fd.events = POLLIN;
  // Timeout after 3 seconds.
  if (poll(&ack_fd, 1, 3000) <= 0) {
    pthread_mutex_unlock(&(sock->recv_lock));
    return;
  }
// Fallthrough.
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
    cmu_tcp_header_t* header = (cmu_tcp_header_t*)pkt;
    if(get_flags(header) != ACK_FLAG_MASK) satisfy = false;
    if(get_ack(header) != sock->window.last_ack_received + 1) satisfy=false;
    if(satisfy){
      set_flags(header, 0);
      sock->window.last_ack_received = get_ack(header);
      handle_message(sock, pkt);
    }
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
}

void *begin_backend(void *in) {
  printf("    in_func: begin_background\n");
  cmu_socket_t *sock = (cmu_socket_t *)in;
  int death, buf_len, send_signal;
  uint8_t *data;

  while(sock->type == TCP_INITIATOR){
    client_first_handshake(sock);
    if (!handle_second_handshake(sock)) {
      continue;
    }
    client_third_handshake(sock);
    // check_for_data(sock, TIMEOUT);
    break;
  }

  while(sock->type == TCP_LISTENER){
    printf("a\n");
    if(!handle_first_handshake(sock)){
      continue;
    }
    handle_third_handshake(sock);
    // exit(0);
    break;
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

    //只有需要发送数据时才会执行single_send.  即sending_len > 0时。
    if (buf_len > 0) {
      data = malloc(buf_len);
      memcpy(data, sock->sending_buf, buf_len);
      sock->sending_len = 0;
      free(sock->sending_buf);
      sock->sending_buf = NULL;
      pthread_mutex_unlock(&(sock->send_lock));
      single_send(sock, data, buf_len);
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
      //发送一个信号给另外一个正在处于阻塞等待状态的线程,使其脱离阻塞状态
      pthread_cond_signal(&(sock->wait_cond));
    }
  }

  pthread_exit(NULL);
  printf("    out_func: begin_background\n");
  return NULL;
}
