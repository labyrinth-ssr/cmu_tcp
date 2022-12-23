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
  result = after(sock->window.last_seq_acked, seq);
  pthread_mutex_unlock(&(sock->window.ack_lock));
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
void handle_message_sw(cmu_socket_t *sock, uint8_t *pkt) {
  printf("in_func: handle_message_sw\n");
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  window_t *window = &sock->window;
  read_header(hdr);
  uint8_t flags = get_flags(hdr);

  switch (flags) {
    case ACK_FLAG_MASK: {
      if (between(get_ack(hdr), window->last_seq_acked + 1,
                  window->last_seq_sent + sock->payload_len_last_sent)) {
        while (window->last_seq_acked + 1 < get_ack(hdr)) {
          //update：此处修改成了跳格子的逻辑，每次向后跳跃一个包裹负载的长度。
          struct sendQ_slot *slot;
          slot = &window->sendQ[window->last_seq_acked % get_advertised_window(hdr)];
          window->last_seq_acked += get_payload_len(slot->msg);
          slot->msg = NULL;
        }
        // 如果当前还有没收到确认的报文段，则重启计时器。
        if(window->last_seq_acked + 1<window->last_seq_sent + sock->payload_len_last_sent)
          set_timer(sock);
        sock->adv_win_size = get_advertised_window(hdr);
        printf("recver told sender adv_win_size:%d\n", sock->adv_win_size);
      } else {
        printf("ack out of win range:ack:%d,min:%d,max:%d", get_ack(hdr),
               window->last_seq_acked + 1,
               window->last_seq_sent + sock->payload_len_last_sent);
      }
      break;
    }
    // beginning of handshake in server. - wgy
    case SYN_FLAG_MASK: {
      if (get_hlen(hdr) != get_plen(hdr)) break;
      sock->window.last_seq_read = get_seq(hdr);
      sock->window.next_seq_expected = get_seq(hdr) + 1;
      sock->adv_win_size = get_advertised_window(hdr);
      printf("recver told sender adv_win_size:%d\n", sock->adv_win_size);
      handshake_send(sock, NULL, 0, (SYN_FLAG_MASK | ACK_FLAG_MASK));
      break;
    }

    default: {  // 普通包裹
      uint32_t seq = get_seq(hdr);
      struct recvQ_slot *slot;
      // 接收窗口的大小：由自己决定
      printf("window->next_seq_expected:%d,window->last_seq_read:%d\n",
             window->next_seq_expected, window->last_seq_read);
      uint16_t rcv_win_size = MAX_RCV_BUFFER - ((window->next_seq_expected - 1) - window->last_seq_read);
      printf("rcv data: rcv_win_size: %d\n", rcv_win_size);
      slot = &window->recvQ[seq % rcv_win_size];
      printf("fill rcv slot:%d\n", seq % rcv_win_size);
      if (!between(
              seq, window->next_seq_expected,
              window->next_seq_expected + get_advertised_window(hdr) - 1)) {
        return;
      }
      slot->msg = (uint8_t *)hdr;
      slot->received = true;
      if (seq == window->next_seq_expected) {
        while (slot->received) {  // 处理收到的数据
          uint8_t *pkt = slot->msg;
          uint16_t payload_len = get_payload_len(pkt);
          uint8_t *payload = get_payload(pkt);
          // Make sure there is enough space in the buffer to store the payload.
          sock->received_buf =
              realloc(sock->received_buf, sock->received_len + payload_len);
          memcpy(sock->received_buf + sock->received_len, payload, payload_len);
          printf("payload:%s\n", payload);
          printf("read buf:%s\n", sock->received_buf);
          sock->received_len += payload_len;
          window->last_seq_read = seq + payload_len - 1;
          slot->msg = NULL;
          slot->received = false;
          window->next_seq_expected = seq + payload_len;
          slot = &window->recvQ[window->next_seq_expected % rcv_win_size];
        }  // 发送ACK
        socklen_t conn_len = sizeof(sock->conn);
        seq = sock->window.last_seq_acked + 1;
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
        uint16_t adv_window = rcv_win_size;
        printf("rcver send adv_win_size:%d\n", adv_window);
        uint8_t *response_packet =
            create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);
        send_header((cmu_tcp_header_t *)response_packet);
        sendto(sock->socket, response_packet, plen, 0, (struct sockaddr *)&(sock->conn), conn_len);
        window->last_seq_sent = seq;
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
      //只判断有没有超时。删去了原本的poll逻辑（会造成等着的时候没法发东西）。
      //TODO: RTT estimation/ dynamic time interval
      struct timeval current_time;
      gettimeofday(&current_time, NULL);
      if (current_time.tv_sec - sock->window.send_time.tv_sec >3) 
        time_out=true;
      break;
    }
    // Fallthrough.
    case NO_WAIT:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
            MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),&conn_len);
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
    }
    handle_message_sw(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  sleep(1);

  return time_out;
}
void set_timer(cmu_socket_t *sock) {//以窗口为单位确定超时情况。
  gettimeofday(&sock->window.send_time, NULL);
  timer_on = true;
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
  uint32_t seq = sock->window.last_seq_acked + 1;
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint16_t adv_window = 1;  // no usage
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;
  uint8_t flags = 0;
  int sockfd = sock->socket;
  uint32_t ack = sock->window.next_seq_expected;
  while (buf_len != 0) {  // 在buf未发送完毕时，反复发送。
    // 1. 计算可用发送窗口
    printf("in sender:adv_win_size:%d,last_seq_sent:%d,last_seq_acked:%d\n",
           sock->adv_win_size, window->last_seq_sent, window->last_seq_acked);
    uint16_t effective_win_size = sock->adv_win_size - (window->last_seq_sent - window->last_seq_acked);
    // 2. 计算接下来可发出的新包裹大小
    uint16_t payload_len = MIN((uint16_t)buf_len, (uint16_t)MSS);
    printf("effectiv_win_size:%d\n", effective_win_size);
    if (effective_win_size < payload_len) {
      while (!has_been_acked(sock, window->last_seq_acked + 1)) ;
      payload_len = MIN(effective_win_size, payload_len);
    }
    // 3. 发包
    struct sendQ_slot *slot;
    uint16_t plen = hlen + payload_len;
    uint8_t *payload = data_offset;
    buf_len -= payload_len;  // 接下来将要发出payload_len长度的内容。
  
    if (check_for_data(sock, TIMEOUT)) {//判断是否超时。
      //如果处于重传阶段，在这里就不执行创建新包裹操作，而是重传最小序号未应答报文段。
      slot = &window->sendQ[(sock->window.last_seq_acked + 1) % sock->adv_win_size];
      cmu_tcp_header_t *frame = (cmu_tcp_header_t *)slot->msg;
      msg=slot->msg;
      //原本打算在这里讨论要重发的包和可用窗口大小的关系，决定要不要截断重发的包裹的。
      //大致思路是，如果要重发的包大于可用窗口大小，就将其截断并重新存入发送缓存，并发送前半段。
      //截断和截断后的重传太复杂了所以作罢。
      set_timer(sock);
      send_header(frame);
      sendto(sockfd, msg, get_plen(msg), 0, (struct sockaddr *)&(sock->conn), conn_len);
    } else {// 如果不在重传阶段，就正常发送新包裹。
      msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);
      if (!timer_on) set_timer(sock);
      cmu_tcp_header_t *frame = (cmu_tcp_header_t *)msg;
      slot = &window->sendQ[seq % sock->adv_win_size];
      slot->msg = msg;
      send_header(frame);
      sock->payload_len_last_sent = payload_len;
      sendto(sockfd, msg, get_plen(msg), 0, (struct sockaddr *)&(sock->conn), conn_len);
      data_offset += payload_len;
      window->last_seq_sent = seq;
      printf("in sw_sender: upd window.last_seq_sent:%d\n", seq);
      seq += payload_len;
    }
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
      printf("ack:%d,last_seq_acked:%d\n", get_ack(hdr),
             sock->window.last_seq_acked);
      if (get_hlen(hdr) != get_plen(hdr)) {
        this_flag = false;
        break;
      }
      if (get_ack(hdr) != sock->window.last_seq_acked + 2) {
        this_flag = false;
        break;
      }
      sock->window.last_seq_acked = get_ack(hdr) - 1;
      sock->window.last_seq_read = get_seq(hdr);
      sock->window.next_seq_expected = get_seq(hdr) + 1;
      handshake_send(sock, data, buf_len, ACK_FLAG_MASK);
      break;
    }
    // when server receive the third handshake package, they regard it as normal
    // data package. when server receive, they send an ack package, so the block
    // should also handle it when in initiator.
    case ACK_FLAG_MASK: {
      if (sock->type == TCP_LISTENER &&
          get_ack(hdr) != sock->window.last_seq_acked + 2) {
        this_flag = false;
        break;
      }
      if (sock->type == TCP_LISTENER) {
        set_flags(hdr, 0);
        sock->window.last_seq_acked = get_ack(hdr) - 1;
      }
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
  uint32_t seq = sock->window.last_seq_acked + 1;
  uint32_t ack = sock->window.next_seq_expected;
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t adv_window = MAX_RCV_BUFFER;
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;
  uint16_t payload_len = MIN((uint16_t)buf_len, (uint16_t)MSS);
  uint8_t *payload = data_offset;
  uint16_t plen = hlen + payload_len;
  uint8_t flags = flag;

  msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                      ext_len, ext_data, payload, payload_len);
  while (1) {
    // for all three handshakes send and handle.
    send_header((cmu_tcp_header_t *)msg);
    sock->payload_len_last_sent = payload_len;
    sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn), conn_len);
    sock->window.last_seq_sent = seq;
    if (handle_handshake(sock, data, b_len, wait_check(sock))) {
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
