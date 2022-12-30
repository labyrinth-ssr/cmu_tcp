`window_t`：

- `sendQ[MAX_SEND_BUFFER]`:发送队列缓存。每个index对应一个byte(Seqno)。但是在缓存时，将整个packet的数据存入`sendQ[seq % sock->adv_win_size]`，剩余`payload_len`个`sendQ`entry留空。

`void handle_message_sw(cmu_socket_t *sock, uint8_t *pkt);`：
处理接收到的packet。

- 如果是ack，判断ack确认的序列号是否在本侧socket的发送窗口内。循环将所有小于ack的`Seqno`对应的`sendQ` entry的超时事件取消，并清空内部存储的`msg`（其实只有每个packet的第一个`Seqno`注册了超时事件并保存了数据，但是累计确认不知道每个packet的`payload_len`，所以对没有注册超时事件和缓存数据的entry也做了一次无效的清空）。完成后`window->last_seq_acked` 被修改为 `get_ack(hdr)-1`。将`hdr`中的`advertised_window`保存到本侧的`sock->adv_win_size`，成为下次发送的发送窗口大小
- 如果是数据。用`MAX_RCV_BUFFER - ((window->next_seq_expected-1)-window->last_seq_read)`。计算出接收窗口大小后，判断接收到的`Seqno`是否在接收窗口范围内。如果不在，直接返回。将`Seqno`对应的`recvQ` entry的`received`设为`true`并缓存数据。当`seq==window->next_seq_expected`时，循环更新本侧的`sock->received_buf`，和`window->last_seq_read`，清除对应`recvQ` entry的`received`和`msg`。循环结束后发送累计确认的ack（`window->next_seq_expected`）。

`void sw_send(cmu_socket_t *sock,uint8_t *data, int buf_len);`
将data分成packet后发送。

- effective_win_size即可以发送的窗口大小，由sock->adv_win_size - (window->last_seq_sent-window->last_seq_acked)得到。
- packet的发送，结合了nagle's algorithm。
   - payload初始值为MIN(buf_len,MSS)。
   - 当effective_win_size小于初始值、且有未确认的序列号时，循环等待到一次ack后，将payload_len = MIN(effective_win_size, payload_len)的数据发送。
   - 其他情况下，发送payload_len初始值大小的数据。
- 每发送一个packet，在sendQ对应位置保存数据，并注册超时事件
- **sw_send里没有确认超时并重传对应packet的逻辑**