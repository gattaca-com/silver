# P2P Connection & Stream Negotiation — Ladder Diagrams

## Client Side

```
Handler              P2p                  Peer                 Stream               Quinn                Socket
   |                  |                     |                     |                     |                     |
   |--new_peer()----->|                     |                     |                     |                     |
   |  (PeerId,Addr)   |                     |                     |                     |                     |
   |                  |--endpoint.connect()-------------------------------------------------->|              |
   |                  |<---------------------------(handle, Connection)-------------------|              |
   |                  |--Peer::new(handle,conn)-->|                     |                     |              |
   |                  |                     |                     |                     |                     |
   |                  |                +----+  QUIC HANDSHAKE (multiple rounds)         |                     |
   |                  |                |    |--transmit()------------------------------>|                     |
   |                  |                |    |<--------------------------Some(Transmit)--|                     |
   |                  |                |    |                     |                     |--send()------------>|
   |                  |                |    |                     |                     |               [UDP out]
   |                  |                |    |                     |                     |                     |
   |                  |                |    |                     |                     |<--recv()------------|
   |                  |  recv()------->|    |                     |                     |               [UDP in]
   |                  |  endpoint.handle()------------------------------------------------->|                |
   |                  |<--ConnectionEvent--------------------------------------------------|                |
   |                  |                |    |<--event(ce)-----------------------------------|                |
   |                  |                |    |--handle_event(ce)----------------------------->|                |
   |                  |                +----+  ... repeat until Connected              |                     |
   |                  |                     |                     |                     |                     |
   |                  |                     |--spin()             |                     |                     |
   |                  |                     |  poll()---------------------------------------->|               |
   |                  |                     |<-----------Event::Connected-------------------|               |
   |                  |                     |  id_from_connection()------------------------->|               |
   |                  |                     |<---------------------------(PeerId)-----------|               |
   |<--new_connection(RemotePeer)-----------|                     |                     |                     |
   |                  |                     |                     |                     |                     |
   |--new_streams()-->|                     |                     |                     |                     |
   | (RemotePeer,     |                     |                     |                     |                     |
   |  GossipSub)      |                     |                     |                     |                     |
   |                  |--open_stream(GossipSub)--->|              |                     |                     |
   |                  |                     |  streams().open(Bi)------------------------------>|             |
   |                  |                     |<---------------------------StreamId(0)-----------|             |
   |                  |                     |--Stream::new_outbound()--->|                     |             |
   |                  |                     |                     |<--(Negotiating)            |             |
   |                  |                     |--stream.drive()---------->|                     |             |
   |                  |                     |                     |--write_negotiate()         |             |
   |                  |                     |                     |  [MULTISTREAM_V1 +         |             |
   |                  |                     |                     |   protocol.multiselect()]  |             |
   |                  |                     |                     |--send_stream().write()---->|             |
   |                  |                     |                     |<--Pending                  |             |
   |                  |                     |                     |                     |                     |
   |                  |                     |--transmit()------------------------------>|                     |
   |                  |                     |<--------------------------Some(Transmit)--|                     |
   |                  |                     |                     |                     |--send()------------>|
   |                  |                     |                     |                     |    [multistream out] |
   |                  |                     |                     |                     |                     |
   |                  |                     |                     |                     |<--recv()------------|
   |                  |  recv()-->endpoint.handle()------------------------------------>|          [echo in]  |
   |                  |<--ConnectionEvent--------------------------------------------------|                |
   |                  |                     |<--event(ce)-----------------------------------|                |
   |                  |                     |                     |                     |                     |
   |                  |                     |--spin()             |                     |                     |
   |                  |                     |  poll()---------------------------------------->|               |
   |                  |                     |<--Event::Stream(Readable)---------------------|               |
   |                  |                     |--stream.drive_read()-->|                     |               |
   |                  |                     |                     |--read_negotiate()      |               |
   |                  |                     |                     |  recv_stream().read()-->|               |
   |                  |                     |                     |<--chunks(echo bytes)---|               |
   |                  |                     |                     |--feed_read()           |               |
   |                  |                     |                     |  [verify header+proto] |               |
   |                  |                     |<--Ready(GossipSub)--|                     |                     |
   |                  |                     |--stream.apply(Ready)--->|                     |                |
   |                  |                     |                     |-->Active(GossipSub)     |                |
   |<--new_stream(RemotePeer, StreamId)-----|                     |                     |                     |
   |                  |                     |                     |                     |                     |
   |--to_send()------>|                     |                     |                     |                     |
   | (conn, stream,   |                     |                     |                     |                     |
   |  data)           |--write(stream,data)----->|                |                     |                     |
   |                  |                     |  is_active()------->|                     |                     |
   |                  |                     |<--true--------------|                     |                     |
   |                  |                     |  send_stream().write(data)--------------->|                     |
   |<--sent()---------|                     |                     |                     |                     |
   |                  |                     |--transmit()------------------------------>|                     |
   |                  |                     |                     |                     |--send()------------>|
   |                  |                     |                     |                     |        [app data out]
```

## Server Side

```
Socket               Quinn                P2p                  Peer                 Stream               Handler
   |                     |                     |                     |                     |                     |
   |--recv()------------>|                     |                     |                     |                     |
   | [UDP in: Initial]   |                     |                     |                     |                     |
   |                     |  recv()-->endpoint.handle()-->|           |                     |                     |
   |                     |<--NewConnection---------------|           |                     |                     |
   |                     |                     |--endpoint.accept()----->|                  |                     |
   |                     |                     |<--(handle, Connection)--|                  |                     |
   |                     |                     |--Peer::new(handle,conn)->|                 |                     |
   |                     |                     |                     |                     |                     |
   |                     |                +----+  QUIC HANDSHAKE (multiple rounds)         |                     |
   |--recv()------------>|                     |                     |                     |                     |
   |                     |  recv()-->endpoint.handle()-->|           |                     |                     |
   |                     |<--ConnectionEvent-------------|           |                     |                     |
   |                     |                     |                     |<--event(ce)---------|                     |
   |                     |                     |                     |--handle_event(ce)-->|                     |
   |                     |                     |                     |                     |                     |
   |                     |                     |                     |--spin()             |                     |
   |                     |                     |                     |  poll()------------>|                     |
   |                     |                     |                     |<--Event::Connected--|                     |
   |                     |                     |                     |  id_from_connection()->|                  |
   |                     |                     |                     |<-------(PeerId)-------|                  |
   |                     |                     |                     |                     |                     |
   |                     |                     |                     |--new_connection(RemotePeer)-------------->|
   |                     |                     |                     |                     |                     |
   |                     |                     |                     |--transmit()-------->|                     |
   |<--send()------------|                     |                     |<--Transmit----------|                     |
   | [handshake resp]    |                +----+  ... repeat         |                     |                     |
   |                     |                     |                     |                     |                     |
   |                     |  ======= CLIENT OPENS STREAM =======     |                     |                     |
   |                     |                     |                     |                     |                     |
   |--recv()------------>|                     |                     |                     |                     |
   | [UDP in: stream]    |  recv()-->endpoint.handle()-->|           |                     |                     |
   |                     |<--ConnectionEvent-------------|           |                     |                     |
   |                     |                     |                     |<--event(ce)---------|                     |
   |                     |                     |                     |--handle_event(ce)-->|                     |
   |                     |                     |                     |                     |                     |
   |                     |                     |                     |--spin()             |                     |
   |                     |                     |                     |  poll()------------>|                     |
   |                     |                     |                     |<--Opened{Bi}--------|                     |
   |                     |                     |                     |  streams().accept()->|                    |
   |                     |                     |                     |<--StreamId(0)--------|                    |
   |                     |                     |                     |                     |                     |
   |                     |                     |                     |--Stream::new_inbound()--->|               |
   |                     |                     |                     |                     |<--(Negotiating)     |
   |                     |                     |                     |--stream.drive()---------->|               |
   |                     |                     |                     |                     |                     |
   |                     |                     |                     |                     |--read_negotiate()   |
   |                     |                     |                     |                     |  recv_stream()----->|
   |                     |                     |                     |                     |<--chunks-----------|
   |                     |                     |                     |                     |  [MULTISTREAM_V1    |
   |                     |                     |                     |                     |   + protocol line]  |
   |                     |                     |                     |                     |                     |
   |                     |                     |                     |                     |--feed_read()        |
   |                     |                     |                     |                     |  InReadingHeader:   |
   |                     |                     |                     |                     |   verify MULTI_V1   |
   |                     |                     |                     |                     |  InReadingProtocol: |
   |                     |                     |                     |                     |   from_multiselect()|
   |                     |                     |                     |                     |   -> InWriting      |
   |                     |                     |                     |                     |                     |
   |                     |                     |                     |                     |--write_negotiate()  |
   |                     |                     |                     |                     |  [MULTISTREAM_V1    |
   |                     |                     |                     |                     |   + GossipSub echo] |
   |                     |                     |                     |                     |--send_stream()----->|
   |                     |                     |                     |                     |                     |
   |                     |                     |                     |                     |--advance_write()    |
   |                     |                     |                     |                     |  -> Done(GossipSub) |
   |                     |                     |                     |<--Ready(GossipSub)--|                     |
   |                     |                     |                     |                     |                     |
   |                     |                     |                     |--process_stream_event(Ready)              |
   |                     |                     |                     |--stream.apply(Ready)--->|                 |
   |                     |                     |                     |                     |-->Active(GossipSub) |
   |                     |                     |                     |                     |                     |
   |                     |                     |                     |--new_stream(RemotePeer, StreamId)-------->|
   |                     |                     |                     |                     |                     |
   |                     |                     |                     |--transmit()-------->|                     |
   |<--send()------------|                     |                     |<--Transmit----------|                     |
   | [echo out]          |                     |                     |                     |                     |
   |                     |                     |                     |                     |                     |
   |                     |  ======= APPLICATION DATA =======        |                     |                     |
   |                     |                     |                     |                     |                     |
   |--recv()------------>|                     |                     |                     |                     |
   | [UDP in: app data]  |  recv()-->endpoint.handle()-->|           |                     |                     |
   |                     |<--ConnectionEvent-------------|           |                     |                     |
   |                     |                     |                     |<--event(ce)---------|                     |
   |                     |                     |                     |                     |                     |
   |                     |                     |                     |--spin()             |                     |
   |                     |                     |                     |  poll()------------>|                     |
   |                     |                     |                     |<--Readable----------|                     |
   |                     |                     |                     |                     |                     |
   |                     |                     |                     |  is_active() == true|                     |
   |                     |                     |                     |--read_active()      |                     |
   |                     |                     |                     |  recv_stream().read()->|                  |
   |                     |                     |                     |<--chunks(app data)----|                  |
   |                     |                     |                     |                     |                     |
   |                     |                     |                     |--recv(RemotePeer, StreamId, data)-------->|
   |                     |                     |                     |                     |                     |
```
