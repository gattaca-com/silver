// PeerHandler has been removed in favor of the NetEvent queue on `P2p`.
// This module is kept as a placeholder; outbound connect requests are now
// issued via `P2p::connect()` and connection lifecycle is surfaced via
// `NetEvent::PeerConnected` / `NetEvent::PeerDisconnected`.
