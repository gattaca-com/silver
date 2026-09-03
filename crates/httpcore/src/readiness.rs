use std::{io::ErrorKind, time::Duration};

use mio::{Events, Poll, Registry};

/// One readiness loop for every HTTP machine sharing a thread: each tenant
/// registers its sockets through a `Registry` clone and reads the same event
/// batch, so an iteration waits once however many tenants there are.
pub struct Readiness {
    poll: Poll,
    events: Events,
}

impl Readiness {
    pub fn new(events_capacity: usize) -> Self {
        Self {
            poll: Poll::new().expect("mio Poll::new failed"),
            events: Events::with_capacity(events_capacity),
        }
    }

    pub fn registry(&self) -> &Registry {
        self.poll.registry()
    }

    pub fn wait(&mut self, timeout: Duration) {
        match self.poll.poll(&mut self.events, Some(timeout)) {
            Ok(()) => {}
            // A signal cut the wait short; the batch is empty and the next
            // iteration waits again.
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => panic!("mio poll failed: {e}"),
        }
    }

    pub fn events(&self) -> &Events {
        &self.events
    }
}
