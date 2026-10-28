use std::time::Duration;

use mio::{Events, Registry};
use silver_httpcore::{
    BufferCapacity, ClientRequest, ClientResponse, Endpoint, HttpPool, TokenRange,
};

/// `MAX_BUILDER_ENTRIES`: entries sharing a URL take a connection each.
pub(crate) const MAX_REQUESTS: usize = 64;
/// Half a builder's connections, so its bid requests always have the rest.
pub(crate) const PREFERENCE_CONNECTIONS: usize = MAX_REQUESTS / 2;
/// Nothing waits on preferences but the VC, and a timed-out entry makes it
/// send its whole request again.
const PREFERENCES_TIMEOUT: Duration = Duration::from_secs(1);
/// A request id's top two bits name its call.
const CALL_SHIFT: u32 = 62;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BuilderCall {
    Bid,
    Block,
    Preferences,
}

impl BuilderCall {
    fn tagged(self, id: u64) -> u64 {
        debug_assert!(id >> CALL_SHIFT == 0, "a call's id fits below its tag");
        (self as u64) << CALL_SHIFT | id
    }

    fn untagged(tagged: u64) -> (Self, u64) {
        let call = match tagged >> CALL_SHIFT {
            0 => Self::Bid,
            1 => Self::Block,
            _ => Self::Preferences,
        };
        (call, tagged & ((1 << CALL_SHIFT) - 1))
    }
}

/// A pool per builder URL, each outliving its requests so the next one reuses
/// the connection. Once `MAX_REQUESTS` URLs hold one, an idle pool is handed
/// to the next new URL.
pub(crate) struct BuilderPools {
    pools: Vec<BuilderPool>,
    tokens: TokenRange,
    bid_timeout: Duration,
}

/// One builder's connections, shared by every call to it.
pub(crate) struct BuilderPool {
    url: Box<str>,
    pool: HttpPool,
    bid_timeout: Duration,
    preferences_in_flight: usize,
}

pub(crate) enum PoolUnavailable {
    Scheme,
    TooManyUrls,
    Busy,
}

impl PoolUnavailable {
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::Scheme => "only http:// and https:// builder urls are served",
            Self::TooManyUrls => "too many builder urls in flight",
            Self::Busy => "builder connections all busy",
        }
    }
}

impl BuilderPools {
    pub(crate) fn new(tokens: TokenRange, bid_timeout: Duration) -> Self {
        Self { pools: Vec::new(), tokens, bid_timeout }
    }

    pub(crate) fn bid_timeout(&self) -> Duration {
        self.bid_timeout
    }

    /// `url`'s pool when it has a connection for `call`.
    pub(crate) fn get(
        &mut self,
        url: &str,
        call: BuilderCall,
    ) -> Result<&mut BuilderPool, PoolUnavailable> {
        let at = self.position(url)?;
        let pool = &mut self.pools[at];
        if pool.has_capacity(call) { Ok(pool) } else { Err(PoolUnavailable::Busy) }
    }

    fn position(&mut self, url: &str) -> Result<usize, PoolUnavailable> {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(PoolUnavailable::Scheme);
        }
        if let Some(at) = self.pools.iter().position(|pool| *pool.url == *url) {
            return Ok(at);
        }
        let at = if self.pools.len() < MAX_REQUESTS {
            self.pools.len()
        } else {
            let idle = self.pools.iter().position(|pool| pool.pool.is_idle());
            idle.ok_or(PoolUnavailable::TooManyUrls)?
        };
        let pool = HttpPool::new(
            Endpoint::Http(url.to_owned()),
            self.tokens.share_of(at, MAX_REQUESTS),
            BufferCapacity { read: 16 << 10, write: 8 << 10 },
            MAX_REQUESTS,
        );
        let builder = BuilderPool {
            url: url.into(),
            pool,
            bid_timeout: self.bid_timeout,
            preferences_in_flight: 0,
        };
        if at == self.pools.len() {
            self.pools.push(builder);
        } else {
            self.pools[at] = builder;
        }
        Ok(at)
    }

    /// `on_answered` gets each answer's builder URL, and the call and id it
    /// was sent under.
    pub(crate) fn dispatch_events(
        &mut self,
        events: &Events,
        registry: &Registry,
        on_answered: &mut impl FnMut(&str, BuilderCall, u64, Result<ClientResponse<'_>, &str>),
    ) {
        for BuilderPool { url, pool, preferences_in_flight, .. } in &mut self.pools {
            pool.dispatch_events(events, registry, &mut |tagged, response| {
                let (call, id) = BuilderCall::untagged(tagged);
                if call == BuilderCall::Preferences {
                    *preferences_in_flight -= 1;
                }
                on_answered(url, call, id, response);
            });
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.pools.len()
    }
}

impl BuilderPool {
    fn has_capacity(&self, call: BuilderCall) -> bool {
        let within_share =
            call != BuilderCall::Preferences || self.preferences_in_flight < PREFERENCE_CONNECTIONS;
        within_share && self.pool.has_capacity()
    }

    /// `dispatch_events` answers under `call` and `id`.
    pub(crate) fn enqueue(
        &mut self,
        call: BuilderCall,
        id: u64,
        request: &ClientRequest<'_>,
        registry: &Registry,
    ) {
        debug_assert!(self.has_capacity(call), "callers check capacity first");
        let timeout = match call {
            BuilderCall::Bid | BuilderCall::Block => self.bid_timeout,
            BuilderCall::Preferences => {
                self.preferences_in_flight += 1;
                PREFERENCES_TIMEOUT
            }
        };
        self.pool.enqueue(call.tagged(id), request, timeout, registry);
    }
}
