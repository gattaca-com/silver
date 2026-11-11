use std::time::Duration;

use mio::{Events, Registry};
use silver_httpcore::{
    BufferCapacity, ClientRequest, ClientResponse, Endpoint, HttpPool, TokenRange,
};

/// `MAX_BUILDER_ENTRIES`: entries sharing a URL take a connection each. It
/// bounds the requests in flight across every builder, not per builder.
pub(crate) const MAX_REQUESTS: usize = 64;
/// Half the requests in flight, so bid requests always have the rest.
pub(crate) const PREFERENCE_CONNECTIONS: usize = MAX_REQUESTS / 2;
/// A JSON bid listing every commitment its SSZ bound allows is about 400 KiB.
/// Preference and block answers are a status and an error message.
const MAX_BUILDER_RESPONSE: usize = 1 << 20;
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
    PreferencesJson,
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
            2 => Self::Preferences,
            _ => Self::PreferencesJson,
        };
        (call, tagged & ((1 << CALL_SHIFT) - 1))
    }

    fn is_preferences(self) -> bool {
        matches!(self, Self::Preferences | Self::PreferencesJson)
    }
}

/// A pool per builder URL, each outliving its requests so the next one reuses
/// the connection. Once `MAX_REQUESTS` URLs hold one, an idle pool is handed
/// to the next new URL.
pub(crate) struct BuilderPools {
    pools: Vec<BuilderPool>,
    tokens: TokenRange,
    bid_timeout: Duration,
    in_flight: usize,
    preferences_in_flight: usize,
}

/// One builder's connections, shared by every call to it.
struct BuilderPool {
    url: Box<str>,
    pool: HttpPool,
}

pub(crate) enum PoolUnavailable {
    Scheme,
    ServerName,
    TooManyUrls,
    Busy,
}

impl PoolUnavailable {
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::Scheme => "only http:// and https:// builder urls are served",
            Self::ServerName => "builder url names no valid tls server",
            Self::TooManyUrls => "too many builder urls in flight",
            Self::Busy => "builder connections all busy",
        }
    }
}

impl BuilderPools {
    pub(crate) fn new(tokens: TokenRange, bid_timeout: Duration) -> Self {
        Self { pools: Vec::new(), tokens, bid_timeout, in_flight: 0, preferences_in_flight: 0 }
    }

    /// `dispatch_events` answers under `call` and `id`.
    pub(crate) fn enqueue(
        &mut self,
        url: &str,
        call: BuilderCall,
        id: u64,
        request: &ClientRequest<'_>,
        registry: &Registry,
    ) -> Result<(), PoolUnavailable> {
        if !self.has_capacity(call) {
            return Err(PoolUnavailable::Busy);
        }
        let at = self.position(url)?;
        let pool = &mut self.pools[at].pool;
        debug_assert!(pool.has_capacity(), "a pool's connections cap at MAX_REQUESTS");
        self.in_flight += 1;
        let timeout = match call {
            BuilderCall::Bid | BuilderCall::Block => self.bid_timeout,
            BuilderCall::Preferences | BuilderCall::PreferencesJson => {
                self.preferences_in_flight += 1;
                PREFERENCES_TIMEOUT
            }
        };
        pool.enqueue(call.tagged(id), request, timeout, registry);
        Ok(())
    }

    fn has_capacity(&self, call: BuilderCall) -> bool {
        let within_share =
            !call.is_preferences() || self.preferences_in_flight < PREFERENCE_CONNECTIONS;
        within_share && self.in_flight < MAX_REQUESTS
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
            BufferCapacity { read: 16 << 10, write: 8 << 10, max_response: MAX_BUILDER_RESPONSE },
            MAX_REQUESTS,
        )
        .map_err(|_| PoolUnavailable::ServerName)?;
        let builder = BuilderPool { url: url.into(), pool };
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
        let Self { pools, in_flight, preferences_in_flight, .. } = self;
        for BuilderPool { url, pool } in pools {
            pool.dispatch_events(events, registry, &mut |tagged, response| {
                let (call, id) = BuilderCall::untagged(tagged);
                *in_flight -= 1;
                if call.is_preferences() {
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
