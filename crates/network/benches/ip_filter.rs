use std::{
    collections::HashSet, net::{IpAddr, Ipv4Addr}
};

use criterion::{Criterion, criterion_group, criterion_main};
use fxhash::FxHasher;
use ipnet_trie::IpnetTrie;
use pprof::criterion::{Output, PProfProfiler};
use rand::RngCore;
use silver_common::WitherFilter;

pub fn filter(c: &mut Criterion) {
    let group_name = "filter";
    let mut group = c.benchmark_group(group_name);

    let mut rng = rand::rngs::OsRng::default();
    let (universe, filter): (Vec<IpAddr>, Vec<IpAddr>) = {
        let mut addrs = vec![];
        let mut filter = vec![];
        for i in 0..8096 {
            let mut octets = [0u8; 4];
            rng.fill_bytes(&mut octets);
            addrs.push(Ipv4Addr::from_octets(octets).into());
            if i & 1 == 0 {
                filter.push(Ipv4Addr::from_octets(octets).into());
            }
        };
        (addrs, filter)
    };

    group.bench_with_input( "hashset", &(&universe, &filter), |b, (universe, filter)| {
        let mut filter_set = HashSet::new();
        for i in *filter {
            filter_set.insert(*i);
        }
        b.iter(|| {
            let mut set = false;
            for i in *universe {
                set |= filter_set.contains(i);
            }
            set
        });
    });

    group.bench_with_input( "trie", &(&universe, &filter), |b, (universe, filter)| {
        let mut filter_set = IpnetTrie::new();
        for i in *filter {
            filter_set.insert(*i, ());
        }
        b.iter(|| {
            let mut set = false;
            for i in *universe {
                set |= filter_set.exact_match(*i).is_some();
            }
            set
        });
    });

    group.bench_with_input( "wither", &(&universe, &filter), |b, (universe, filter)| {
        let mut filter_set = WitherFilter::<IpAddr, FxHasher, 4096>::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        for i in *filter {
            filter_set.insert(*i);
        }
        b.iter(|| {
            let mut set = false;
            for i in *universe {
                set |= filter_set.contains(i);
            }
            set
        });
    });
}

criterion_group! {
    name = benchmark;
    config = Criterion::default().sample_size(10).with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = filter
}
criterion_main!(benchmark);
