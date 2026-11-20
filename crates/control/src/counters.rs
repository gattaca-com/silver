silver_common::declare_counters! {
    #[allow(non_camel_case_types)]
    pub ControlCounters => "control" {
        TailUnavailable,
        RangesIssued,
        RangesUnplaced,
        RangesTimedOut,
        BlocksChasedByRoot,
        RootNeedsStalled,
        RootNeedsTracked: gauge,
        RootNeedsRefused,
        PartialMetadataReceived,
        PartialMetadataReplaced,
        PartialMetadataIgnored,
        PartialStateLimited,
        PartialFramesQueued,
        PartialFramesDropped,
        PartialWithdrawals,
        PartialExchanges: gauge,
        PartialCellsRequested,
        PartialRateLimited,
        PartialCellsRequestedOutbound,
        PartialRequestsTimedOut,
        PartialFullFallbacks,
    }
}
