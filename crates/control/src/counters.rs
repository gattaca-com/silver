silver_common::declare_counters! {
    #[allow(non_camel_case_types)]
    pub ControlCounters => "control" {
        TailUnavailable,
        RangesIssued,
        RangesUnplaced,
        RangesTimedOut,
        BlocksChasedByRoot,
        RootNeedsStalled,
        RootNeedsTracked,
        RootNeedsRefused,
        PartialMetadataReceived,
        PartialMetadataReplaced,
        PartialMetadataIgnored,
        PartialStateLimited,
        PartialFramesQueued,
        PartialFramesDropped,
        PartialWithdrawals,
        PartialExchanges,
        PartialCellsRequested,
        PartialRateLimited,
        PartialCellsRequestedOutbound,
        PartialRequestsTimedOut,
        PartialFullFallbacks,
    }
}
