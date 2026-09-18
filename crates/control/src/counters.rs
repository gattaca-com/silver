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
        _Reserved_PartialFramesWritten,
        PartialFramesDropped,
        _Reserved_PartialCellsServed,
        PartialWithdrawals,
        PartialExchanges,
        _Reserved_PartialPendingFrames,
        _Reserved_PartialResponsesSent,
        PartialCellsRequested,
        PartialRateLimited,
    }
}
