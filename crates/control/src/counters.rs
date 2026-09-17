silver_common::declare_counters! {
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
        PartialFramesWritten,
        PartialFramesDropped,
        PartialCellsServed,
        PartialWithdrawals,
        PartialExchanges,
        PartialPendingFrames,
        PartialResponsesSent,
    }
}
