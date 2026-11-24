#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustodyChange {
    pub from_slot: u64,
    pub columns: u128,
}

impl CustodyChange {
    pub fn from_genesis(columns: u128) -> Self {
        Self { from_slot: 0, columns }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Custody {
    changes: Vec<CustodyChange>,
}

impl Custody {
    pub fn new(columns: u128) -> Self {
        Self { changes: vec![CustodyChange::from_genesis(columns)] }
    }

    pub fn from_changes(changes: Vec<CustodyChange>) -> Option<Self> {
        let first = changes.first()?;
        let ordered = changes.windows(2).all(|pair| {
            pair[0].from_slot < pair[1].from_slot &&
                pair[0].columns & !pair[1].columns == 0 &&
                pair[0].columns != pair[1].columns
        });
        (first.from_slot == 0 && ordered).then_some(Self { changes })
    }

    pub fn changes(&self) -> &[CustodyChange] {
        &self.changes
    }

    pub fn at(&self, slot: u64) -> u128 {
        self.changes
            .iter()
            .rev()
            .find(|change| change.from_slot <= slot)
            .expect("the first change starts at slot 0")
            .columns
    }

    pub fn current(&self) -> u128 {
        self.last().columns
    }

    pub fn last_change_slot(&self) -> u64 {
        self.last().from_slot
    }

    pub fn grow(&mut self, from_slot: u64, columns: u128) -> bool {
        let last = *self.last();
        assert!(last.columns & !columns == 0, "custody only grows");
        assert!(from_slot >= last.from_slot, "custody changes are ordered by slot");
        if columns == last.columns {
            return false;
        }
        if from_slot == last.from_slot {
            self.changes.last_mut().expect("non-empty").columns = columns;
        } else {
            self.changes.push(CustodyChange { from_slot, columns });
        }
        true
    }

    fn last(&self) -> &CustodyChange {
        self.changes.last().expect("custody always has a first change")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_before_a_change_keep_the_old_columns() {
        let mut custody = Custody::new(0b0011);
        assert!(custody.grow(64, 0b0111));
        assert!(custody.grow(96, 0b1111));
        assert_eq!(custody.at(0), 0b0011);
        assert_eq!(custody.at(63), 0b0011);
        assert_eq!(custody.at(64), 0b0111);
        assert_eq!(custody.at(u64::MAX), 0b1111);
        assert_eq!(custody.current(), 0b1111);
        assert_eq!(custody.last_change_slot(), 96);
    }

    #[test]
    fn same_columns_or_same_slot_do_not_add_a_change() {
        let mut custody = Custody::new(0b01);
        assert!(!custody.grow(64, 0b01));
        assert_eq!(custody.last_change_slot(), 0);
        assert!(custody.grow(64, 0b011));
        assert!(custody.grow(64, 0b111));
        assert_eq!(custody.changes().len(), 2);
        assert_eq!(custody.at(64), 0b111);
    }

    #[test]
    fn growing_from_slot_zero_replaces_the_first_change() {
        let mut custody = Custody::new(0b01);
        assert!(custody.grow(0, 0b11));
        assert_eq!(custody.changes(), [CustodyChange { from_slot: 0, columns: 0b11 }]);
        assert_eq!(Custody::from_changes(custody.changes().to_vec()), Some(custody));
    }

    #[test]
    #[should_panic(expected = "custody only grows")]
    fn shrinking_is_rejected() {
        Custody::new(0b11).grow(64, 0b01);
    }

    #[test]
    fn decoded_changes_must_start_at_zero_and_grow() {
        let change = |from_slot, columns| CustodyChange { from_slot, columns };
        assert!(Custody::from_changes(vec![change(0, 1), change(8, 3)]).is_some());
        assert!(Custody::from_changes(vec![]).is_none());
        assert!(Custody::from_changes(vec![change(1, 1)]).is_none());
        assert!(Custody::from_changes(vec![change(0, 3), change(8, 1)]).is_none());
        assert!(Custody::from_changes(vec![change(0, 1), change(8, 1)]).is_none());
        assert!(Custody::from_changes(vec![change(0, 1), change(0, 3)]).is_none());
    }
}
