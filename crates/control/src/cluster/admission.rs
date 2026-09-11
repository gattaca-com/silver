use std::{error::Error, fmt};

use silver_common::SLOTS_PER_EPOCH;

/// Why a locally-originated attestation was rejected before it entered Raft.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    StartupFloorUnset,
    BeforeStartupFloor { slot: u64, minimum: u64 },
    TooOld { slot: u64, minimum: u64 },
    Future { slot: u64, wall_slot: u64 },
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StartupFloorUnset => {
                f.write_str("attestation admission is disabled until the node is synced")
            }
            Self::BeforeStartupFloor { slot, minimum } => {
                write!(f, "attestation slot {slot} is before startup floor {minimum}")
            }
            Self::TooOld { slot, minimum } => {
                write!(f, "attestation slot {slot} is before age floor {minimum}")
            }
            Self::Future { slot, wall_slot } => {
                write!(f, "attestation slot {slot} is after wall slot {wall_slot}")
            }
        }
    }
}

impl Error for AdmissionError {}

/// Admission policy for locally-originated attestations.
///
/// The startup floor is latched when the node first reports itself synced and
/// is immutable thereafter. The age floor advances with wall time and permits
/// at most one epoch of past slots.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AttestationAdmission {
    startup_floor: Option<u64>,
}

impl AttestationAdmission {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Set the immutable startup floor to the slot after `startup_wall_slot`.
    /// Returns `true` only for the first call.
    pub(crate) fn set_startup_wall_slot(&mut self, startup_wall_slot: u64) -> bool {
        if self.startup_floor.is_some() {
            return false;
        }
        self.startup_floor = Some(startup_wall_slot.saturating_add(1));
        true
    }

    pub(crate) fn age_floor(wall_slot: u64) -> u64 {
        wall_slot.saturating_sub(SLOTS_PER_EPOCH)
    }

    pub(crate) fn validate(&self, slot: u64, wall_slot: u64) -> Result<(), AdmissionError> {
        let startup_floor = self.startup_floor.ok_or(AdmissionError::StartupFloorUnset)?;
        if slot > wall_slot {
            return Err(AdmissionError::Future { slot, wall_slot });
        }
        if slot < startup_floor {
            return Err(AdmissionError::BeforeStartupFloor { slot, minimum: startup_floor });
        }

        let age_floor = Self::age_floor(wall_slot);
        if slot < age_floor {
            return Err(AdmissionError::TooOld { slot, minimum: age_floor });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_has_startup_age_and_future_bounds() {
        let mut admission = AttestationAdmission::new();

        assert_eq!(admission.validate(100, 100), Err(AdmissionError::StartupFloorUnset));
        assert!(admission.set_startup_wall_slot(100));
        assert!(!admission.set_startup_wall_slot(200));

        assert_eq!(admission.startup_floor, Some(101));
        assert_eq!(
            admission.validate(100, 100),
            Err(AdmissionError::BeforeStartupFloor { slot: 100, minimum: 101 })
        );
        assert_eq!(
            admission.validate(102, 101),
            Err(AdmissionError::Future { slot: 102, wall_slot: 101 })
        );

        let wall_slot = 150;
        let age_floor = wall_slot - SLOTS_PER_EPOCH;
        assert_eq!(
            admission.validate(age_floor - 1, wall_slot),
            Err(AdmissionError::TooOld { slot: age_floor - 1, minimum: age_floor })
        );
        assert_eq!(admission.validate(age_floor, wall_slot), Ok(()));
        assert_eq!(admission.validate(wall_slot, wall_slot), Ok(()));
    }
}
