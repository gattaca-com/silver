use std::path::Path;

use flux::communication::{
    queue::{Consumer, Queue},
    timer::TimingMessage,
};

pub fn sample_reader<T: Copy + flux::type_hash::TypeHash>(
    path: &Path,
    label: &'static str,
) -> Result<Consumer<T>, String> {
    let queue = Queue::try_open_shared(path).map_err(|e| format!("{path:?}: {e:?}"))?;
    let mut reader = Consumer::new(queue, label).without_log();
    reader.subscribe_broadcast();
    Ok(reader)
}

/// A lapped cursor uses one unit of the caller's drain budget to resynchronise.
pub fn consume_sample<T: Copy>(reader: &mut Consumer<T>, record: impl FnOnce(&T)) -> bool {
    use flux::communication::ReadError;
    match reader.try_consume_with_epoch() {
        Ok((value, _, _)) => {
            record(value);
            true
        }
        Err(ReadError::SpedPast) => {
            reader.recover_after_error();
            true
        }
        Err(ReadError::Empty) => false,
    }
}

pub fn consume_elapsed(
    reader: &mut Consumer<TimingMessage>,
    mut record: impl FnMut(flux::timing::Duration),
) -> bool {
    consume_sample(reader, |msg| {
        if msg.is_valid() {
            record(msg.elapsed());
        }
    })
}
