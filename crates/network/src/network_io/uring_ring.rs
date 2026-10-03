#[cfg(test)]
mod tests;

use std::io;

use io_uring::{IoUring, Probe, opcode};
use silver_config::UringConfig;

/// Creates a SQPOLL ring without binding sockets or submitting operations.
/// Opcode probes cannot validate provided-buffer registration or multishot
/// receive flags.
pub(super) fn build(config: &UringConfig) -> io::Result<IoUring> {
    let idle_millis = config.validate()?;
    let mut builder = IoUring::builder();
    builder.setup_sqpoll(idle_millis).setup_cqsize(config.cq_entries);
    if let Some(cpu) = config.sqpoll_cpu {
        builder.setup_sqpoll_cpu(cpu);
    }
    let ring = builder.build(config.sq_entries)?;

    let params = ring.params();
    for (supported, name) in [
        (params.is_feature_nodrop(), "IORING_FEAT_NODROP"),
        (params.is_feature_fast_poll(), "IORING_FEAT_FAST_POLL"),
        (params.is_feature_sqpoll_nonfixed(), "IORING_FEAT_SQPOLL_NONFIXED"),
        (params.is_feature_ext_arg(), "IORING_FEAT_EXT_ARG"),
    ] {
        if !supported {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("network io_uring requires {name}"),
            ));
        }
    }

    let mut probe = Probe::new();
    ring.submitter().register_probe(&mut probe)?;
    for (code, name) in [
        (opcode::RecvMsg::CODE, "IORING_OP_RECVMSG"),
        (opcode::SendMsg::CODE, "IORING_OP_SENDMSG"),
        (opcode::SendMsgZc::CODE, "IORING_OP_SENDMSG_ZC"),
        (opcode::AsyncCancel::CODE, "IORING_OP_ASYNC_CANCEL"),
        (opcode::FutexWait::CODE, "IORING_OP_FUTEX_WAIT"),
    ] {
        if !probe.is_supported(code) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("network io_uring requires {name}"),
            ));
        }
    }
    Ok(ring)
}
