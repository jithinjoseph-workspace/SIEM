//! analysisd's built-in decoders (analysisd/decoders/*.c other than the XML
//! decoders): each owns an `OSDecoderInfo` that is not in the decoder
//! lists, created when the event loop starts (`*Init`) and whose id is
//! looked up again on a ruleset hot reload (`*HotReload`).

pub mod ciscat;
pub mod dbsync;
pub mod hostinfo;
pub mod rootcheck;
pub mod sca;
pub mod syscheck;
pub mod syscheck_op;
pub mod syscollector;
pub mod upgrade;
pub mod winevt;

use crate::decoders::{DecId, DecoderInfo, Decoders};
use crate::event::OSSEC_RL;

/// The built-in decoders of one ruleset.
#[derive(Debug, Clone, Copy, Default)]
pub struct InternalDecoders {
    pub rootcheck: DecId,
    pub hostinfo: DecId,
    /// `id_new` / `id_mod` of the hostinfo decoder.
    pub hostinfo_new_id: u16,
    pub hostinfo_mod_id: u16,
    pub ciscat: DecId,
    pub winevt: DecId,
    pub sca: DecId,
    pub syscollector: DecId,
    /// The syscheck thread's `fim_decoder` (its id and name change with
    /// every event) and the `fim_decoders` ids.
    pub fim: DecId,
    pub fim_ids: syscheck::FimIds,
}

/// A decoder entry with dynamic field names at the given positions.
fn decoder(d: &Decoders, name: &str, type_: u8, order_size: usize, fields: &[(usize, &str)]) -> DecoderInfo {
    let mut f = vec![None; order_size];
    for &(i, n) in fields {
        if i < order_size {
            f[i] = Some(n.to_string());
        }
    }
    DecoderInfo {
        id: d.get_decoder_from_list(name),
        type_,
        name: Some(name.to_string()),
        fts: 0,
        fields: Some(f),
        ..Default::default()
    }
}

impl InternalDecoders {
    /// `RootcheckInit`, ... (and their `*HotReload` for a new ruleset).
    pub fn init(d: &mut Decoders, order_size: usize) -> InternalDecoders {
        let rk = decoder(d, rootcheck::ROOTCHECK_MOD, OSSEC_RL, order_size, &[(0, "title"), (1, "file")]);
        d.infos.push(rk);
        let rootcheck = d.infos.len() - 1;
        let hi = decoder(d, hostinfo::HOSTINFO_MOD, OSSEC_RL, order_size, &[]);
        d.infos.push(DecoderInfo { fields: None, ..hi });
        let hostinfo = d.infos.len() - 1;
        let cc = decoder(d, ciscat::CISCAT_MOD, OSSEC_RL, order_size, &[]);
        d.infos.push(DecoderInfo { fields: None, ..cc });
        let ciscat = d.infos.len() - 1;
        let we = decoder(d, winevt::WINEVT_MOD, OSSEC_RL, order_size, &[]);
        d.infos.push(DecoderInfo { fields: None, ..we });
        let winevt = d.infos.len() - 1;
        let sc = decoder(d, sca::SCA_MOD, OSSEC_RL, order_size, &[]);
        d.infos.push(DecoderInfo { fields: None, ..sc });
        let sca = d.infos.len() - 1;
        let sy = decoder(d, syscollector::SYSCOLLECTOR_MOD, OSSEC_RL, order_size, &[]);
        d.infos.push(DecoderInfo { fields: None, ..sy });
        let syscollector = d.infos.len() - 1;
        let names: Vec<(usize, &str)> = syscheck::FIELD_NAMES.iter().copied().enumerate().collect();
        let fd = decoder(d, syscheck::FIM_MOD, OSSEC_RL, order_size, &names);
        d.infos.push(fd);
        let fim = d.infos.len() - 1;
        let fim_ids = syscheck::FimIds::load(d);
        InternalDecoders {
            rootcheck,
            hostinfo,
            hostinfo_new_id: d.get_decoder_from_list(hostinfo::HOSTINFO_NEW),
            hostinfo_mod_id: d.get_decoder_from_list(hostinfo::HOSTINFO_MOD),
            ciscat,
            winevt,
            sca,
            syscollector,
            fim,
            fim_ids,
        }
    }
}
