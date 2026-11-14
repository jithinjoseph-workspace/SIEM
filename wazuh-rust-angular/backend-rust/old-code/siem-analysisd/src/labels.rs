//! `wlabel_t` (shared/labels_op.c): agent labels attached to events.

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LabelFlags {
    pub hidden: bool,
    pub system: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Label {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub flags: LabelFlags,
}

/// `labels_get`
pub fn labels_get<'a>(labels: &'a [Label], key: &[u8]) -> Option<&'a [u8]> {
    labels.iter().find(|l| l.key == key).map(|l| l.value.as_slice())
}
