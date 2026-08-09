use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Arrived,
    Removed,
    TopologyChanged,
}

impl EventKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Arrived => "arrived",
            Self::Removed => "removed",
            Self::TopologyChanged => "topology_changed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Informational,
    Notice,
    Alert,
}

impl RiskLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Notice => "notice",
            Self::Alert => "alert",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEvent {
    pub occurred_at_ms: i64,
    pub kind: EventKind,
    pub device_path: String,
    pub interface_class: String,
    pub vendor_id: Option<String>,
    pub product_id: Option<String>,
    pub risk: RiskLevel,
    pub reason: String,
}

impl DeviceEvent {
    pub fn from_native(
        occurred_at_ms: i64,
        kind: EventKind,
        device_path: impl Into<String>,
        interface_class: impl Into<String>,
    ) -> Self {
        let device_path = device_path.into();
        let uppercase = device_path.to_ascii_uppercase();
        let vendor_id = marker_value(&uppercase, "VID_");
        let product_id = marker_value(&uppercase, "PID_");
        Self {
            occurred_at_ms,
            kind,
            device_path,
            interface_class: interface_class.into(),
            vendor_id,
            product_id,
            risk: RiskLevel::Informational,
            reason: "native device notification".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedEvent {
    pub sequence: i64,
    #[serde(flatten)]
    pub event: DeviceEvent,
    pub previous_hash: String,
    pub hash: String,
}

#[derive(Debug, Clone)]
pub struct AlertPolicy {
    denied_pairs: Vec<(String, String)>,
    topology_notice: bool,
}

impl AlertPolicy {
    pub fn new(denied_pairs: Vec<(String, String)>) -> Self {
        Self {
            denied_pairs: denied_pairs
                .into_iter()
                .map(|(vendor, product)| {
                    (vendor.to_ascii_uppercase(), product.to_ascii_uppercase())
                })
                .collect(),
            topology_notice: true,
        }
    }

    pub fn evaluate(&self, event: &mut DeviceEvent) {
        if let (Some(vendor), Some(product)) = (&event.vendor_id, &event.product_id)
            && self
                .denied_pairs
                .contains(&(vendor.to_ascii_uppercase(), product.to_ascii_uppercase()))
        {
            event.risk = RiskLevel::Alert;
            event.reason = format!("device pair {vendor}:{product} matches a local alert rule");
        } else if self.topology_notice && event.kind == EventKind::TopologyChanged {
            event.risk = RiskLevel::Notice;
            event.reason = "device topology changed without an interface path".into();
        }
    }
}

impl Default for AlertPolicy {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

pub fn seal(sequence: i64, event: DeviceEvent, previous_hash: String) -> SealedEvent {
    let hash = event_hash(sequence, &event, &previous_hash);
    SealedEvent {
        sequence,
        event,
        previous_hash,
        hash,
    }
}

pub fn verify_chain(events: &[SealedEvent]) -> bool {
    let mut previous = String::new();
    for (index, event) in events.iter().enumerate() {
        if event.sequence != index as i64 + 1
            || event.previous_hash != previous
            || event.hash != event_hash(event.sequence, &event.event, &event.previous_hash)
        {
            return false;
        }
        previous.clone_from(&event.hash);
    }
    true
}

fn event_hash(sequence: i64, event: &DeviceEvent, previous_hash: &str) -> String {
    let canonical = serde_json::to_vec(&(
        sequence,
        event.occurred_at_ms,
        event.kind,
        &event.device_path,
        &event.interface_class,
        &event.vendor_id,
        &event.product_id,
        event.risk,
        &event.reason,
        previous_hash,
    ))
    .expect("event fields serialize");
    format!("{:x}", Sha256::digest(canonical))
}

fn marker_value(path: &str, marker: &str) -> Option<String> {
    let start = path.find(marker)? + marker.len();
    let value: String = path[start..]
        .chars()
        .take_while(|character| character.is_ascii_hexdigit())
        .take(4)
        .collect();
    (value.len() == 4).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_usb_vendor_and_product_without_retaining_secrets() {
        let event = DeviceEvent::from_native(
            1,
            EventKind::Arrived,
            r"\\?\USB#VID_1234&PID_ABCD#SYNTHETIC",
            "usb",
        );
        assert_eq!(event.vendor_id.as_deref(), Some("1234"));
        assert_eq!(event.product_id.as_deref(), Some("ABCD"));
    }

    #[test]
    fn local_pair_rule_produces_explainable_alert() {
        let mut event = DeviceEvent::from_native(
            1,
            EventKind::Arrived,
            r"\\?\USB#VID_1234&PID_ABCD#SYNTHETIC",
            "usb",
        );
        AlertPolicy::new(vec![("1234".into(), "abcd".into())]).evaluate(&mut event);
        assert_eq!(event.risk, RiskLevel::Alert);
        assert!(event.reason.contains("1234:ABCD"));
    }

    #[test]
    fn modified_event_breaks_chain() {
        let first = seal(
            1,
            DeviceEvent::from_native(1, EventKind::Arrived, "device-one", "usb"),
            String::new(),
        );
        let mut second = seal(
            2,
            DeviceEvent::from_native(2, EventKind::Removed, "device-one", "usb"),
            first.hash.clone(),
        );
        assert!(verify_chain(&[first.clone(), second.clone()]));
        second.event.device_path = "changed".into();
        assert!(!verify_chain(&[first, second]));
    }
}
