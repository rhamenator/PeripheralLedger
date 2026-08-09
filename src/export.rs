use serde::Serialize;

use crate::SealedEvent;

pub fn to_json(events: &[SealedEvent]) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(events)
}

pub fn to_csv(events: &[SealedEvent]) -> Result<String, csv::Error> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    for event in events {
        writer.serialize(CsvEventRow::from(event))?;
    }
    let bytes = writer.into_inner().map_err(|error| error.into_error())?;
    Ok(String::from_utf8(bytes).expect("CSV fields are UTF-8"))
}

#[derive(Serialize)]
struct CsvEventRow<'a> {
    sequence: i64,
    occurred_at_ms: i64,
    kind: &'a str,
    device_path: &'a str,
    interface_class: &'a str,
    vendor_id: Option<&'a str>,
    product_id: Option<&'a str>,
    risk: &'a str,
    reason: &'a str,
    previous_hash: &'a str,
    hash: &'a str,
}

impl<'a> From<&'a SealedEvent> for CsvEventRow<'a> {
    fn from(value: &'a SealedEvent) -> Self {
        Self {
            sequence: value.sequence,
            occurred_at_ms: value.event.occurred_at_ms,
            kind: value.event.kind.as_str(),
            device_path: &value.event.device_path,
            interface_class: &value.event.interface_class,
            vendor_id: value.event.vendor_id.as_deref(),
            product_id: value.event.product_id.as_deref(),
            risk: value.event.risk.as_str(),
            reason: &value.event.reason,
            previous_hash: &value.previous_hash,
            hash: &value.hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceEvent, EventKind, seal};

    #[test]
    fn exports_json_and_csv() {
        let event = seal(
            1,
            DeviceEvent::from_native(1, EventKind::Arrived, "synthetic", "usb"),
            String::new(),
        );
        assert!(
            to_json(std::slice::from_ref(&event))
                .unwrap()
                .contains("device_path")
        );
        let csv = to_csv(&[event]).unwrap();
        assert!(csv.contains("sequence"));
        assert!(csv.contains("synthetic"));
    }
}
