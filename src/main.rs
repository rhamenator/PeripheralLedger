use anyhow::{Context, Result};
use peripheral_ledger::{
    AlertPolicy, DeviceEvent, EventKind, EventStore, RiskLevel, to_csv, to_json,
};

fn main() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        #[cfg(windows)]
        Some("service") => {
            peripheral_ledger::service::dispatch().context("start service dispatcher")
        }
        Some("export-json") => export(arguments.next(), true),
        Some("export-csv") => export(arguments.next(), false),
        Some("demo") | None => demo(),
        Some(command) => anyhow::bail!("unknown command: {command}"),
    }
}

fn export(path: Option<String>, json: bool) -> Result<()> {
    let path = path.context("database path is required")?;
    let store = EventStore::open(path)?;
    store.verify()?;
    let events = store.all()?;
    if json {
        println!("{}", to_json(&events)?);
    } else {
        print!("{}", to_csv(&events)?);
    }
    Ok(())
}

fn demo() -> Result<()> {
    let mut store = EventStore::in_memory()?;
    let policy = AlertPolicy::new(vec![("1234".into(), "ABCD".into())]);
    let mut arrived = DeviceEvent::from_native(
        1_800_000_000_000,
        EventKind::Arrived,
        r"\\?\USB#VID_1234&PID_ABCD#SYNTHETIC",
        "{00000000-0000-0000-0000-000000000000}",
    );
    policy.evaluate(&mut arrived);
    let sealed = store.append(arrived)?;
    store.append(DeviceEvent {
        occurred_at_ms: 1_800_000_001_000,
        kind: EventKind::Removed,
        device_path: sealed.event.device_path.clone(),
        interface_class: sealed.event.interface_class.clone(),
        vendor_id: sealed.event.vendor_id.clone(),
        product_id: sealed.event.product_id.clone(),
        risk: RiskLevel::Informational,
        reason: "synthetic removal".into(),
    })?;
    store.verify()?;
    println!(
        "events={} chain_valid=true first_risk={}",
        store.all()?.len(),
        sealed.event.risk.as_str()
    );
    Ok(())
}
