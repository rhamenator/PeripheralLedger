use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

use crate::{DeviceEvent, EventKind, RiskLevel, SealedEvent, seal, verify_chain};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("event chain verification failed")]
    InvalidChain,
    #[error("stored event value is invalid: {0}")]
    InvalidValue(String),
}

pub struct EventStore {
    connection: Connection,
}

impl EventStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let connection = Connection::open(path)?;
        Self::from_connection(connection)
    }

    pub fn in_memory() -> Result<Self, StoreError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> Result<Self, StoreError> {
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS device_events (
                sequence INTEGER PRIMARY KEY,
                occurred_at_ms INTEGER NOT NULL,
                kind TEXT NOT NULL,
                device_path TEXT NOT NULL,
                interface_class TEXT NOT NULL,
                vendor_id TEXT,
                product_id TEXT,
                risk TEXT NOT NULL,
                reason TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                hash TEXT NOT NULL UNIQUE
            );",
        )?;
        Ok(Self { connection })
    }

    pub fn append(&mut self, event: DeviceEvent) -> Result<SealedEvent, StoreError> {
        let transaction = self.connection.transaction()?;
        let previous: Option<(i64, String)> = transaction
            .query_row(
                "SELECT sequence, hash FROM device_events ORDER BY sequence DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (sequence, previous_hash) = previous
            .map(|(sequence, hash)| (sequence + 1, hash))
            .unwrap_or((1, String::new()));
        let sealed = seal(sequence, event, previous_hash);
        transaction.execute(
            "INSERT INTO device_events
             (sequence, occurred_at_ms, kind, device_path, interface_class, vendor_id,
              product_id, risk, reason, previous_hash, hash)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                sealed.sequence,
                sealed.event.occurred_at_ms,
                sealed.event.kind.as_str(),
                sealed.event.device_path,
                sealed.event.interface_class,
                sealed.event.vendor_id,
                sealed.event.product_id,
                sealed.event.risk.as_str(),
                sealed.event.reason,
                sealed.previous_hash,
                sealed.hash,
            ],
        )?;
        transaction.commit()?;
        Ok(sealed)
    }

    pub fn all(&self) -> Result<Vec<SealedEvent>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT sequence, occurred_at_ms, kind, device_path, interface_class,
                    vendor_id, product_id, risk, reason, previous_hash, hash
             FROM device_events ORDER BY sequence",
        )?;
        statement
            .query_map([], |row| {
                let kind: String = row.get(2)?;
                let risk: String = row.get(7)?;
                Ok(SealedEvent {
                    sequence: row.get(0)?,
                    event: DeviceEvent {
                        occurred_at_ms: row.get(1)?,
                        kind: parse_kind(&kind).map_err(to_sql_error)?,
                        device_path: row.get(3)?,
                        interface_class: row.get(4)?,
                        vendor_id: row.get(5)?,
                        product_id: row.get(6)?,
                        risk: parse_risk(&risk).map_err(to_sql_error)?,
                        reason: row.get(8)?,
                    },
                    previous_hash: row.get(9)?,
                    hash: row.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn verify(&self) -> Result<(), StoreError> {
        verify_chain(&self.all()?)
            .then_some(())
            .ok_or(StoreError::InvalidChain)
    }
}

fn parse_kind(value: &str) -> Result<EventKind, String> {
    match value {
        "arrived" => Ok(EventKind::Arrived),
        "removed" => Ok(EventKind::Removed),
        "topology_changed" => Ok(EventKind::TopologyChanged),
        _ => Err(value.into()),
    }
}

fn parse_risk(value: &str) -> Result<RiskLevel, String> {
    match value {
        "informational" => Ok(RiskLevel::Informational),
        "notice" => Ok(RiskLevel::Notice),
        "alert" => Ok(RiskLevel::Alert),
        _ => Err(value.into()),
    }
}

fn to_sql_error(value: String) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(StoreError::InvalidValue(value)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_roundtrip_keeps_valid_chain() {
        let mut store = EventStore::in_memory().unwrap();
        store
            .append(DeviceEvent::from_native(
                1,
                EventKind::Arrived,
                "synthetic-one",
                "usb",
            ))
            .unwrap();
        store
            .append(DeviceEvent::from_native(
                2,
                EventKind::Removed,
                "synthetic-one",
                "usb",
            ))
            .unwrap();
        assert_eq!(store.all().unwrap().len(), 2);
        store.verify().unwrap();
    }
}
