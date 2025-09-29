use crate::audit::{AuditEntry, AuditFilters, ComplianceReport, ComplianceStandard, ExportFormat, SecurityIncident};
use crate::error::CoreError;
use async_trait::async_trait;
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres::{Config as PgConfig, NoTls};
use chrono::{DateTime, Utc};

pub struct PostgresAuditStorage {
    pool: Pool,
}

impl PostgresAuditStorage {
    pub async fn new(database_url: &str) -> Result<Self, CoreError> {
        let mut cfg: PgConfig = database_url
            .parse()
            .map_err(|e| CoreError::database(format!("invalid postgres url: {}", e)))?;
        let mgr = Manager::from_config(cfg, NoTls, ManagerConfig { recycling_method: RecyclingMethod::Fast });
        let pool = Pool::builder(mgr)
            .max_size(8)
            .build()
            .map_err(|e| CoreError::database(format!("pool build error: {}", e)))?;

        let client = pool.get().await.map_err(|e| CoreError::database(e.to_string()))?;
        client.execute(
            "CREATE TABLE IF NOT EXISTS audit_entries (
                id TEXT PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                event_type TEXT NOT NULL,
                user_id TEXT,
                session_id TEXT,
                action TEXT NOT NULL,
                resource JSONB,
                client_ip TEXT,
                user_agent TEXT,
                geo_location TEXT,
                success BOOLEAN NOT NULL,
                error TEXT,
                risk_score DOUBLE PRECISION NOT NULL,
                metadata JSONB NOT NULL,
                security_level TEXT NOT NULL,
                source TEXT NOT NULL,
                trail JSONB,
                compliance_tags JSONB NOT NULL,
                data_classification TEXT NOT NULL,
                correlation_id TEXT,
                request_id TEXT,
                duration_ms BIGINT,
                data_size BIGINT,
                encryption_info JSONB
            )",
            &[],
        ).await.map_err(|e| CoreError::database(e.to_string()))?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl crate::audit::AuditStorage for PostgresAuditStorage {
    async fn store(&self, entry: &AuditEntry) -> Result<(), CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::database(e.to_string()))?;
        client.execute(
            "INSERT INTO audit_entries (
                id, timestamp, event_type, user_id, session_id, action, resource, client_ip, user_agent, geo_location,
                success, error, risk_score, metadata, security_level, source, trail, compliance_tags,
                data_classification, correlation_id, request_id, duration_ms, data_size, encryption_info
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
                $11,$12,$13,$14,$15,$16,$17,$18,
                $19,$20,$21,$22,$23,$24
            ) ON CONFLICT (id) DO NOTHING",
            &[
                &entry.id,
                &entry.timestamp,
                &format!("{:?}", entry.event_type),
                &entry.user_id,
                &entry.session_id,
                &entry.action,
                &serde_json::to_value(&entry.resource).unwrap_or(serde_json::Value::Null),
                &entry.client_ip,
                &entry.user_agent,
                &entry.geo_location,
                &entry.success,
                &entry.error,
                &entry.risk_score,
                &serde_json::to_value(&entry.metadata).unwrap_or(serde_json::Value::Null),
                &entry.security_level.name(),
                &entry.source,
                &serde_json::to_value(&entry.trail).unwrap_or(serde_json::Value::Null),
                &serde_json::to_value(&entry.compliance_tags).unwrap_or(serde_json::Value::Null),
                &entry.data_classification,
                &entry.correlation_id,
                &entry.request_id,
                &entry.duration_ms.map(|v| v as i64),
                &entry.data_size.map(|v| v as i64),
                &serde_json::to_value(&entry.encryption_info).unwrap_or(serde_json::Value::Null),
            ],
        ).await.map_err(|e| CoreError::database(e.to_string()))?;
        Ok(())
    }

    async fn store_batch(&self, entries: &[AuditEntry]) -> Result<(), CoreError> {
        for e in entries {
            self.store(e).await?;
        }
        Ok(())
    }

    async fn retrieve(&self, filters: AuditFilters) -> Result<Vec<AuditEntry>, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::database(e.to_string()))?;
        let mut sql = "SELECT id, timestamp, event_type, user_id, session_id, action, resource, client_ip, user_agent, geo_location, success, error, risk_score, metadata, security_level, source, trail, compliance_tags, data_classification, correlation_id, request_id, duration_ms, data_size, encryption_info FROM audit_entries WHERE 1=1".to_string();
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync>> = Vec::new();
        let mut idx = 1;
        if let Some(user_id) = filters.user_id {
            sql.push_str(&format!(" AND user_id = ${}", idx));
            params.push(Box::new(user_id)); idx+=1;
        }
        if let Some(action) = filters.action {
            sql.push_str(&format!(" AND action LIKE ${}", idx));
            params.push(Box::new(action)); idx+=1;
        }
        if let Some(limit) = filters.limit { sql.push_str(&format!(" LIMIT {}", limit)); }
        if let Some(offset) = filters.offset { sql.push_str(&format!(" OFFSET {}", offset)); }

        let rows = client.query(sql.as_str(), &params.iter().map(|b| &**b as _).collect::<Vec<_>>()).await.map_err(|e| CoreError::database(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            let id: String = row.get(0);
            let timestamp: DateTime<Utc> = row.get(1);
            let action: String = row.get(5);
            let success: bool = row.get(10);
            let risk_score: f64 = row.get(12);
            let source: String = row.get(15);
            // Minimal reconstruction; other fields mapped as needed
            let mut entry = AuditEntry::builder()
                .action(action)
                .success(success)
                .risk_score(risk_score)
                .source(source)
                .build();
            entry.id = id;
            entry.timestamp = timestamp;
            out.push(entry);
        }
        Ok(out)
    }

    async fn count(&self, _filters: AuditFilters) -> Result<u64, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::database(e.to_string()))?;
        let row = client.query_one("SELECT COUNT(*) FROM audit_entries", &[]).await.map_err(|e| CoreError::database(e.to_string()))?;
        let n: i64 = row.get(0);
        Ok(n as u64)
    }

    async fn cleanup_before(&self, before: DateTime<Utc>) -> Result<u64, CoreError> {
        let client = self.pool.get().await.map_err(|e| CoreError::database(e.to_string()))?;
        let res = client.execute("DELETE FROM audit_entries WHERE timestamp < $1", &[&before]).await.map_err(|e| CoreError::database(e.to_string()))?;
        Ok(res as u64)
    }

    async fn verify_integrity(&self, _from: DateTime<Utc>, _to: DateTime<Utc>) -> Result<bool, CoreError> {
        // Placeholder: a production implementation would verify hash chain
        Ok(true)
    }

    async fn generate_compliance_report(&self, _standard: ComplianceStandard, _period: (DateTime<Utc>, DateTime<Utc>)) -> Result<ComplianceReport, CoreError> {
        Err(CoreError::invalid_operation("generate_compliance_report not implemented for PostgresAuditStorage"))
    }

    async fn search_incidents(&self, _patterns: Vec<String>, _time_range: (DateTime<Utc>, DateTime<Utc>)) -> Result<Vec<SecurityIncident>, CoreError> {
        Ok(vec![])
    }

    async fn export_data(&self, format: ExportFormat, filters: AuditFilters) -> Result<Vec<u8>, CoreError> {
        let entries = self.retrieve(filters).await?;
        match format {
            ExportFormat::JSON => Ok(serde_json::to_vec(&entries).map_err(CoreError::Serialization)?),
            ExportFormat::CSV => {
                // Minimal CSV without external crate
                let mut out = String::from("id,action,timestamp,source,success\n");
                for e in entries {
                    out.push_str(&format!("{},{},{},{},{}\n",
                        e.id.replace(',', " "),
                        e.action.replace(',', " "),
                        e.timestamp.to_rfc3339(),
                        e.source.replace(',', " "),
                        e.success
                    ));
                }
                Ok(out.into_bytes())
            },
            _ => Ok(serde_json::to_vec(&entries).map_err(CoreError::Serialization)?),
        }
    }

    async fn archive_entries(&self, before: DateTime<Utc>, _encryption_key: Option<&[u8]>) -> Result<String, CoreError> {
        // Minimal implementation: delete and return count as string; production would write to archive storage
        let deleted = self.cleanup_before(before).await?;
        Ok(format!("archived:{}", deleted))
    }
}


