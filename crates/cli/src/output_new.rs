use serde::Serialize;

#[derive(Debug, Clone)]
pub enum OutputFormat {
    Json,
    Table,
    Text,
}

impl OutputFormat {
    pub fn format<T: Serialize>(&self, data: &T) -> String {
        match self {
            OutputFormat::Json => serde_json::to_string_pretty(data).unwrap_or_else(|_| "{}".to_string()),
            OutputFormat::Table => serde_json::to_string_pretty(data).unwrap_or_else(|_| "{}".to_string()), // Simple fallback
            OutputFormat::Text => format!("{:?}", data),
        }
    }
}
