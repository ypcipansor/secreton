use serde::Serialize;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum OutputFormat {
    Json,
    Table,
    Text,
}

#[allow(dead_code)]
impl OutputFormat {
    pub fn format<T: Serialize + std::fmt::Debug>(&self, data: &T) -> String {
        match self {
            OutputFormat::Json => {
                serde_json::to_string_pretty(data).unwrap_or_else(|_| "{}".to_string())
            }
            OutputFormat::Table => {
                serde_json::to_string_pretty(data).unwrap_or_else(|_| "{}".to_string())
            } // Simple fallback
            OutputFormat::Text => format!("{:?}", data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Serialize)]
    struct SampleData {
        name: String,
        value: i32,
    }

    fn sample() -> SampleData {
        SampleData {
            name: "example".into(),
            value: 42,
        }
    }

    #[test]
    fn test_json_format() {
        let formatted = OutputFormat::Json.format(&sample());
        assert!(formatted.contains("\"name\""));
        assert!(formatted.contains("example"));
    }

    #[test]
    fn test_table_format_fallback() {
        let formatted = OutputFormat::Table.format(&sample());
        assert!(formatted.contains("example"));
        // Table currently falls back to pretty JSON
        assert!(formatted.contains("\"value\""));
    }

    #[test]
    fn test_text_format() {
        let formatted = OutputFormat::Text.format(&sample());
        assert!(formatted.contains("SampleData"));
        assert!(formatted.contains("value: 42"));
    }
}
