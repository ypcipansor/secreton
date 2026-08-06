//! The single API envelope used by the REST API, the typed client, and the UI.
//!
//! Before the refactor there were three separate `ApiResponse` definitions (server, shared
//! crate, UI) whose shapes had drifted apart, which forced the UI into a parse-then-fallback
//! heuristic. There is now exactly one, and it lives here.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Envelope wrapping every JSON response from `/api/v1`.
///
/// `data` and `error` are mutually exclusive and both are omitted when empty, so a success
/// carries no `error` key at all rather than an explicit `null`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            metadata: HashMap::new(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
            metadata: HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// Pagination as accepted on the query string, e.g. `?page=2&limit=100`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaginationParams {
    /// 1-based page number.
    #[serde(default = "PaginationParams::default_page")]
    pub page: u32,
    /// Items per page. Clamped by [`PaginationParams::normalized`].
    #[serde(default = "PaginationParams::default_limit")]
    pub limit: u32,
    pub sort_by: Option<String>,
    #[serde(default)]
    pub sort_order: SortOrder,
}

impl PaginationParams {
    pub const MAX_LIMIT: u32 = 1_000;

    fn default_page() -> u32 {
        1
    }
    fn default_limit() -> u32 {
        50
    }

    /// Clamp caller-supplied values into a range the storage layer can serve.
    ///
    /// A `page` of 0 would underflow the offset calculation and an unbounded `limit` is a
    /// trivial way to make the server read an entire table into memory, so both are corrected
    /// here rather than trusted at the call site.
    pub fn normalized(&self) -> Self {
        Self {
            page: self.page.max(1),
            limit: self.limit.clamp(1, Self::MAX_LIMIT),
            sort_by: self.sort_by.clone(),
            sort_order: self.sort_order,
        }
    }

    /// Row offset for the normalized page, saturating instead of overflowing.
    pub fn offset(&self) -> u64 {
        let n = self.normalized();
        u64::from(n.page - 1).saturating_mul(u64::from(n.limit))
    }
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: Self::default_page(),
            limit: Self::default_limit(),
            sort_by: None,
            sort_order: SortOrder::Asc,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    #[default]
    Asc,
    Desc,
}

/// Pagination plus free-form filtering, for list endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QueryParams {
    #[serde(flatten)]
    pub pagination: PaginationParams,
    #[serde(default)]
    pub filters: HashMap<String, String>,
    pub search: Option<String>,
}

/// One page of results plus the cursor information a client needs to ask for the next.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u32,
    pub limit: u32,
}

impl<T> Page<T> {
    pub fn new(items: Vec<T>, total: u64, params: &PaginationParams) -> Self {
        let p = params.normalized();
        Self {
            items,
            total,
            page: p.page,
            limit: p.limit,
        }
    }

    pub fn has_more(&self) -> bool {
        self.total > u64::from(self.page).saturating_mul(u64::from(self.limit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_response_omits_error_key() {
        let json = serde_json::to_value(ApiResponse::success(42)).unwrap();
        assert_eq!(json["data"], 42);
        assert!(json.get("error").is_none());
        assert!(json.get("metadata").is_none());
    }

    #[test]
    fn pagination_clamps_hostile_input() {
        let p = PaginationParams {
            page: 0,
            limit: u32::MAX,
            ..Default::default()
        }
        .normalized();
        assert_eq!(p.page, 1);
        assert_eq!(p.limit, PaginationParams::MAX_LIMIT);
    }

    #[test]
    fn offset_saturates_instead_of_overflowing() {
        let p = PaginationParams {
            page: u32::MAX,
            limit: PaginationParams::MAX_LIMIT,
            ..Default::default()
        };
        // Must not panic under `overflow-checks = true`.
        assert!(p.offset() > 0);
    }

    #[test]
    fn has_more_is_false_on_the_last_page() {
        let params = PaginationParams {
            page: 2,
            limit: 10,
            ..Default::default()
        };
        let page = Page::new(vec![1, 2, 3], 13, &params);
        assert!(!page.has_more());
    }
}
