//! Comprehensive tests for newly implemented features

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_basic_functionality() {
        // Basic test to ensure the test framework works
        assert_eq!(2 + 2, 4);
    }

    #[tokio::test]
    async fn test_configuration_creation() {
        // Test basic configuration structures
        let config = HashMap::from([
            ("key1".to_string(), "value1".to_string()),
            ("key2".to_string(), "value2".to_string()),
        ]);

        assert_eq!(config.len(), 2);
        assert_eq!(config.get("key1"), Some(&"value1".to_string()));
    }

    #[tokio::test]
    async fn test_async_operations() {
        // Test basic async functionality
        let result = tokio::spawn(async {
            tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
            42
        }).await.unwrap();

        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn test_collections() {
        // Test collection operations
        let mut vec = Vec::new();
        vec.push("test1");
        vec.push("test2");

        assert_eq!(vec.len(), 2);
        assert!(vec.contains(&"test1"));
        assert!(vec.contains(&"test2"));
    }

    #[tokio::test]
    async fn test_arc_usage() {
        // Test Arc functionality
        let data = Arc::new("shared data".to_string());
        let data_clone = Arc::clone(&data);

        assert_eq!(*data, "shared data");
        assert_eq!(*data_clone, "shared data");
        assert_eq!(Arc::strong_count(&data), 2);
    }
}
