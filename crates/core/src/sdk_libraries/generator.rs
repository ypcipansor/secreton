use std::collections::HashMap;

use super::{go_sdk, js_sdk, python_sdk};

/// SDK generation utilities
pub struct SdkGenerator;

impl SdkGenerator {
    /// Generate all SDKs
    pub fn generate_all_sdks() -> HashMap<String, String> {
        let mut sdks = HashMap::new();

        sdks.insert("go".to_string(), go_sdk::generate_go_sdk());
        sdks.insert("python".to_string(), python_sdk::generate_python_sdk());
        sdks.insert("typescript".to_string(), js_sdk::generate_typescript_sdk());

        sdks
    }

    /// Generate SDK documentation
    pub fn generate_documentation() -> String {
        r#"
# Secreton SDK Libraries

This document describes the available SDK libraries for integrating with Secreton.

## Supported Languages

### Go SDK
- **Package**: `github.com/secreton/secreton-go`
- **Features**: Full API coverage, type-safe client, context support
- **Installation**: `go get github.com/secreton/secreton-go`

### Python SDK
- **Package**: `secreton`
- **Features**: Type hints, async support, comprehensive error handling
- **Installation**: `pip install secreton`

### TypeScript/JavaScript SDK
- **Package**: `@secreton/client`
- **Features**: TypeScript definitions, promise-based API, browser support
- **Installation**: `npm install @secreton/client`

## Common Usage Patterns

### Authentication
All SDKs support token-based authentication:

```go
client := secreton.NewClient("https://your-secreton-server.com", "your-token")
```

```python
client = secreton.create_client("https://your-secreton-server.com", "your-token")
```

```typescript
const client = createClient({
  serverUrl: "https://your-secreton-server.com",
  token: "your-token"
});
```

### CRUD Operations
All SDKs provide consistent CRUD operations:

```go
// Create
err := client.CreateSecret("path/to/secret", map[string]string{
    "key": "value",
})

// Read
data, err := client.ReadSecret("path/to/secret")

// Update
err = client.UpdateSecret("path/to/secret", map[string]string{
    "key": "new-value",
})

// Delete
err = client.DeleteSecret("path/to/secret")
```

## Error Handling

All SDKs provide comprehensive error handling with detailed error messages and appropriate HTTP status codes.

## Examples

See the `examples/` directory for complete usage examples in each supported language.
"#
        .to_string()
    }
}
