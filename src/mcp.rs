//! Local, stateless MCP endpoint. A token is validated against the current vault
//! on *every HTTP request*, not merely on initialize or on a tool call.
use crate::api_keys::{self, Access, ApiKey};
use crate::crypto::VaultKey;
use crate::storage::{UnlockedVault, VaultStore};
use anyhow::{Context, Result};
use axum::{
    body::Body,
    http::{header::AUTHORIZATION, HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    Router,
};
use rmcp::schemars;
use rmcp::{
    handler::server::{tool::Extension, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig},
    tool, tool_handler, tool_router,
    transport::{
        streamable_http_server::{
            session::never::NeverSessionManager, tower::StreamableHttpService,
        },
        StreamableHttpServerConfig,
    },
    ErrorData, ServerHandler,
};
use std::{collections::BTreeMap, net::Ipv4Addr, sync::Arc};

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?;
    if token.is_empty() || token.bytes().any(|b| b.is_ascii_whitespace()) {
        None
    } else {
        Some(token)
    }
}

fn allowed(permissions: &BTreeMap<String, Access>, group: &str, write: bool) -> bool {
    matches!(permissions.get(group), Some(Access::ReadWrite))
        || (!write && matches!(permissions.get(group), Some(Access::ReadOnly)))
}

fn visible_groups<'a>(
    permissions: &BTreeMap<String, Access>,
    names: impl Iterator<Item = &'a str>,
) -> Vec<&'a str> {
    names
        .filter(|name| allowed(permissions, name, false))
        .collect()
}

#[derive(Clone)]
struct State {
    key: VaultKey,
    // Keep in-process writes from clobbering each other while each request reloads the vault.
    writes: Arc<tokio::sync::Mutex<()>>,
}

fn authenticate_request(headers: &HeaderMap, state: &State) -> Result<(UnlockedVault, ApiKey)> {
    let token = bearer(headers).context("missing bearer token")?;
    let vault = VaultStore::new()?.unlock_with_key(state.key)?;
    let api_key = api_keys::authenticate(token, &vault)?;
    Ok((vault, api_key))
}

async fn require_bearer(
    axum::extract::State(state): axum::extract::State<State>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Fail closed for *all* requests including initialize, notifications, GET,
    // and tools/list. Never include the token or vault error in an HTTP response.
    authenticate_request(request.headers(), &state).map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(next.run(request).await)
}

#[derive(Clone)]
struct VaultTools {
    state: State,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
struct GroupArg {
    group: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
struct SearchArg {
    group: String,
    query: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
struct SecretArg {
    group: String,
    key: String,
}

#[derive(serde::Deserialize, schemars::JsonSchema)]
struct SetArg {
    group: String,
    key: String,
    value: String,
}

fn result(value: impl Into<String>) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(value.into())])
}

fn tool_error(message: &'static str) -> ErrorData {
    ErrorData::invalid_params(message, None)
}

impl VaultTools {
    fn new(state: State) -> Self {
        Self { state }
    }

    fn vault_and_key(
        &self,
        parts: &axum::http::request::Parts,
    ) -> Result<(UnlockedVault, ApiKey), ErrorData> {
        authenticate_request(&parts.headers, &self.state).map_err(|_| tool_error("Unauthorized"))
    }

    fn checked_group<'a>(
        &self,
        vault: &'a UnlockedVault,
        key: &ApiKey,
        group: &str,
        write: bool,
    ) -> Result<&'a crate::storage::Group, ErrorData> {
        if !allowed(&key.permissions, group, write) {
            return Err(tool_error("Group access denied"));
        }
        vault
            .data()
            .groups
            .get(group)
            .ok_or_else(|| tool_error("Group not found"))
    }
}

#[tool_router]
impl VaultTools {
    #[tool(description = "List groups visible to this API key (no secret values)")]
    fn list_groups(
        &self,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let (vault, key) = self.vault_and_key(&parts)?;
        let groups = visible_groups(
            &key.permissions,
            vault.data().groups.keys().map(String::as_str),
        );
        Ok(result(
            serde_json::to_string(&groups).map_err(|_| tool_error("Serialization failed"))?,
        ))
    }

    #[tool(description = "List secret names in an authorized group; never returns values")]
    fn list_keys(
        &self,
        Parameters(args): Parameters<GroupArg>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let (vault, key) = self.vault_and_key(&parts)?;
        let group = self.checked_group(&vault, &key, &args.group, false)?;
        let keys: Vec<&str> = group.secrets.keys().map(String::as_str).collect();
        Ok(result(
            serde_json::to_string(&keys).map_err(|_| tool_error("Serialization failed"))?,
        ))
    }

    #[tool(
        description = "Find case-insensitive matching secret names in an authorized group; never returns values"
    )]
    fn search_keys(
        &self,
        Parameters(args): Parameters<SearchArg>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let (vault, key) = self.vault_and_key(&parts)?;
        let group = self.checked_group(&vault, &key, &args.group, false)?;
        let query = args.query.to_lowercase();
        let keys: Vec<&str> = group
            .secrets
            .keys()
            .filter(|name| name.to_lowercase().contains(&query))
            .map(String::as_str)
            .collect();
        Ok(result(
            serde_json::to_string(&keys).map_err(|_| tool_error("Serialization failed"))?,
        ))
    }

    #[tool(description = "Get a secret value from an authorized group")]
    fn get_secret(
        &self,
        Parameters(args): Parameters<SecretArg>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let (vault, key) = self.vault_and_key(&parts)?;
        self.checked_group(&vault, &key, &args.group, false)?;
        let value = vault
            .get_in_group(&args.group, &args.key)
            .map_err(|_| tool_error("Cannot read secret"))?
            .ok_or_else(|| tool_error("Secret not found"))?;
        Ok(result(value))
    }

    #[tool(description = "Set a secret in a group with read-write permission")]
    async fn set_secret(
        &self,
        Parameters(args): Parameters<SetArg>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let _guard = self.state.writes.lock().await;
        let (mut vault, key) = self.vault_and_key(&parts)?;
        self.checked_group(&vault, &key, &args.group, true)?;
        vault
            .set_in_group(&args.group, &args.key, &args.value)
            .map_err(|_| tool_error("Cannot set secret"))?;
        Ok(result("OK"))
    }

    #[tool(description = "Delete a secret in a group with read-write permission")]
    async fn delete_secret(
        &self,
        Parameters(args): Parameters<SecretArg>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<CallToolResult, ErrorData> {
        let _guard = self.state.writes.lock().await;
        let (mut vault, key) = self.vault_and_key(&parts)?;
        self.checked_group(&vault, &key, &args.group, true)?;
        let removed = vault
            .delete_in_group(&args.group, &args.key)
            .map_err(|_| tool_error("Cannot delete secret"))?;
        Ok(result(removed.to_string()))
    }
}

#[tool_handler]
impl ServerHandler for VaultTools {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}

fn router(state: State) -> Router {
    let factory_state = state.clone();
    let service: StreamableHttpService<VaultTools, NeverSessionManager> =
        StreamableHttpService::new(
            move || Ok(VaultTools::new(factory_state.clone())),
            NeverSessionManager::default().into(),
            StreamableHttpServerConfig::default()
                .with_legacy_session_mode(false)
                .with_json_response(true)
                .enforce_origin_validation(),
        );
    Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn_with_state(state, require_bearer))
}

/// Run a localhost-only HTTP MCP service. The vault key is retained only in
/// process memory; every request opens the *current* encrypted vault file.
pub fn start(port: u16) -> Result<()> {
    let password = match std::env::var("KS_PASSWORD") {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => rpassword::prompt_password("Vault password: ")?,
        Err(err) => return Err(err.into()),
    };
    let vault = VaultStore::new()?
        .unlock(&password)
        .context("failed to unlock vault")?;
    let state = State {
        key: *vault.key(),
        writes: Arc::new(tokio::sync::Mutex::new(())),
    };
    drop(vault);
    drop(password);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        println!(
            "MCP server listening on http://127.0.0.1:{}/mcp",
            listener.local_addr()?.port()
        );
        axum::serve(listener, router(state))
            .await
            .context("MCP server failed")
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_keys::Access;
    use std::collections::BTreeMap;
    use tower::ServiceExt;

    async fn call_http(
        state: &State,
        token: &str,
        method: &str,
        params: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("Host", "localhost")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2025-03-26")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::from(
                serde_json::json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params})
                    .to_string(),
            ))
            .unwrap();
        let response = router(state.clone()).oneshot(request).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    async fn run_authorized_http_fixture() {
        let mut vault = VaultStore::new()
            .unwrap()
            .create("isolated test password")
            .unwrap();
        vault
            .set_in_group("default", "VISIBLE", "visible value")
            .unwrap();
        vault.create_group("private").unwrap();
        vault
            .set_in_group("private", "HIDDEN", "hidden value")
            .unwrap();
        let (read_id, read_token) = vault
            .create_api_key("readonly", key(&[("default", Access::ReadOnly)]), None)
            .unwrap();
        let (_, write_token) = vault
            .create_api_key("writer", key(&[("private", Access::ReadWrite)]), None)
            .unwrap();
        let state = State {
            key: *vault.key(),
            writes: Arc::new(tokio::sync::Mutex::new(())),
        };

        let (status, initialize) = call_http(&state, &read_token, "initialize", serde_json::json!({"protocolVersion":"2025-03-26", "capabilities":{}, "clientInfo":{"name":"test", "version":"1"}})).await;
        assert_eq!(status, StatusCode::OK);
        assert!(initialize.get("result").is_some(), "initialization failed");
        let (status, tools) =
            call_http(&state, &read_token, "tools/list", serde_json::json!({})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(tools["result"]["tools"].as_array().unwrap().len(), 6);

        let (_, groups) = call_http(
            &state,
            &read_token,
            "tools/call",
            serde_json::json!({"name":"list_groups","arguments":{}}),
        )
        .await;
        assert_eq!(groups["result"]["content"][0]["text"], "[\"default\"]");
        let (_, value) = call_http(&state, &read_token, "tools/call", serde_json::json!({"name":"get_secret","arguments":{"group":"default","key":"VISIBLE"}})).await;
        assert_eq!(value["result"]["content"][0]["text"], "visible value");
        let (_, denied_write) = call_http(&state, &read_token, "tools/call", serde_json::json!({"name":"set_secret","arguments":{"group":"default","key":"X","value":"no"}})).await;
        assert!(denied_write.get("error").is_some() || denied_write["result"]["isError"] == true);
        let (_, denied_group) = call_http(
            &state,
            &read_token,
            "tools/call",
            serde_json::json!({"name":"get_secret","arguments":{"group":"private","key":"HIDDEN"}}),
        )
        .await;
        assert!(denied_group.get("error").is_some() || denied_group["result"]["isError"] == true);
        assert!(vault.get_in_group("default", "X").unwrap().is_none());

        let (_, other_value) = call_http(
            &state,
            &write_token,
            "tools/call",
            serde_json::json!({"name":"get_secret","arguments":{"group":"private","key":"HIDDEN"}}),
        )
        .await;
        assert_eq!(other_value["result"]["content"][0]["text"], "hidden value");
        let (_, other_groups) = call_http(
            &state,
            &write_token,
            "tools/call",
            serde_json::json!({"name":"list_groups","arguments":{}}),
        )
        .await;
        assert_eq!(
            other_groups["result"]["content"][0]["text"],
            "[\"private\"]"
        );

        vault.delete_api_key(&read_id).unwrap();
        let (status, _) = call_http(&state, &read_token, "tools/list", serde_json::json!({})).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    fn key(scopes: &[(&str, Access)]) -> BTreeMap<String, Access> {
        scopes
            .iter()
            .map(|(name, access)| (name.to_string(), *access))
            .collect()
    }

    #[test]
    fn bearer_rejects_missing_malformed_and_empty_header() {
        let mut headers = axum::http::HeaderMap::new();
        assert!(bearer(&headers).is_none());
        for value in ["token", "Basic foo", "Bearer ", "Bearer x y"] {
            headers.insert(axum::http::header::AUTHORIZATION, value.parse().unwrap());
            assert!(
                bearer(&headers).is_none(),
                "accepted malformed bearer header"
            );
        }
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer abc.def.ghi".parse().unwrap(),
        );
        assert_eq!(bearer(&headers), Some("abc.def.ghi"));
    }

    #[test]
    fn authorization_is_scoped_to_exact_group_and_access_level() {
        let key = key(&[("team", Access::ReadOnly), ("prod", Access::ReadWrite)]);
        assert!(allowed(&key, "team", false));
        assert!(!allowed(&key, "team", true));
        assert!(allowed(&key, "prod", false));
        assert!(allowed(&key, "prod", true));
        assert!(!allowed(&key, "team-other", false));
    }

    #[test]
    fn group_listing_only_exposes_authorized_existing_groups() {
        let key = key(&[("team", Access::ReadOnly), ("removed", Access::ReadWrite)]);
        let names = ["team", "personal"];
        assert_eq!(visible_groups(&key, names.into_iter()), vec!["team"]);
    }

    #[tokio::test]
    async fn http_initialization_and_listing_require_a_bearer_even_without_tool_call() {
        use tower::ServiceExt;
        let state = State {
            key: [0; 32],
            writes: Arc::new(tokio::sync::Mutex::new(())),
        };
        for body in [
            serde_json::json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{"protocolVersion":"2025-03-26", "capabilities":{}, "clientInfo":{"name":"test", "version":"1"}}}),
            serde_json::json!({"jsonrpc":"2.0", "id":2, "method":"tools/list"}),
        ] {
            let request = Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("Content-Type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();
            let response = router(state.clone()).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[test]
    fn only_six_secret_tools_are_advertised() {
        let state = State {
            key: [0; 32],
            writes: Arc::new(tokio::sync::Mutex::new(())),
        };
        let _ = VaultTools::new(state);
        let names: Vec<_> = VaultTools::tool_router()
            .list_all()
            .into_iter()
            .map(|tool| tool.name.to_string())
            .collect();
        assert_eq!(
            names,
            [
                "delete_secret",
                "get_secret",
                "list_groups",
                "list_keys",
                "search_keys",
                "set_secret"
            ]
        );
    }

    #[tokio::test]
    async fn authorized_http_scopes_and_revocation() {
        if std::env::var_os("KS_MCP_HTTP_CHILD").is_some() {
            run_authorized_http_fixture().await;
        } else {
            // HOME is process-global; isolate the real vault fixture in a child
            // process so parallel tests cannot access a user's vault.
            let home = std::path::PathBuf::from(std::env::var_os("HOME").unwrap());
            let scratch = if home.to_string_lossy().contains("/.hermes/cache/scratch") {
                home
            } else {
                home.join(".hermes/cache/scratch")
            };
            let test_home = scratch.join(format!("ks-mcp-http-{}", api_keys::new_id()));
            std::fs::create_dir_all(&test_home).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "mcp::tests::authorized_http_scopes_and_revocation",
                    "--nocapture",
                ])
                .env("HOME", &test_home)
                .env("KS_MCP_HTTP_CHILD", "1")
                .output()
                .unwrap();
            let _ = std::fs::remove_dir_all(&test_home);
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "child fixture did not run"
            );
        }
    }
}
