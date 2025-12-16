//! MCP Server Template
//!
//! Provides reusable server infrastructure with stdio and TCP transports.

use crate::config::ServerConfig;
use crate::data;
use crate::error::{McpError, Result};
use crate::ipc::{AgentClient, SharedAgentClient};
use crate::meta::{ServerIdentity, SharedMetaTools};
use crate::registry::ToolRegistry;
use crate::types::{Prompt, Resource};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// Transport mode for the server
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Standard input/output (for Claude Desktop)
    Stdio,
    /// TCP socket on specified port
    Tcp(u16),
}

/// Re-export ServerIdentity for convenience
pub use crate::meta::ServerIdentity as McpServerIdentity;

/// MCP Server with configurable transport
pub struct McpServer {
    /// Server identity
    identity: ServerIdentity,
    /// Server configuration (used for timeouts, retry settings)
    #[allow(dead_code)]
    config: ServerConfig,
    /// Tool registry
    registry: Arc<RwLock<ToolRegistry>>,
    /// Registered prompts
    prompts: Arc<RwLock<HashMap<String, Prompt>>>,
    /// Registered resources
    resources: Arc<RwLock<Vec<Resource>>>,
    /// Agent client
    agent: SharedAgentClient,
    /// Shared meta tools handler
    meta_tools: Arc<SharedMetaTools>,
    /// Custom tool handler
    tool_handler: Option<Arc<dyn ToolHandlerFn>>,
    /// Custom prompt handler
    prompt_handler: Option<Arc<dyn PromptHandlerFn>>,
}

/// Trait for custom tool handlers
pub trait ToolHandlerFn: Send + Sync {
    fn handle(
        &self,
        name: String,
        args: serde_json::Value,
        agent: SharedAgentClient,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + '_>>;
}

/// Trait for custom prompt handlers
pub trait PromptHandlerFn: Send + Sync {
    fn handle(
        &self,
        name: String,
        args: serde_json::Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send>>;
}

impl<F, Fut> ToolHandlerFn for F
where
    F: Fn(String, serde_json::Value, SharedAgentClient) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Result<serde_json::Value>> + Send + 'static,
{
    fn handle(
        &self,
        name: String,
        args: serde_json::Value,
        agent: SharedAgentClient,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + '_>>
    {
        Box::pin(self(name, args, agent))
    }
}

impl<F, Fut> PromptHandlerFn for F
where
    F: Fn(String, serde_json::Value) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = Result<serde_json::Value>> + Send + 'static,
{
    fn handle(
        &self,
        name: String,
        args: serde_json::Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send>>
    {
        Box::pin(self(name, args))
    }
}

/// JSON-RPC request structure
#[derive(Debug, Clone, Deserialize)]
struct JsonRpcRequest {
    /// JSON-RPC version (should be "2.0")
    #[serde(default)]
    #[allow(dead_code)]
    jsonrpc: String,
    /// Request ID (None for notifications)
    id: Option<serde_json::Value>,
    /// Method name
    method: String,
    /// Method parameters
    #[serde(default)]
    params: serde_json::Value,
}

impl JsonRpcRequest {
    /// Validate the request structure
    fn validate(&self) -> Result<()> {
        // Method name validation
        if self.method.is_empty() {
            return Err(McpError::InvalidParams(
                "Method name cannot be empty".to_string(),
            ));
        }
        if self.method.len() > 256 {
            return Err(McpError::InvalidParams(
                "Method name too long (max 256 chars)".to_string(),
            ));
        }
        Ok(())
    }
}

impl McpServer {
    /// Create a new MCP server
    pub fn new(identity: ServerIdentity, config: ServerConfig) -> Self {
        let meta_tools = Arc::new(SharedMetaTools::new(identity.clone()));
        let mut registry = ToolRegistry::new();

        // Register shared meta tools
        if let Err(e) = meta_tools.register(&mut registry) {
            error!("Failed to register meta tools: {}", e);
        }

        // Load prompts
        let mut prompts = HashMap::new();
        match data::parse_prompts_list() {
            Ok(json) => match serde_json::from_value::<Vec<Prompt>>(json) {
                Ok(list) => {
                    for p in list {
                        prompts.insert(p.name.clone(), p);
                    }
                    debug!("Loaded {} prompts from embedded data", prompts.len());
                }
                Err(e) => error!("Failed to deserialize prompts: {}", e),
            },
            Err(e) => error!("Failed to load prompts: {}", e),
        }

        // Load resources
        let mut resources = Vec::new();
        match data::parse_resources_list() {
            Ok(json) => match serde_json::from_value::<Vec<Resource>>(json) {
                Ok(list) => {
                    resources = list;
                    debug!("Loaded {} resources from embedded data", resources.len());
                }
                Err(e) => error!("Failed to deserialize resources: {}", e),
            },
            Err(e) => error!("Failed to load resources: {}", e),
        }

        Self {
            identity,
            agent: Arc::new(AgentClient::with_config(config.clone())),
            config,
            registry: Arc::new(RwLock::new(registry)),
            prompts: Arc::new(RwLock::new(prompts)),
            resources: Arc::new(RwLock::new(resources)),
            meta_tools,
            tool_handler: None,
            prompt_handler: None,
        }
    }

    /// Create server for ghost-core-mcp
    pub fn core() -> Self {
        Self::new(ServerIdentity::core(), ServerConfig::core())
    }

    /// Create server for ghost-analysis-mcp
    pub fn analysis() -> Self {
        Self::new(ServerIdentity::analysis(), ServerConfig::analysis())
    }

    /// Create server for ghost-static-mcp
    pub fn static_analysis() -> Self {
        Self::new(
            ServerIdentity::static_analysis(),
            ServerConfig::static_analysis(),
        )
    }

    /// Create server for ghost-extended-mcp
    pub fn extended() -> Self {
        Self::new(ServerIdentity::extended(), ServerConfig::extended())
    }

    /// Set custom tool handler
    pub fn with_tool_handler<H: ToolHandlerFn + 'static>(mut self, handler: H) -> Self {
        self.tool_handler = Some(Arc::new(handler));
        self
    }

    /// Set custom prompt handler
    pub fn with_prompt_handler<H: PromptHandlerFn + 'static>(mut self, handler: H) -> Self {
        self.prompt_handler = Some(Arc::new(handler));
        self
    }

    /// Register prompts
    pub async fn register_prompts(&self, prompts: Vec<Prompt>) {
        let mut registry = self.prompts.write().await;
        for prompt in prompts {
            registry.insert(prompt.name.clone(), prompt);
        }
    }

    /// Get mutable access to registry for tool registration
    pub async fn registry(&self) -> tokio::sync::RwLockWriteGuard<'_, ToolRegistry> {
        self.registry.write().await
    }

    /// Get read access to registry
    pub async fn registry_read(&self) -> tokio::sync::RwLockReadGuard<'_, ToolRegistry> {
        self.registry.read().await
    }

    /// Get agent client reference
    pub fn agent(&self) -> &SharedAgentClient {
        &self.agent
    }

    /// Get server identity
    pub fn identity(&self) -> &ServerIdentity {
        &self.identity
    }

    /// Try to connect to agent
    pub async fn try_connect_agent(&self) -> bool {
        self.agent.try_connect().await
    }

    /// Connect to agent with retry
    pub async fn connect_agent(&self) -> Result<()> {
        self.agent.connect().await
    }

    /// Run server in stdio mode
    pub async fn serve_stdio(self) -> Result<()> {
        info!("Starting {} in stdio mode", self.identity.name);

        // Try to connect to agent
        self.try_connect_agent().await;

        let stdin = BufReader::new(tokio::io::stdin());
        let mut stdout = tokio::io::stdout();
        let mut lines = stdin.lines();

        info!("MCP server ready, waiting for requests...");

        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim().is_empty() {
                continue;
            }

            // Log request (truncated)
            let truncated = if line.len() > 500 {
                let mut end = 500;
                while end > 0 && !line.is_char_boundary(end) {
                    end -= 1;
                }
                format!("{}...[truncated]", &line[..end])
            } else {
                line.clone()
            };
            debug!(direction = "REQUEST", "{}", truncated);

            let response = self.handle_request(&line).await;

            // Don't send response for notifications
            if !response.is_null() {
                let response_str =
                    serde_json::to_string(&response).map_err(McpError::Serialization)?;

                // Log response (truncated)
                let truncated_resp = if response_str.len() > 500 {
                    let mut end = 500;
                    while end > 0 && !response_str.is_char_boundary(end) {
                        end -= 1;
                    }
                    format!("{}...[truncated]", &response_str[..end])
                } else {
                    response_str.clone()
                };
                debug!(direction = "RESPONSE", "{}", truncated_resp);

                stdout.write_all(response_str.as_bytes()).await?;
                stdout.write_all(b"\n").await?;
                stdout.flush().await?;
            }
        }

        info!("Server shutdown complete");
        Ok(())
    }

    /// Run server in TCP mode
    pub async fn serve_tcp(self, port: u16) -> Result<()> {
        let addr = format!("127.0.0.1:{}", port);
        info!("Starting {} on {}", self.identity.name, addr);

        let listener = TcpListener::bind(&addr).await?;
        info!("Listening on {}", addr);

        // Try to connect to agent
        self.try_connect_agent().await;

        let server = Arc::new(self);

        loop {
            let (stream, peer) = listener.accept().await?;
            info!("New connection from {}", peer);

            let server_clone = Arc::clone(&server);
            tokio::spawn(async move {
                if let Err(e) = server_clone.handle_tcp_connection(stream).await {
                    error!("Connection error: {}", e);
                }
            });
        }
    }

    /// Handle a single TCP connection
    async fn handle_tcp_connection(&self, stream: TcpStream) -> Result<()> {
        stream.set_nodelay(true)?;
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim().is_empty() {
                continue;
            }

            let response = self.handle_request(&line).await;

            if !response.is_null() {
                let response_str = serde_json::to_string(&response)?;
                writer.write_all(response_str.as_bytes()).await?;
                writer.write_all(b"\n").await?;
                writer.flush().await?;
            }
        }

        Ok(())
    }

    /// Run with specified transport
    pub async fn serve(self, transport: Transport) -> Result<()> {
        match transport {
            Transport::Stdio => self.serve_stdio().await,
            Transport::Tcp(port) => self.serve_tcp(port).await,
        }
    }

    /// Handle a JSON-RPC request
    async fn handle_request(&self, line: &str) -> serde_json::Value {
        // Defensive: limit request size
        if line.len() > 1024 * 1024 {
            error!(target: "ghost_mcp::server", size = line.len(), "Request too large");
            return serde_json::json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": -32600,
                    "message": "Request too large (max 1MB)"
                }
            });
        }

        let request: JsonRpcRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                error!(target: "ghost_mcp::server", error = %e, "Failed to parse request");
                return serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {
                        "code": -32700,
                        "message": format!("Parse error: {}", e)
                    }
                });
            }
        };

        // Validate request structure
        if let Err(e) = request.validate() {
            error!(target: "ghost_mcp::server", error = %e, "Invalid request");
            return serde_json::json!({
                "jsonrpc": "2.0",
                "id": request.id,
                "error": {
                    "code": e.to_jsonrpc_code(),
                    "message": e.to_string()
                }
            });
        }

        // Handle notifications (no id)
        if request.id.is_none() {
            self.handle_notification(&request.method, &request.params)
                .await;
            return serde_json::Value::Null;
        }

        let id = request.id.clone().unwrap_or(serde_json::Value::Null);

        match self.dispatch_method(&request.method, request.params).await {
            Ok(result) => serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result
            }),
            Err(e) => serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": e.to_jsonrpc_code(),
                    "message": e.to_string()
                }
            }),
        }
    }

    /// Dispatch method call
    async fn dispatch_method(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        match method {
            // MCP protocol methods
            "initialize" => self.handle_initialize(&params).await,
            "tools/list" => self.handle_tools_list().await,
            "tools/call" => self.handle_tools_call(&params).await,
            "resources/list" => self.handle_resources_list().await,
            "resources/read" => self.handle_resources_read(&params).await,
            "prompts/list" => self.handle_prompts_list().await,
            "prompts/get" => self.handle_prompts_get(&params).await,

            // Unknown method
            _ => Err(McpError::Protocol(format!("Unknown method: {}", method))),
        }
    }

    /// Handle notifications
    async fn handle_notification(&self, method: &str, _params: &serde_json::Value) {
        match method {
            "notifications/initialized" => {
                info!("Client initialized");
            }
            "notifications/cancelled" => {
                debug!("Request cancelled");
            }
            _ => {
                debug!("Unknown notification: {}", method);
            }
        }
    }

    /// Handle initialize
    async fn handle_initialize(&self, _params: &serde_json::Value) -> Result<serde_json::Value> {
        let registry: tokio::sync::RwLockReadGuard<ToolRegistry> = self.registry.read().await;
        Ok(serde_json::json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": self.identity.name,
                "version": crate::VERSION
            },
            "capabilities": {
                "tools": {
                    "listChanged": false
                },
                "resources": {
                    "subscribe": false,
                    "listChanged": false
                },
                "prompts": {
                    "listChanged": false
                }
            },
            "instructions": format!(
                "{} - {} tools available across {} categories",
                self.identity.description,
                registry.len(),
                self.identity.categories.len()
            )
        }))
    }

    /// Handle tools/list
    async fn handle_tools_list(&self) -> Result<serde_json::Value> {
        let registry: tokio::sync::RwLockReadGuard<ToolRegistry> = self.registry.read().await;
        let tools = registry.to_mcp_tools();
        Ok(serde_json::json!({ "tools": tools }))
    }

    /// Handle tools/call
    async fn handle_tools_call(&self, params: &serde_json::Value) -> Result<serde_json::Value> {
        let name = params
            .get("name")
            .and_then(|n| n.as_str())
            .ok_or_else(|| McpError::InvalidParams("Missing 'name' parameter".to_string()))?;

        let args = params
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::json!({}));

        debug!("Tool call: {} with args: {:?}", name, args);

        // Check if it's a meta tool
        match name {
            "mcp_capabilities" => {
                let registry: tokio::sync::RwLockReadGuard<ToolRegistry> =
                    self.registry.read().await;
                return self.meta_tools.handle_capabilities(&args, &registry);
            }
            "mcp_documentation" => {
                let registry: tokio::sync::RwLockReadGuard<ToolRegistry> =
                    self.registry.read().await;
                return self.meta_tools.handle_documentation(&args, &registry);
            }
            "mcp_version" => {
                let registry: tokio::sync::RwLockReadGuard<ToolRegistry> =
                    self.registry.read().await;
                return self.meta_tools.handle_version(&registry);
            }
            "mcp_health" => {
                let registry: tokio::sync::RwLockReadGuard<ToolRegistry> =
                    self.registry.read().await;
                return self
                    .meta_tools
                    .handle_health(Some(&self.agent), &registry)
                    .await;
            }
            _ => {}
        }

        // Defensive: refuse to forward if agent is not healthy (only for non-meta tools)
        // Try to connect/reconnect if not connected
        if !matches!(
            name,
            "mcp_capabilities" | "mcp_documentation" | "mcp_version" | "mcp_health"
        ) && (!self.agent.is_connected() || !self.agent.is_healthy().await)
        {
            // Attempt to connect before failing
            debug!("Agent not connected, attempting connection...");
            if !self.agent.try_connect().await {
                return Err(McpError::AgentNotConnected);
            }
        }

        // Check registry for tool with handler
        {
            let registry: tokio::sync::RwLockReadGuard<ToolRegistry> = self.registry.read().await;
            if let Some(tool) = registry.get(name) {
                if let Some(handler) = tool.handler() {
                    return handler(args).await;
                }
            }
        }

        // Try custom handler
        if let Some(ref handler) = self.tool_handler {
            return handler
                .handle(name.to_string(), args, self.agent.clone())
                .await;
        }

        Err(McpError::ToolNotFound(name.to_string()))
    }

    /// Handle resources/list
    async fn handle_resources_list(&self) -> Result<serde_json::Value> {
        let mut resources_list = Vec::new();

        // Add dynamic status resource
        resources_list.push(serde_json::json!({
            "uri": format!("ghost://{}/status", self.identity.name),
            "name": "Server Status",
            "description": "Current server and agent status",
            "mimeType": "application/json"
        }));

        // Add registered resources
        let registry = self.resources.read().await;
        for resource in registry.iter() {
            // Check if we already added a resource with this URI (e.g. ghost://status)
            // If so, we might want to skip or merge?
            // For now, let's just add them.
            // Note: ghost://status in resources.json might conflict if we want to handle it specifically.
            resources_list.push(serde_json::to_value(resource)?);
        }

        Ok(serde_json::json!({
            "resources": resources_list
        }))
    }

    /// Handle resources/read
    async fn handle_resources_read(&self, params: &serde_json::Value) -> Result<serde_json::Value> {
        let uri = params
            .get("uri")
            .and_then(|u| u.as_str())
            .ok_or_else(|| McpError::InvalidParams("Missing 'uri' parameter".to_string()))?;

        if uri.ends_with("/status") || uri == "ghost://status" {
            let registry = self.registry.read().await;
            let status = serde_json::json!({
                "server": self.identity.name,
                "version": crate::VERSION,
                "tool_count": registry.len(),
                "agent_connected": self.agent.is_connected(),
                "agent_status": self.agent.status().await
            });

            Ok(serde_json::json!({
                "contents": [{
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": serde_json::to_string_pretty(&status)?
                }]
            }))
        } else {
            Err(McpError::InvalidParams(format!(
                "Unknown resource: {}",
                uri
            )))
        }
    }

    /// Handle prompts/list
    async fn handle_prompts_list(&self) -> Result<serde_json::Value> {
        let registry = self.prompts.read().await;
        let prompts: Vec<_> = registry.values().collect();
        Ok(serde_json::json!({ "prompts": prompts }))
    }

    /// Handle prompts/get
    async fn handle_prompts_get(&self, params: &serde_json::Value) -> Result<serde_json::Value> {
        let name = params
            .get("name")
            .and_then(|n| n.as_str())
            .ok_or_else(|| McpError::InvalidParams("Missing 'name' parameter".to_string()))?;

        // Check static registry first
        let registry = self.prompts.read().await;
        if let Some(prompt) = registry.get(name) {
            return Ok(serde_json::json!({
                "description": prompt.description,
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": format!("Execute prompt: {}", prompt.name)
                        }
                    }
                ]
            }));
        }

        // Try custom handler
        if let Some(ref handler) = self.prompt_handler {
            // Pass the whole params object as args, or just arguments?
            // MCP spec says params has "arguments" field.
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::json!({}));
            return handler.handle(name.to_string(), args).await;
        }

        Err(McpError::InvalidParams(format!("Unknown prompt: {}", name)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_enum() {
        let stdio = Transport::Stdio;
        let tcp = Transport::Tcp(8080);
        assert_eq!(stdio, Transport::Stdio);
        assert_eq!(tcp, Transport::Tcp(8080));
    }

    #[test]
    fn test_transport_clone() {
        let transport = Transport::Tcp(9999);
        let cloned = transport;
        assert_eq!(cloned, Transport::Tcp(9999));
    }

    #[tokio::test]
    async fn test_server_creation() {
        let server = McpServer::core();
        assert_eq!(server.identity().name, "ghost-core-mcp");

        let registry: tokio::sync::RwLockReadGuard<ToolRegistry> = server.registry_read().await;
        assert!(registry.get("mcp_capabilities").is_some());
    }

    #[tokio::test]
    async fn test_server_analysis_creation() {
        let server = McpServer::analysis();
        assert_eq!(server.identity().name, "ghost-analysis-mcp");
        assert_eq!(server.identity().port, 13341);
    }

    #[tokio::test]
    async fn test_server_static_creation() {
        let server = McpServer::static_analysis();
        assert_eq!(server.identity().name, "ghost-static-mcp");
        assert!(!server.identity().requires_agent);
    }

    #[tokio::test]
    async fn test_server_extended_creation() {
        let server = McpServer::extended();
        assert_eq!(server.identity().name, "ghost-extended-mcp");
        assert_eq!(server.identity().port, 13343);
    }

    #[tokio::test]
    async fn test_handle_initialize() {
        let server = McpServer::core();
        let result = server
            .handle_initialize(&serde_json::json!({}))
            .await
            .unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert_eq!(result["serverInfo"]["name"], "ghost-core-mcp");
        assert!(result.get("capabilities").is_some());
    }

    #[tokio::test]
    async fn test_handle_tools_list() {
        let server = McpServer::core();
        let result = server.handle_tools_list().await.unwrap();
        assert!(result.get("tools").is_some());
        let tools = result["tools"].as_array().unwrap();
        assert!(!tools.is_empty());
    }

    #[tokio::test]
    async fn test_handle_resources_list() {
        let server = McpServer::core();
        let result = server.handle_resources_list().await.unwrap();
        assert!(result.get("resources").is_some());
    }

    #[tokio::test]
    async fn test_handle_prompts_list() {
        let server = McpServer::core();
        let result = server.handle_prompts_list().await.unwrap();
        assert!(result.get("prompts").is_some());
    }

    #[tokio::test]
    async fn test_handle_tools_call_meta_capabilities() {
        let server = McpServer::core();
        let params = serde_json::json!({
            "name": "mcp_capabilities",
            "arguments": {}
        });
        let result = server.handle_tools_call(&params).await.unwrap();
        assert!(result.get("content").is_some());
    }

    #[tokio::test]
    async fn test_handle_tools_call_meta_version() {
        let server = McpServer::core();
        let params = serde_json::json!({
            "name": "mcp_version",
            "arguments": {}
        });
        let result = server.handle_tools_call(&params).await.unwrap();
        assert!(result.get("content").is_some());
    }

    #[tokio::test]
    async fn test_handle_tools_call_meta_documentation() {
        let server = McpServer::core();
        let params = serde_json::json!({
            "name": "mcp_documentation",
            "arguments": {"tool": "mcp_capabilities"}
        });
        let result = server.handle_tools_call(&params).await.unwrap();
        assert!(result.get("content").is_some());
    }

    #[tokio::test]
    async fn test_handle_tools_call_unknown_tool() {
        let server = McpServer::core();
        let params = serde_json::json!({
            "name": "nonexistent_tool",
            "arguments": {}
        });
        let result = server.handle_tools_call(&params).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_tools_call_missing_name() {
        let server = McpServer::core();
        let params = serde_json::json!({
            "arguments": {}
        });
        let result = server.handle_tools_call(&params).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_request_parse_error() {
        let server = McpServer::core();
        let response = server.handle_request("invalid json").await;
        assert!(response.get("error").is_some());
        assert_eq!(response["error"]["code"], -32700);
    }

    #[tokio::test]
    async fn test_handle_request_too_large() {
        let server = McpServer::core();
        let large_request = "x".repeat(2 * 1024 * 1024);
        let response = server.handle_request(&large_request).await;
        assert!(response.get("error").is_some());
        assert_eq!(response["error"]["code"], -32600);
    }

    #[tokio::test]
    async fn test_handle_request_valid_initialize() {
        let server = McpServer::core();
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        let response = server.handle_request(&request.to_string()).await;
        assert!(response.get("result").is_some());
        assert_eq!(response["id"], 1);
    }

    #[tokio::test]
    async fn test_handle_request_notification() {
        let server = McpServer::core();
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        });
        let response = server.handle_request(&request.to_string()).await;
        assert!(response.is_null());
    }

    #[tokio::test]
    async fn test_handle_request_unknown_method() {
        let server = McpServer::core();
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "unknown/method",
            "params": {}
        });
        let response = server.handle_request(&request.to_string()).await;
        assert!(response.get("error").is_some());
    }

    #[tokio::test]
    async fn test_handle_resources_read_status() {
        let server = McpServer::core();
        let params = serde_json::json!({
            "uri": "ghost://ghost-core-mcp/status"
        });
        let result = server.handle_resources_read(&params).await.unwrap();
        assert!(result.get("contents").is_some());
    }

    #[tokio::test]
    async fn test_handle_resources_read_unknown() {
        let server = McpServer::core();
        let params = serde_json::json!({
            "uri": "ghost://unknown/resource"
        });
        let result = server.handle_resources_read(&params).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_prompts_get_unknown() {
        let server = McpServer::core();
        let params = serde_json::json!({
            "name": "unknown_prompt"
        });
        let result = server.handle_prompts_get(&params).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_json_rpc_request_validation_empty_method() {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(1)),
            method: "".to_string(),
            params: serde_json::json!({}),
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn test_json_rpc_request_validation_long_method() {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(1)),
            method: "x".repeat(300),
            params: serde_json::json!({}),
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn test_json_rpc_request_validation_valid() {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(1)),
            method: "tools/list".to_string(),
            params: serde_json::json!({}),
        };
        assert!(request.validate().is_ok());
    }

    #[tokio::test]
    async fn test_agent_not_connected() {
        let server = McpServer::core();
        assert!(!server.agent().is_connected());
    }

    #[tokio::test]
    async fn test_registry_has_meta_tools() {
        let server = McpServer::core();
        let registry: tokio::sync::RwLockReadGuard<ToolRegistry> = server.registry_read().await;

        assert!(registry.get("mcp_capabilities").is_some());
        assert!(registry.get("mcp_documentation").is_some());
        assert!(registry.get("mcp_version").is_some());
        assert!(registry.get("mcp_health").is_some());
        assert_eq!(registry.len(), 4);
    }
}
