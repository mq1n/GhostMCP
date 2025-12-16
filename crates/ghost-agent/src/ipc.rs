//! Legacy single-client IPC server for agent
//!
//! **DEPRECATED**: This module is superseded by `multi_client` module which supports
//! multiple concurrent client connections with event bus and shared state.
//!
//! Kept for reference and potential fallback scenarios.

#![allow(dead_code)]

use ghost_common::ipc::{Request, Response, MAX_MESSAGE_SIZE};
use ghost_common::{debug, error, info, warn, Error, Result};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

/// Default port for ghost-agent IPC
pub const AGENT_PORT: u16 = 13338;

/// IPC server using TCP socket
pub struct IpcServer {
    stream: TcpStream,
}

impl IpcServer {
    /// Create a TCP server and wait for host connection
    pub fn create_and_wait() -> Result<Self> {
        let addr = format!("127.0.0.1:{}", AGENT_PORT);

        info!(target: "ghost_agent::ipc", port = AGENT_PORT, "Starting IPC server");

        let listener = match TcpListener::bind(&addr) {
            Ok(l) => {
                info!(target: "ghost_agent::ipc", address = %addr, "IPC server bound successfully");
                l
            }
            Err(e) => {
                error!(target: "ghost_agent::ipc", error = %e, address = %addr, "Failed to bind IPC server");
                return Err(Error::Ipc(format!("Failed to bind: {}", e)));
            }
        };

        info!(target: "ghost_agent::ipc", "Waiting for host connection...");

        let (stream, peer) = match listener.accept() {
            Ok(conn) => {
                info!(target: "ghost_agent::ipc", peer = %conn.1, "Host connected");
                conn
            }
            Err(e) => {
                error!(target: "ghost_agent::ipc", error = %e, "Accept failed");
                return Err(Error::Ipc(format!("Accept failed: {}", e)));
            }
        };

        // Set TCP_NODELAY for low latency
        if let Err(e) = stream.set_nodelay(true) {
            warn!(target: "ghost_agent::ipc", error = %e, "Failed to set TCP_NODELAY");
        }

        debug!(target: "ghost_agent::ipc", peer = %peer, "IPC connection established");

        Ok(Self { stream })
    }

    /// Receive a request from the host
    pub fn receive_request(&mut self) -> Result<Request> {
        // Read length prefix (4 bytes)
        let mut len_buf = [0u8; 4];
        if let Err(e) = self.stream.read_exact(&mut len_buf) {
            debug!(target: "ghost_agent::ipc", error = %e, "Failed to read length prefix");
            return Err(Error::Ipc(format!("Failed to read length: {}", e)));
        }

        let len = u32::from_le_bytes(len_buf) as usize;
        if len > MAX_MESSAGE_SIZE {
            error!(target: "ghost_agent::ipc", size = len, max = MAX_MESSAGE_SIZE, "Message too large");
            return Err(Error::Ipc(format!("Message too large: {}", len)));
        }

        // Read body
        let mut body = vec![0u8; len];
        if let Err(e) = self.stream.read_exact(&mut body) {
            error!(target: "ghost_agent::ipc", error = %e, size = len, "Failed to read message body");
            return Err(Error::Ipc(format!("Failed to read body: {}", e)));
        }

        match serde_json::from_slice::<Request>(&body) {
            Ok(req) => {
                debug!(target: "ghost_agent::ipc", method = %req.method, id = req.id, "Received request");
                Ok(req)
            }
            Err(e) => {
                error!(target: "ghost_agent::ipc", error = %e, "Invalid JSON in request");
                Err(Error::Ipc(format!("Invalid JSON: {}", e)))
            }
        }
    }

    /// Send a response to the host
    pub fn send_response(&mut self, response: &Response) -> Result<()> {
        let body = match serde_json::to_vec(response) {
            Ok(b) => b,
            Err(e) => {
                error!(target: "ghost_agent::ipc", error = %e, "Failed to serialize response");
                return Err(Error::Ipc(format!("Serialization failed: {}", e)));
            }
        };

        if body.len() > MAX_MESSAGE_SIZE {
            error!(target: "ghost_agent::ipc", size = body.len(), max = MAX_MESSAGE_SIZE, "Response too large");
            return Err(Error::Ipc("Response too large".into()));
        }

        // Write length prefix
        let len = (body.len() as u32).to_le_bytes();
        if let Err(e) = self.stream.write_all(&len) {
            error!(target: "ghost_agent::ipc", error = %e, "Failed to write length prefix");
            return Err(Error::Ipc(format!("Failed to write length: {}", e)));
        }

        // Write body
        if let Err(e) = self.stream.write_all(&body) {
            error!(target: "ghost_agent::ipc", error = %e, "Failed to write response body");
            return Err(Error::Ipc(format!("Failed to write body: {}", e)));
        }

        if let Err(e) = self.stream.flush() {
            error!(target: "ghost_agent::ipc", error = %e, "Failed to flush stream");
            return Err(Error::Ipc(format!("Failed to flush: {}", e)));
        }

        debug!(target: "ghost_agent::ipc", id = response.id, size = body.len(), "Sent response");

        Ok(())
    }
}
