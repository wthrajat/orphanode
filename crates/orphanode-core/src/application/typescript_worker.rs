use std::{
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    thread,
    time::Duration,
};

use serde_json::{Value, json};
use thiserror::Error;

use crate::limits::AnalysisLimits;

const PROTOCOL_NAME: &str = "orphanode.typescript-worker";
const PROTOCOL_VERSION: u32 = 1;
const WORKER_MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeScriptWorkerOptions {
    pub node_executable: PathBuf,
    pub worker_script: PathBuf,
    pub timeout: Duration,
    pub max_message_bytes: usize,
}

impl TypeScriptWorkerOptions {
    #[must_use]
    pub fn new(worker_script: impl Into<PathBuf>) -> Self {
        Self {
            node_executable: PathBuf::from("node"),
            worker_script: worker_script.into(),
            timeout: Duration::from_secs(5),
            max_message_bytes: WORKER_MAX_MESSAGE_BYTES,
        }
    }

    #[must_use]
    pub fn with_limits(mut self, limits: AnalysisLimits) -> Self {
        self.max_message_bytes = limits
            .max_protocol_message_bytes
            .min(WORKER_MAX_MESSAGE_BYTES);
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WorkerReply {
    pub id: u64,
    pub result: Value,
}

#[derive(Debug, Error)]
pub enum TypeScriptWorkerError {
    #[error("TypeScript deep worker timeout must be between 1 ms and 30 seconds")]
    InvalidTimeout,
    #[error("TypeScript deep worker message limit must be between 1 and 1048576 bytes")]
    InvalidMessageLimit,
    #[error("cannot start TypeScript deep worker `{path}`: {source}")]
    Spawn {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("TypeScript deep worker did not expose its stdin or stdout channel")]
    MissingChannel,
    #[error("cannot write a TypeScript deep worker request: {0}")]
    Write(#[source] io::Error),
    #[error("TypeScript deep worker request exceeds {limit} bytes")]
    RequestTooLarge { limit: usize },
    #[error("TypeScript deep worker response exceeds {limit} bytes")]
    ResponseTooLarge { limit: usize },
    #[error("TypeScript deep worker returned invalid JSON: {0}")]
    InvalidJson(#[source] serde_json::Error),
    #[error("TypeScript deep worker returned an invalid protocol response: {0}")]
    InvalidProtocol(String),
    #[error("TypeScript deep worker rejected the request with `{code}`: {message}")]
    Rejected { code: String, message: String },
    #[error("TypeScript deep worker exited before replying")]
    Exited,
    #[error("TypeScript deep worker exceeded its hard {timeout_ms} ms deadline and was terminated")]
    Timeout { timeout_ms: u128 },
}

pub struct TypeScriptWorkerHost {
    child: Child,
    stdin: ChildStdin,
    responses: Receiver<Result<Vec<u8>, ReaderFailure>>,
    next_id: u64,
    timeout: Duration,
    max_message_bytes: usize,
}

impl TypeScriptWorkerHost {
    /// Starts the explicit deep-mode worker. Starting the process alone does not
    /// authorize loading project-local TypeScript code.
    ///
    /// # Errors
    ///
    /// Returns an error when the timeout or message limit is invalid, the worker
    /// process cannot be started, or its standard I/O channels are unavailable.
    pub fn spawn(options: TypeScriptWorkerOptions) -> Result<Self, TypeScriptWorkerError> {
        if options.timeout.is_zero() || options.timeout > MAX_TIMEOUT {
            return Err(TypeScriptWorkerError::InvalidTimeout);
        }
        if options.max_message_bytes == 0 || options.max_message_bytes > WORKER_MAX_MESSAGE_BYTES {
            return Err(TypeScriptWorkerError::InvalidMessageLimit);
        }

        let mut child = Command::new(&options.node_executable)
            .arg(&options.worker_script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|source| TypeScriptWorkerError::Spawn {
                path: options.worker_script,
                source,
            })?;
        let stdin = child
            .stdin
            .take()
            .ok_or(TypeScriptWorkerError::MissingChannel)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(TypeScriptWorkerError::MissingChannel)?;
        let (sender, responses) = mpsc::channel();
        let max_message_bytes = options.max_message_bytes;
        thread::spawn(move || read_responses(stdout, max_message_bytes, &sender));

        Ok(Self {
            child,
            stdin,
            responses,
            next_id: 1,
            timeout: options.timeout,
            max_message_bytes,
        })
    }

    /// Requests the worker's supported protocol capabilities.
    ///
    /// # Errors
    ///
    /// Returns a protocol, I/O, timeout, size-limit, or worker rejection error.
    pub fn capabilities(&mut self) -> Result<WorkerReply, TypeScriptWorkerError> {
        self.request("capabilities", json!({}))
    }

    /// Initializes against the controlling workspace's TypeScript package.
    ///
    /// # Errors
    ///
    /// Returns a protocol, I/O, timeout, or worker rejection error.
    pub fn initialize(
        &mut self,
        workspace_root: &Path,
        tsconfig_path: &Path,
        allow_project_typescript: bool,
    ) -> Result<WorkerReply, TypeScriptWorkerError> {
        self.initialize_from(
            workspace_root,
            workspace_root,
            tsconfig_path,
            allow_project_typescript,
        )
    }

    /// Initializes the worker while resolving `typescript` from the package
    /// that owns the selected configuration. This preserves monorepo compiler
    /// version boundaries without allowing the worker to read outside the
    /// controlling workspace.
    ///
    /// # Errors
    ///
    /// Returns a protocol, I/O, timeout, or worker rejection error.
    pub fn initialize_from(
        &mut self,
        workspace_root: &Path,
        typescript_resolution_root: &Path,
        tsconfig_path: &Path,
        allow_project_typescript: bool,
    ) -> Result<WorkerReply, TypeScriptWorkerError> {
        self.request(
            "initialize",
            json!({
                "workspaceRoot": workspace_root,
                "typescriptResolutionRoot": typescript_resolution_root,
                "tsconfigPath": tsconfig_path,
                "allowProjectTypeScript": allow_project_typescript,
            }),
        )
    }

    /// Runs a batch of initialized TypeScript queries.
    ///
    /// # Errors
    ///
    /// Returns a protocol, I/O, timeout, size-limit, or worker rejection error.
    pub fn query(&mut self, queries: Vec<Value>) -> Result<WorkerReply, TypeScriptWorkerError> {
        let params = Value::Object(
            [("queries".to_owned(), Value::Array(queries))]
                .into_iter()
                .collect(),
        );
        self.request("query", params)
    }

    /// Sends a request using the worker protocol.
    ///
    /// # Errors
    ///
    /// Returns an error when request serialization or I/O fails, a message
    /// exceeds its size limit, the worker times out or exits, or the response is
    /// invalid or rejected.
    pub fn request(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<WorkerReply, TypeScriptWorkerError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let timeout_ms = u64::try_from(self.timeout.as_millis()).unwrap_or(30_000);
        let request = Value::Object(
            [
                ("protocol".to_owned(), Value::from(PROTOCOL_NAME)),
                ("protocolVersion".to_owned(), Value::from(PROTOCOL_VERSION)),
                ("id".to_owned(), Value::from(id)),
                ("method".to_owned(), Value::from(method)),
                ("params".to_owned(), params),
                ("timeoutMs".to_owned(), Value::from(timeout_ms)),
            ]
            .into_iter()
            .collect(),
        );
        let mut encoded =
            serde_json::to_vec(&request).map_err(TypeScriptWorkerError::InvalidJson)?;
        if encoded.len() > self.max_message_bytes {
            return Err(TypeScriptWorkerError::RequestTooLarge {
                limit: self.max_message_bytes,
            });
        }
        encoded.push(b'\n');
        self.stdin
            .write_all(&encoded)
            .and_then(|()| self.stdin.flush())
            .map_err(TypeScriptWorkerError::Write)?;

        let response = match self.responses.recv_timeout(self.timeout) {
            Ok(Ok(response)) => response,
            Ok(Err(ReaderFailure::TooLarge)) => {
                self.terminate();
                return Err(TypeScriptWorkerError::ResponseTooLarge {
                    limit: self.max_message_bytes,
                });
            }
            Ok(Err(ReaderFailure::Io)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.terminate();
                return Err(TypeScriptWorkerError::Exited);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.terminate();
                return Err(TypeScriptWorkerError::Timeout {
                    timeout_ms: self.timeout.as_millis(),
                });
            }
        };
        let value: Value =
            serde_json::from_slice(&response).map_err(TypeScriptWorkerError::InvalidJson)?;
        validate_response(&value, id)
    }

    fn terminate(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for TypeScriptWorkerHost {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[derive(Debug)]
enum ReaderFailure {
    TooLarge,
    Io,
}

fn read_responses(
    mut stdout: impl Read,
    max_message_bytes: usize,
    sender: &mpsc::Sender<Result<Vec<u8>, ReaderFailure>>,
) {
    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match stdout.read(&mut byte) {
            Ok(0) if response.is_empty() => break,
            Ok(0) => {
                let _ = sender.send(Ok(response));
                break;
            }
            Ok(_) if byte[0] == b'\n' => {
                if response.last() == Some(&b'\r') {
                    response.pop();
                }
                if sender.send(Ok(std::mem::take(&mut response))).is_err() {
                    break;
                }
            }
            Ok(_) if response.len() == max_message_bytes => {
                let _ = sender.send(Err(ReaderFailure::TooLarge));
                break;
            }
            Ok(_) => {
                response.push(byte[0]);
            }
            Err(_) => {
                let _ = sender.send(Err(ReaderFailure::Io));
                break;
            }
        }
    }
}

fn validate_response(
    value: &Value,
    expected_id: u64,
) -> Result<WorkerReply, TypeScriptWorkerError> {
    if value.get("protocol").and_then(Value::as_str) != Some(PROTOCOL_NAME)
        || value.get("protocolVersion").and_then(Value::as_u64) != Some(u64::from(PROTOCOL_VERSION))
        || value.get("id").and_then(Value::as_u64) != Some(expected_id)
    {
        return Err(TypeScriptWorkerError::InvalidProtocol(
            "protocol, version, or request id did not match".to_owned(),
        ));
    }
    if let Some(error) = value.get("error") {
        return Err(TypeScriptWorkerError::Rejected {
            code: error
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("unknown_error")
                .to_owned(),
            message: error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("worker rejected the request")
                .to_owned(),
        });
    }
    let result = value
        .get("result")
        .cloned()
        .ok_or_else(|| TypeScriptWorkerError::InvalidProtocol("missing result".to_owned()))?;
    Ok(WorkerReply {
        id: expected_id,
        result,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{PROTOCOL_NAME, PROTOCOL_VERSION, TypeScriptWorkerError, validate_response};

    #[test]
    fn protocol_validation_rejects_a_mismatched_id() {
        let error = validate_response(
            &json!({
                "protocol": PROTOCOL_NAME,
                "protocolVersion": PROTOCOL_VERSION,
                "id": 2,
                "result": {},
            }),
            1,
        )
        .expect_err("reject mismatched response");

        assert!(matches!(error, TypeScriptWorkerError::InvalidProtocol(_)));
    }

    #[test]
    fn protocol_validation_surfaces_worker_errors_without_source_text() {
        let error = validate_response(
            &json!({
                "protocol": PROTOCOL_NAME,
                "protocolVersion": PROTOCOL_VERSION,
                "id": 1,
                "error": { "code": "typescript_unavailable", "message": "not available" },
            }),
            1,
        )
        .expect_err("surface worker error");

        assert!(matches!(
            error,
            TypeScriptWorkerError::Rejected { code, .. } if code == "typescript_unavailable"
        ));
    }
}
