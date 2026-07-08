//! trace-core: local-first iOS sysdiagnose spyware-trace scanner.
//!
//! Compiled to WebAssembly and driven from the browser. The archive is
//! streamed in chunks and never leaves the machine; only STIX2 indicator
//! bundles are (optionally) fetched from public sources by the JS host.

// The engine and its result types are public so native tooling (the
// examples/scan.rs harness, property tests, future fuzz targets) can drive
// the exact pipeline the WASM Scanner wraps. The parsers stay private.
pub mod engine;
pub mod ioc;
pub mod report;
pub mod tar_stream;

mod crash_log;
mod heuristics;
mod ps;
mod shutdown_log;
mod unified_log;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Scanner {
    inner: Option<engine::Engine>,
}

#[wasm_bindgen]
impl Scanner {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Scanner {
        console_error_panic_hook::set_once();
        Scanner {
            inner: Some(engine::Engine::new()),
        }
    }

    /// Load a STIX2 bundle (JSON text). Returns per-set stats as JSON.
    pub fn load_stix(&mut self, set_name: &str, stix_json: &str) -> Result<String, JsError> {
        let engine = self
            .inner
            .as_mut()
            .ok_or_else(|| JsError::new("scanner already finished"))?;
        let stats = engine
            .load_stix(set_name, stix_json)
            .map_err(|m| JsError::new(&m))?;
        serde_json::to_string(&stats).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Stream the next chunk of the sysdiagnose archive (.tar.gz or .tar).
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), JsError> {
        let engine = self
            .inner
            .as_mut()
            .ok_or_else(|| JsError::new("scanner already finished"))?;
        engine.push(chunk).map_err(|m| JsError::new(&m))
    }

    /// Finalize the scan and return the full report as JSON.
    pub fn finish(&mut self) -> Result<String, JsError> {
        let engine = self
            .inner
            .take()
            .ok_or_else(|| JsError::new("scanner already finished"))?;
        let report = engine.finish().map_err(|m| JsError::new(&m))?;
        serde_json::to_string(&report).map_err(|e| JsError::new(&e.to_string()))
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Scanner::new()
    }
}
