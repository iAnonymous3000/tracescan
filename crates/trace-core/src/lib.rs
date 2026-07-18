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
        #[cfg(debug_assertions)]
        console_error_panic_hook::set_once();
        #[cfg_attr(not(target_arch = "wasm32"), allow(unused_mut))]
        let mut inner = engine::Engine::new();
        // The engine measures scan duration itself (the expensive work is
        // inside finish, past any reading a JS producer could take); it
        // just needs a clock, which wasm32 does not have natively.
        #[cfg(target_arch = "wasm32")]
        inner.set_clock(Box::new(js_sys::Date::now));
        Scanner { inner: Some(inner) }
    }

    /// Load a STIX2 bundle (JSON text). Returns per-set stats as JSON.
    pub fn load_stix(&mut self, set_name: &str, stix_json: &str) -> Result<String, JsError> {
        self.load_stix_with_meta(set_name, stix_json, "{}")
    }

    /// Load a STIX2 bundle with catalog metadata (JSON: date, url, source,
    /// loaded_from, upstream) recorded as provenance in the report. The
    /// set's hash is computed here from the text, never taken from meta.
    pub fn load_stix_with_meta(
        &mut self,
        set_name: &str,
        stix_json: &str,
        meta_json: &str,
    ) -> Result<String, JsError> {
        let engine = self
            .inner
            .as_mut()
            .ok_or_else(|| JsError::new("scanner already finished"))?;
        let meta: engine::SetMeta =
            serde_json::from_str(meta_json).map_err(|e| JsError::new(&e.to_string()))?;
        let stats = engine
            .load_stix_with_meta(set_name, stix_json, meta)
            .map_err(|m| JsError::new(&m))?;
        serde_json::to_string(&stats).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Record scan-level metadata (JSON: source_name, source_size,
    /// scanned_via, generated_at, duration_ms) for the report envelope.
    /// Descriptive only; nothing here can influence the verdict.
    pub fn set_scan_meta(&mut self, meta_json: &str) -> Result<(), JsError> {
        let engine = self
            .inner
            .as_mut()
            .ok_or_else(|| JsError::new("scanner already finished"))?;
        let meta: engine::ScanMeta =
            serde_json::from_str(meta_json).map_err(|e| JsError::new(&e.to_string()))?;
        engine.set_scan_meta(meta);
        Ok(())
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
        #[cfg_attr(not(target_arch = "wasm32"), allow(unused_mut))]
        let mut engine = self
            .inner
            .take()
            .ok_or_else(|| JsError::new("scanner already finished"))?;
        // Stamped when finalization begins: the closest observable moment
        // to "when the report was generated".
        #[cfg(target_arch = "wasm32")]
        if let Some(iso) = js_sys::Date::new_0().to_iso_string().as_string() {
            engine.set_generated_at(iso);
        }
        let report = engine.finish().map_err(|m| JsError::new(&m))?;
        serde_json::to_string(&report).map_err(|e| JsError::new(&e.to_string()))
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Scanner::new()
    }
}
