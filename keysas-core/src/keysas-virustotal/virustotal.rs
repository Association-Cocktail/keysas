// SPDX-License-Identifier: GPL-3.0-only
/*
 * VirusTotal API v3 client for keysas-virustotal.
 *
 * Only SHA256 hash lookups are performed — files are never uploaded.
 * Results are cached in memory for 1 hour to avoid redundant API calls
 * and stay within the rate limit of the free tier (4 req/min).
 *
 * If VT is unreachable (no internet, timeout, rate limit), behaviour is
 * controlled by fail_open: true = let the file pass, false = block it.
 */

use std::collections::HashMap;
use std::time::{Duration, Instant};

struct CacheEntry {
    detections: u32,
    summary: String,
    inserted: Instant,
}

/// VirusTotal client — owned by the main processing loop, single-threaded.
pub struct VtClient {
    api_key: String,
    /// Base URL for the VT files API (without trailing slash).
    api_url: String,
    /// True = pass file if VT is unreachable. False = block.
    pub fail_open: bool,
    /// Number of malicious detections required to block the file.
    pub block_threshold: u32,
    /// HTTP timeout for VT API calls.
    timeout: Duration,
    /// How long a cache entry remains valid.
    cache_ttl: Duration,
    cache: HashMap<String, CacheEntry>,
}

impl VtClient {
    #[must_use]
    pub fn new(
        api_key: &str,
        api_url: &str,
        fail_open: bool,
        block_threshold: u32,
        timeout_ms: u64,
        cache_ttl_secs: u64,
    ) -> Self {
        Self {
            api_key: api_key.to_string(),
            api_url: api_url.to_string(),
            fail_open,
            block_threshold,
            timeout: Duration::from_millis(timeout_ms),
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            cache: HashMap::new(),
        }
    }

    /// Look up a SHA256 hash in VirusTotal.
    ///
    /// Returns `(pass, detections, summary)`:
    /// - `pass`       — true if the file may proceed
    /// - `detections` — number of engines reporting the file as malicious
    /// - `summary`    — human-readable result string for the .krp report
    #[must_use]
    pub fn lookup(&mut self, sha256: &str) -> (bool, u32, String) {
        let now = Instant::now();

        // Cache hit
        if let Some(entry) = self.cache.get(sha256) {
            if now.duration_since(entry.inserted) < self.cache_ttl {
                let pass = entry.detections < self.block_threshold;
                log::info!("VT cache hit {sha256}: {} detection(s)", entry.detections);
                return (pass, entry.detections, entry.summary.clone());
            }
            // Expired — remove before re-querying
            self.cache.remove(sha256);
        }

        // API call
        let url = format!("{}/{sha256}", self.api_url);
        let response = match ureq::get(&url)
            .timeout(self.timeout)
            .set("x-apikey", &self.api_key)
            .call()
        {
            Ok(r) => r,
            Err(ureq::Error::Status(404, _)) => {
                // File never seen by VT — not malicious, simply unknown
                log::info!("VT: {sha256} unknown (not in database)");
                let summary = "unknown to VirusTotal".to_string();
                self.insert_cache(sha256, 0, summary.clone(), now);
                return (true, 0, summary);
            }
            Err(ureq::Error::Status(429, _)) => {
                log::warn!("VT: API rate limit exceeded");
                return (self.fail_open, 0, "VT rate limit exceeded".to_string());
            }
            Err(e) => {
                log::warn!("VT: API error for {sha256}: {e}");
                return (
                    self.fail_open,
                    0,
                    format!("VT unreachable: {}", e),
                );
            }
        };

        let body: serde_json::Value = match serde_json::from_reader(response.into_reader()) {
            Ok(j) => j,
            Err(e) => {
                log::warn!("VT: JSON parse error: {e}");
                return (self.fail_open, 0, "VT response parse error".to_string());
            }
        };

        let stats = &body["data"]["attributes"]["last_analysis_stats"];
        let malicious = stats["malicious"].as_u64().unwrap_or(0) as u32;
        let suspicious = stats["suspicious"].as_u64().unwrap_or(0) as u32;
        let harmless = stats["harmless"].as_u64().unwrap_or(0) as u32;
        let undetected = stats["undetected"].as_u64().unwrap_or(0) as u32;
        let total = malicious + suspicious + harmless + undetected;

        let summary = if malicious > 0 {
            format!("{malicious} malicious, {suspicious} suspicious / {total} engines")
        } else if suspicious > 0 {
            format!("{suspicious} suspicious / {total} engines")
        } else {
            format!("clean ({total} engines)")
        };

        log::info!("VT result for {sha256}: {summary}");
        self.insert_cache(sha256, malicious, summary.clone(), now);

        let pass = malicious < self.block_threshold;
        (pass, malicious, summary)
    }

    fn insert_cache(&mut self, sha256: &str, detections: u32, summary: String, now: Instant) {
        self.cache.insert(
            sha256.to_string(),
            CacheEntry { detections, summary, inserted: now },
        );
    }
}
