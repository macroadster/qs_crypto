//! External Trin process backend.
//!
//! Wall-clock of the `trin run` process is the observer meter (outside the math).
//! SpinSample is derived on the host from secret + program + stdout (S3/S4).

use crate::{
    absorb_lp, EvolutionSpec, Result, SpinBackend, SpinBackendError, SpinSample,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Invoke `trin run <program>` with a seed on stdin; sample from host SHAKE.
pub struct TrinBackend {
    trin_bin: PathBuf,
    program: PathBuf,
    prepared: bool,
    evolved: bool,
    secret: Vec<u8>,
    program_hash: [u8; 32],
    stdout: Option<Vec<u8>>,
}

impl TrinBackend {
    pub fn new(trin_bin: impl Into<PathBuf>, program: impl Into<PathBuf>) -> Self {
        Self {
            trin_bin: trin_bin.into(),
            program: program.into(),
            prepared: false,
            evolved: false,
            secret: Vec::new(),
            program_hash: [0u8; 32],
            stdout: None,
        }
    }

    /// Resolve trin binary + shipped `trin/spin_sample.trin` if present.
    ///
    /// Search order for binary:
    /// 1. `TRIN` env (absolute path to the executable)
    /// 2. `trin` on `$PATH` (recommended: `~/.local/bin/trin`)
    pub fn discover() -> Result<Self> {
        let trin = discover_trin_bin().ok_or(SpinBackendError::Backend(
            "trin not found on PATH (install to ~/.local/bin/trin or set TRIN=)",
        ))?;
        let program = discover_program().ok_or(SpinBackendError::Backend(
            "spin_sample.trin not found next to crate",
        ))?;
        Ok(Self::new(trin, program))
    }

    pub fn trin_bin(&self) -> &Path {
        &self.trin_bin
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Whether the binary exists and is executable-looking.
    pub fn available(&self) -> bool {
        self.trin_bin.is_file() && self.program.is_file()
    }
}

impl SpinBackend for TrinBackend {
    fn backend_id(&self) -> &str {
        "trin-v1"
    }

    fn prepare(&mut self, spec: &EvolutionSpec, secret: &[u8]) -> Result<()> {
        if !self.trin_bin.is_file() {
            return Err(SpinBackendError::Backend("trin binary missing"));
        }
        if !self.program.is_file() {
            return Err(SpinBackendError::Backend("trin program missing"));
        }
        self.secret = secret.to_vec();
        self.program_hash = spec.program_hash;
        self.prepared = true;
        self.evolved = false;
        self.stdout = None;
        Ok(())
    }

    fn evolve(&mut self) -> Result<()> {
        if !self.prepared {
            return Err(SpinBackendError::NotPrepared);
        }
        // Content-dependent seed line (hex of SHAKE(secret)[0..16]).
        let seed_line = seed_hex_line(&self.secret);

        let mut child = Command::new(&self.trin_bin)
            .arg("run")
            .arg(&self.program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| SpinBackendError::Backend("failed to spawn trin"))?;

        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or(SpinBackendError::Backend("trin stdin unavailable"))?;
            stdin
                .write_all(seed_line.as_bytes())
                .map_err(|_| SpinBackendError::Backend("trin stdin write failed"))?;
            // newline so input() completes
            stdin
                .write_all(b"\n")
                .map_err(|_| SpinBackendError::Backend("trin stdin write failed"))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|_| SpinBackendError::Backend("trin wait failed"))?;

        if !output.status.success() {
            return Err(SpinBackendError::Backend("trin run failed"));
        }
        if output.stdout.is_empty() {
            return Err(SpinBackendError::Backend("trin produced empty stdout"));
        }
        self.stdout = Some(output.stdout);
        self.evolved = true;
        Ok(())
    }

    fn measure(&mut self) -> Result<SpinSample> {
        if !self.prepared || !self.evolved {
            return Err(SpinBackendError::NotPrepared);
        }
        let stdout = self
            .stdout
            .as_ref()
            .ok_or(SpinBackendError::NotPrepared)?;
        // Host-side sample: secret + program + stdout (never wall_ns).
        let mut h = Shake256::default();
        h.update(b"trin-sample-v1");
        absorb_lp(&mut h, &self.secret);
        absorb_lp(&mut h, &self.program_hash);
        absorb_lp(&mut h, stdout);
        let mut bytes = vec![0u8; 32];
        h.finalize_xof().read(&mut bytes);
        Ok(SpinSample { bytes })
    }
}

fn seed_hex_line(secret: &[u8]) -> String {
    let mut h = Shake256::default();
    h.update(b"trin-seed-line-v1");
    absorb_lp(&mut h, secret);
    let mut raw = [0u8; 16];
    h.finalize_xof().read(&mut raw);
    let mut s = String::with_capacity(32);
    for b in raw {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn discover_trin_bin() -> Option<PathBuf> {
    // Explicit override (CI, non-PATH installs).
    if let Ok(p) = std::env::var("TRIN") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    // Standard PATH lookup only — no machine-specific absolute paths in tree.
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let p = dir.join("trin");
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

fn discover_program() -> Option<PathBuf> {
    // CARGO_MANIFEST_DIR at compile time for tests/examples.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("trin/spin_sample.trin");
    if manifest.is_file() {
        return Some(manifest);
    }
    let cwd = PathBuf::from("trin/spin_sample.trin");
    if cwd.is_file() {
        return Some(cwd);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EvolutionMode, EvolutionSpec};

    fn trin_spec() -> EvolutionSpec {
        EvolutionSpec {
            backend_id: "trin-v1".into(),
            program_hash: [3u8; 32],
            schedule_id: "spin_sample.trin".into(),
            mode: EvolutionMode::DeterministicClassical,
        }
    }

    #[test]
    fn trin_determinism_if_available() {
        let mut backend = match TrinBackend::discover() {
            Ok(b) if b.available() => b,
            _ => {
                eprintln!("skip trin_determinism_if_available: trin not available");
                return;
            }
        };
        let spec = trin_spec();
        let secret = b"trin-test-secret";
        backend.prepare(&spec, secret).unwrap();
        backend.evolve().unwrap();
        let s1 = backend.measure().unwrap();

        let mut b2 = TrinBackend::new(backend.trin_bin(), backend.program());
        b2.prepare(&spec, secret).unwrap();
        b2.evolve().unwrap();
        let s2 = b2.measure().unwrap();
        assert_eq!(s1, s2);
        assert_eq!(s1.bytes.len(), 32);
    }

    #[test]
    fn trin_secret_sensitivity_if_available() {
        let mut a = match TrinBackend::discover() {
            Ok(b) if b.available() => b,
            _ => return,
        };
        let mut b = TrinBackend::new(a.trin_bin(), a.program());
        let spec = trin_spec();
        a.prepare(&spec, b"secret-a").unwrap();
        b.prepare(&spec, b"secret-b").unwrap();
        a.evolve().unwrap();
        b.evolve().unwrap();
        assert_ne!(a.measure().unwrap(), b.measure().unwrap());
    }
}
