// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2025 Stephane Neveu, Luc Bonnafoux
 *
 * Progress tracking module for KeySAS daemons
 */

use anyhow::Result;
use log;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

/// Progress status for file analysis
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AnalysisStep {
    /// File received and waiting to be processed
    Pending,
    /// Calculating SHA256 hash
    Hashing,
    /// Checking file size
    CheckingSize,
    /// Verifying file type with magic numbers
    CheckingFileType,
    /// Scanning with ClamAV antivirus
    AntivirusScan,
    /// Scanning with YARA rules
    YaraScan,
    /// Verifying digital signature
    VerifyingSignature,
    /// File analysis complete
    Complete,
    /// File analysis failed
    Failed(String),
}

/// Detailed file analysis status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileProgress {
    pub filename: String,
    pub step: AnalysisStep,
    pub step_description: String,
    pub percentage: u8,
    pub start_time: String,
    pub current_time: String,
}

impl FileProgress {
    pub fn new(filename: String) -> Self {
        let now = OffsetDateTime::now_utc();
        let time_str = format!(
            "{:02}-{:02}-{}_{:02}-{:02}-{:02}",
            now.day(),
            now.month(),
            now.year(),
            now.hour(),
            now.minute(),
            now.second()
        );

        Self {
            filename,
            step: AnalysisStep::Pending,
            step_description: "En attente de traitement".to_string(),
            percentage: 0,
            start_time: time_str.clone(),
            current_time: time_str,
        }
    }

    pub fn update_step(&mut self, step: AnalysisStep, percentage: u8) {
        self.step = step.clone();
        self.percentage = percentage;
        self.step_description = step.description();

        let now = OffsetDateTime::now_utc();
        self.current_time = format!(
            "{:02}-{:02}-{}_{:02}-{:02}-{:02}",
            now.day(),
            now.month(),
            now.year(),
            now.hour(),
            now.minute(),
            now.second()
        );
    }
}

impl AnalysisStep {
    pub fn description(&self) -> String {
        match self {
            AnalysisStep::Pending => "En attente de traitement".to_string(),
            AnalysisStep::Hashing => "Calcul du hash SHA256...".to_string(),
            AnalysisStep::CheckingSize => "Vérification de la taille...".to_string(),
            AnalysisStep::CheckingFileType => "Vérification du type de fichier...".to_string(),
            AnalysisStep::AntivirusScan => "Scan antivirus en cours...".to_string(),
            AnalysisStep::YaraScan => "Scan YARA en cours...".to_string(),
            AnalysisStep::VerifyingSignature => "Vérification de la signature...".to_string(),
            AnalysisStep::Complete => "Analyse terminée".to_string(),
            AnalysisStep::Failed(reason) => format!("Échec: {}", reason),
        }
    }

    pub fn percentage(&self) -> u8 {
        match self {
            AnalysisStep::Pending => 0,
            AnalysisStep::Hashing => 10,
            AnalysisStep::CheckingSize => 20,
            AnalysisStep::CheckingFileType => 30,
            AnalysisStep::AntivirusScan => 50,
            AnalysisStep::YaraScan => 75,
            AnalysisStep::VerifyingSignature => 90,
            AnalysisStep::Complete => 100,
            AnalysisStep::Failed(_) => 0,
        }
    }
}

/// Global progress tracker for a daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonProgress {
    pub daemon_name: String,
    pub total_files: usize,
    pub processed_files: usize,
    pub failed_files: usize,
    pub current_file: Option<FileProgress>,
    pub queue: Vec<String>,
    pub completed: Vec<String>,
    pub is_processing: bool,
}

impl DaemonProgress {
    pub fn new(daemon_name: String) -> Self {
        Self {
            daemon_name,
            total_files: 0,
            processed_files: 0,
            failed_files: 0,
            current_file: None,
            queue: Vec::new(),
            completed: Vec::new(),
            is_processing: false,
        }
    }

    pub fn update_progress_file(&self, path: &PathBuf) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    pub fn add_files_to_queue(&mut self, files: Vec<String>) {
        self.queue.extend(files);
        self.total_files = self.queue.len() + self.processed_files + self.failed_files;
    }

    pub fn start_next_file(&mut self, filename: String) {
        self.current_file = Some(FileProgress::new(filename.clone()));
        self.queue.retain(|f| f != &filename);
        self.is_processing = true;
    }

    pub fn update_current_step(&mut self, step: AnalysisStep) {
        if let Some(ref mut current) = self.current_file {
            let percentage = step.percentage();
            current.update_step(step, percentage);
        }
    }

    pub fn complete_current_file(&mut self, success: bool) {
        if let Some(current) = self.current_file.take() {
            if success {
                self.processed_files += 1;
                self.completed.push(current.filename);
            } else {
                self.failed_files += 1;
            }

            if self.queue.is_empty() {
                self.is_processing = false;
            }
        }
    }

    pub fn get_overall_percentage(&self) -> u8 {
        if self.total_files == 0 {
            return 0;
        }
        let completed = self.processed_files + self.failed_files;
        ((completed * 100) / self.total_files) as u8
    }
}

/// Thread-safe progress tracker
pub struct ProgressTracker {
    progress: Arc<Mutex<DaemonProgress>>,
    progress_file: PathBuf,
}

impl ProgressTracker {
    pub fn new(daemon_name: String, progress_file: PathBuf) -> Self {
        Self {
            progress: Arc::new(Mutex::new(DaemonProgress::new(daemon_name))),
            progress_file,
        }
    }

    pub fn add_files_to_queue(&self, files: Vec<String>) {
        let mut progress = self.progress.lock().unwrap();
        progress.add_files_to_queue(files);
        if let Err(e) = progress.update_progress_file(&self.progress_file) {
            log::warn!("Failed to write progress file: {}", e);
        }
    }

    pub fn start_file(&self, filename: String) {
        let mut progress = self.progress.lock().unwrap();
        progress.start_next_file(filename);
        if let Err(e) = progress.update_progress_file(&self.progress_file) {
            log::warn!("Failed to write progress file: {}", e);
        }
    }

    pub fn update_step(&self, step: AnalysisStep) {
        let mut progress = self.progress.lock().unwrap();
        progress.update_current_step(step);
        if let Err(e) = progress.update_progress_file(&self.progress_file) {
            log::warn!("Failed to write progress file: {}", e);
        }
    }

    pub fn complete_file(&self, success: bool) {
        let mut progress = self.progress.lock().unwrap();
        progress.complete_current_file(success);
        if let Err(e) = progress.update_progress_file(&self.progress_file) {
            log::warn!("Failed to write progress file: {}", e);
        }
    }

    pub fn get_progress(&self) -> DaemonProgress {
        let progress = self.progress.lock().unwrap();
        progress.clone()
    }
}
