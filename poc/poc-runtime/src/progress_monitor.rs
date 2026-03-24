//! Curated terminal narrative built from per-process runtime progress logs.
//!
//! # Why this exists
//! The raw `progress.log` artifacts are useful for postmortem inspection, but operators watching
//! the PoC live need a readable narrative that shows how the protocol is moving in real time.
//!
//! # Role in the system
//! [`NarrativeProgressMonitor`] tails the child-process progress logs that `boomerang-runtime`
//! already writes, deduplicates repeated events, and emits an operator-facing supervisor view.

use std::{
    collections::BTreeSet,
    io::{self, IsTerminal},
    path::{Path, PathBuf},
};

use boomerang_runtime::RuntimeError;
use protocol_wire::control::TransportRole;
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncSeekExt, BufReader, SeekFrom},
};
use tracing::debug;

use crate::launcher::RunningChild;

/// Prints one curated narrative line for the operator-facing PoC supervisor.
pub(crate) fn print_narrative(phase: &str, message: &str) {
    println!(
        "{}",
        format_narrative_line(OutputStream::Stdout, phase, message)
    );
}

/// Prints the concise failure summary for one unexpectedly exited child.
pub(crate) fn print_failure_summary(child: &RunningChild, exit_code: Option<i32>) {
    let summary = super::launcher::format_failure_summary(
        child.role,
        &child.instance_id,
        exit_code,
        &child.node_log_path,
        &child.progress_log_path,
    );
    eprintln!(
        "{}",
        format_narrative_line(OutputStream::Stderr, "failure", &summary)
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColorMode {
    Enabled,
    Disabled,
}

fn format_narrative_line(stream: OutputStream, phase: &str, message: &str) -> String {
    format_narrative_line_with_mode(color_mode_for_stream(stream), phase, message)
}

fn format_narrative_line_with_mode(mode: ColorMode, phase: &str, message: &str) -> String {
    match mode {
        ColorMode::Disabled => format!("{phase}: {message}"),
        ColorMode::Enabled => {
            let message_style = message_style(phase, message);
            if message_style.is_empty() {
                format!("{}{phase}\u{1b}[0m: {message}", phase_style(phase))
            } else {
                format!(
                    "{}{phase}\u{1b}[0m: {message_style}{message}\u{1b}[0m",
                    phase_style(phase)
                )
            }
        }
    }
}

fn color_mode_for_stream(stream: OutputStream) -> ColorMode {
    if std::env::var_os("NO_COLOR").is_some() {
        return ColorMode::Disabled;
    }

    let terminal_supported = match stream {
        OutputStream::Stdout => io::stdout().is_terminal(),
        OutputStream::Stderr => io::stderr().is_terminal(),
    };
    if !terminal_supported {
        return ColorMode::Disabled;
    }

    if matches!(std::env::var("TERM"), Ok(term) if term.eq_ignore_ascii_case("dumb")) {
        return ColorMode::Disabled;
    }

    ColorMode::Enabled
}

fn phase_style(phase: &str) -> &'static str {
    match phase {
        "bootstrap" => "\u{1b}[1;36m",
        "identity" => "\u{1b}[1;35m",
        "cluster" => "\u{1b}[1;34m",
        "setup" => "\u{1b}[1;32m",
        "withdrawal" => "\u{1b}[1;33m",
        "done" => "\u{1b}[1;32m",
        "failure" => "\u{1b}[1;31m",
        "artifacts" => "\u{1b}[2;37m",
        "trace" => "\u{1b}[2;37m",
        _ => "\u{1b}[1;37m",
    }
}

fn message_style(phase: &str, message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();

    if phase == "failure" || lower.contains("failure:") {
        return "\u{1b}[1;31m";
    }

    if lower.contains("duress check") {
        return "\u{1b}[1;31m";
    }

    if lower.contains("approval") || lower.contains("approvals") {
        return "\u{1b}[1;35m";
    }

    if lower.contains("commitment-phase")
        || lower.contains("funding path")
        || lower.contains("locktime")
        || lower.contains("shared state")
        || lower.contains("request")
    {
        return "\u{1b}[1;33m";
    }

    if lower.contains("ping")
        || lower.contains("pong")
        || lower.contains("digging game round")
        || lower.contains("reached-pings")
    {
        return "\u{1b}[1;36m";
    }

    if lower.contains("signature")
        || lower.contains("signatures")
        || lower.contains("workflow complete")
        || lower.contains("completed withdrawal")
        || lower.contains("setup complete")
        || lower.contains(" ready")
    {
        return "\u{1b}[1;32m";
    }

    ""
}

/// Tails a set of progress logs and emits a curated terminal narrative.
#[derive(Debug)]
pub(crate) struct NarrativeProgressMonitor {
    watched_logs: Vec<WatchedProgressLog>,
    state: NarrativeState,
}

impl NarrativeProgressMonitor {
    /// Starts monitoring the current child set from the beginning of each progress log.
    pub(crate) fn from_children(children: &[RunningChild]) -> Self {
        let mut monitor = Self {
            watched_logs: Vec::with_capacity(children.len()),
            state: NarrativeState::default(),
        };
        monitor.add_children(children);
        monitor
    }

    /// Adds newly spawned children to the progress monitor.
    pub(crate) fn add_children(&mut self, children: &[RunningChild]) {
        for child in children {
            let identity = format!("{}:{}", child.role.as_str(), child.instance_id);
            if self.state.known_processes.insert(identity) {
                self.watched_logs.push(WatchedProgressLog {
                    progress_log_path: child.progress_log_path.clone(),
                    offset: 0,
                });

                match child.role {
                    TransportRole::Peer => {
                        self.state.expected_peers += 1;
                    }
                    TransportRole::Sar => {
                        self.state.expected_sars += 1;
                    }
                    _ => {}
                }
            }
        }
    }

    /// Returns the total number of processes the monitor currently tracks.
    pub(crate) fn expected_processes(&self) -> usize {
        self.state.known_processes.len()
    }

    /// Reads any new progress lines and emits the corresponding operator narrative.
    pub(crate) async fn poll(&mut self) -> Result<(), RuntimeError> {
        let mut events = Vec::new();

        for watched in &mut self.watched_logs {
            let (next_offset, mut new_events) =
                read_new_progress_events(&watched.progress_log_path, watched.offset).await?;
            watched.offset = next_offset;
            events.append(&mut new_events);
        }

        for event in events {
            for line in self.state.lines_for_event(&event) {
                print_narrative(line.phase(), line.message());
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
struct WatchedProgressLog {
    progress_log_path: PathBuf,
    offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProgressEvent {
    stage: String,
    role: String,
    instance_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WtPingPongStep {
    SarPingDispatch,
    SarPongCollected,
    PeerPongDispatch,
    PeerPingCollected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerPingPongStep {
    WtPongReceived,
    DuressCheckComplete,
    WtPingSent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NarrativeLine {
    phase: &'static str,
    message: String,
}

impl NarrativeLine {
    fn new(phase: &'static str, message: impl Into<String>) -> Self {
        Self {
            phase,
            message: message.into(),
        }
    }

    fn phase(&self) -> &'static str {
        self.phase
    }

    fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Default)]
struct NarrativeState {
    known_processes: BTreeSet<String>,
    seen_lines: BTreeSet<String>,
    seen_unknown_stages: BTreeSet<String>,
    seen_setup_banner: bool,
    seen_withdrawal_banner: bool,
    expected_peers: usize,
    expected_sars: usize,
    sar_setup_complete: usize,
    peer_setup_complete: usize,
    peer_withdrawal_complete: usize,
}

impl NarrativeState {
    fn lines_for_event(&mut self, event: &ProgressEvent) -> Vec<NarrativeLine> {
        let mut lines = Vec::new();

        match event.stage.as_str() {
            "process_start" | "runtime_built" | "runtime_start" => {}
            "identity_published" if event.role == "wt" => {
                self.push_once(
                    &mut lines,
                    "identity:wt",
                    NarrativeLine::new("identity", "WT published its public identity"),
                );
            }
            "identity_published" if event.role == "sar" => {
                let key = format!("identity:sar:{}", event.instance_id);
                if self.seen_lines.insert(key) {
                    self.sar_setup_complete += 1;
                    lines.push(NarrativeLine::new(
                        "identity",
                        format!(
                            "SAR public identities ready {}/{}",
                            self.sar_setup_complete, self.expected_sars
                        ),
                    ));
                }
            }
            "identity_published" => {}
            "links_established" => {
                self.push_once(
                    &mut lines,
                    "cluster:links_established",
                    NarrativeLine::new(
                        "cluster",
                        "transport links are coming online across the cluster",
                    ),
                );
            }
            "sar_setup_start"
            | "peer_setup_start"
            | "peer_setup_phone_sar_complete"
            | "peer_setup_out_of_band_complete" => {}
            "wt_setup_start" => {
                self.push_setup_banner(&mut lines);
                self.push_once(
                    &mut lines,
                    "setup:wt_start",
                    NarrativeLine::new(
                        "setup",
                        "WT started collecting peer identities and SAR assignments",
                    ),
                );
            }
            "wt_setup_peer_identities_collected" => {
                self.push_setup_banner(&mut lines);
                self.push_once(
                    &mut lines,
                    "setup:wt_peer_ids",
                    NarrativeLine::new("setup", "WT collected peer identities"),
                );
            }
            "wt_setup_sar_assignment_collected" => {
                self.push_setup_banner(&mut lines);
                self.push_once(
                    &mut lines,
                    "setup:wt_sar_assignments",
                    NarrativeLine::new("setup", "WT finalized SAR assignments"),
                );
            }
            "wt_setup_sar_registration_complete" => {
                self.push_setup_banner(&mut lines);
                self.push_once(
                    &mut lines,
                    "setup:wt_sar_registration",
                    NarrativeLine::new("setup", "WT finished SAR registration"),
                );
            }
            "wt_setup_complete" => {
                self.push_setup_banner(&mut lines);
                self.push_once(
                    &mut lines,
                    "setup:wt_complete",
                    NarrativeLine::new("setup", "WT setup complete"),
                );
            }
            "sar_setup_complete" => {
                self.push_setup_banner(&mut lines);
                let key = format!("setup:sar_complete:{}", event.instance_id);
                if self.seen_lines.insert(key) {
                    lines.push(NarrativeLine::new(
                        "setup",
                        format!(
                            "SAR setup complete {}/{}",
                            self.count_seen("setup:sar_complete:"),
                            self.expected_sars
                        ),
                    ));
                }
            }
            "peer_setup_complete" => {
                self.push_setup_banner(&mut lines);
                let key = format!("setup:peer_complete:{}", event.instance_id);
                if self.seen_lines.insert(key) {
                    self.peer_setup_complete += 1;
                    lines.push(NarrativeLine::new(
                        "setup",
                        format!(
                            "Peers ready {}/{}",
                            self.peer_setup_complete, self.expected_peers
                        ),
                    ));
                }
            }
            "peer_setup_iso_complete" => {
                self.push_setup_banner(&mut lines);
                self.push_once(
                    &mut lines,
                    "setup:peer_iso",
                    NarrativeLine::new(
                        "setup",
                        "peer setup has reached the ISO coordination stage",
                    ),
                );
            }
            stage
                if wt_ping_pong_round_step(stage).is_some()
                    || peer_ping_pong_round_step(stage).is_some() =>
            {
                self.push_withdrawal_banner(&mut lines);
                self.handle_withdrawal_event(&mut lines, event);
            }
            stage
                if stage.starts_with("peer_withdrawal_")
                    || stage.starts_with("wt_withdrawal_")
                    || stage.starts_with("sar_withdrawal_")
                    || stage == "peer_ping_pong_final_reached_pings_received" =>
            {
                self.push_withdrawal_banner(&mut lines);
                self.handle_withdrawal_event(&mut lines, event);
            }
            "process_complete" => {}
            _ => {
                if is_low_signal_stage(&event.stage) {
                    return lines;
                }
                if self.seen_unknown_stages.insert(event.stage.clone()) {
                    lines.push(NarrativeLine::new(
                        "trace",
                        format!(
                            "{}:{} reached {}",
                            event.role, event.instance_id, event.stage
                        ),
                    ));
                }
            }
        }

        lines
    }

    fn handle_withdrawal_event(&mut self, lines: &mut Vec<NarrativeLine>, event: &ProgressEvent) {
        match event.stage.as_str() {
            "peer_withdrawal_initiator_funding_start" => self.push_once(
                lines,
                "withdrawal:initiator_funding",
                NarrativeLine::new("withdrawal", "the initiator funding path has started"),
            ),
            "peer_withdrawal_shared_state_received" => self.push_once(
                lines,
                "withdrawal:shared_state",
                NarrativeLine::new(
                    "withdrawal",
                    "peers received the shared state needed to coordinate withdrawal",
                ),
            ),
            "peer_withdrawal_initiator_locktime_reached" => self.push_once(
                lines,
                "withdrawal:locktime_reached",
                NarrativeLine::new("withdrawal", "the initiator locktime has been reached"),
            ),
            "wt_withdrawal_initiator_request_received" => self.push_once(
                lines,
                "withdrawal:wt_request",
                NarrativeLine::new("withdrawal", "WT received the initiator withdrawal request"),
            ),
            "wt_withdrawal_initiator_sar_checks_complete" => self.push_once(
                lines,
                "withdrawal:wt_initiator_sar_checks",
                NarrativeLine::new(
                    "withdrawal",
                    "WT completed SAR checks for the initiator path",
                ),
            ),
            "wt_withdrawal_non_initiator_approvals_collected" => self.push_once(
                lines,
                "withdrawal:wt_non_initiator_approvals",
                NarrativeLine::new("withdrawal", "WT collected the non-initiator approvals"),
            ),
            "wt_withdrawal_all_sar_checks_complete" => self.push_once(
                lines,
                "withdrawal:wt_all_sar_checks",
                NarrativeLine::new("withdrawal", "WT completed all SAR checks"),
            ),
            "wt_withdrawal_ping_pong_start" => self.push_once(
                lines,
                "withdrawal:wt_ping_pong_start",
                NarrativeLine::new(
                    "withdrawal",
                    "WT entered the digging game confirmation exchange",
                ),
            ),
            "wt_withdrawal_ping_pong_complete" => self.push_once(
                lines,
                "withdrawal:ping_pong_complete",
                NarrativeLine::new(
                    "withdrawal",
                    "the digging game confirmation exchange completed",
                ),
            ),
            "wt_withdrawal_complete" => self.push_once(
                lines,
                "withdrawal:wt_complete",
                NarrativeLine::new("withdrawal", "WT withdrawal workflow complete"),
            ),
            "peer_withdrawal_ping_pong_start" => self.push_once(
                lines,
                "withdrawal:digging_game_start",
                NarrativeLine::new("withdrawal", "the digging game has started"),
            ),
            "peer_withdrawal_initiator_duress_check_complete" => self.push_once(
                lines,
                &format!(
                    "withdrawal:initiator_duress_check_complete:{}",
                    event.instance_id
                ),
                NarrativeLine::new(
                    "withdrawal",
                    format!(
                        "{} completed the commitment-phase duress check",
                        event.instance_id
                    ),
                ),
            ),
            "peer_withdrawal_non_initiator_duress_check_complete" => {
                let key = format!(
                    "withdrawal:non_initiator_duress_check_complete:{}",
                    event.instance_id
                );
                if self.seen_lines.insert(key) {
                    lines.push(NarrativeLine::new(
                        "withdrawal",
                        format!(
                            "{} completed the non-initiator approval-phase duress check ({}/{})",
                            event.instance_id,
                            self.count_seen("withdrawal:non_initiator_duress_check_complete:"),
                            self.expected_non_initiators()
                        ),
                    ));
                }
            }
            "peer_withdrawal_finish_signing_start" => self.push_once(
                lines,
                "withdrawal:digging_game_finish_signing",
                NarrativeLine::new(
                    "withdrawal",
                    "the digging game is complete; peers are finalizing signatures",
                ),
            ),
            "peer_withdrawal_start"
            | "peer_withdrawal_initiator_aggregation_start"
            | "peer_withdrawal_non_initiator_approval_start"
            | "peer_withdrawal_non_initiator_ack_start"
            | "peer_withdrawal_non_initiator_commit_start"
            | "sar_withdrawal_initiator_path"
            | "sar_withdrawal_non_initiator_path" => {}
            "peer_withdrawal_complete" => {
                let key = format!("withdrawal:peer_complete:{}", event.instance_id);
                if self.seen_lines.insert(key) {
                    self.peer_withdrawal_complete += 1;
                    lines.push(NarrativeLine::new(
                        "withdrawal",
                        format!(
                            "Peers completed withdrawal {}/{}",
                            self.peer_withdrawal_complete, self.expected_peers
                        ),
                    ));
                }
            }
            "peer_ping_pong_final_reached_pings_received" => {
                let key = format!("withdrawal:peer_final_release:{}", event.instance_id);
                if self.seen_lines.insert(key) {
                    lines.push(NarrativeLine::new(
                        "withdrawal",
                        format!(
                            "{} received the final reached-pings state ({}/{})",
                            event.instance_id,
                            self.count_seen("withdrawal:peer_final_release:"),
                            self.expected_peers
                        ),
                    ));
                }
            }
            stage => {
                if let Some((round, step)) = peer_ping_pong_round_step(stage) {
                    self.handle_peer_ping_pong_round_step(lines, event, round, step);
                    return;
                }
                if let Some((round, step)) = wt_ping_pong_round_step(stage) {
                    self.handle_wt_ping_pong_round_step(lines, round, step);
                    return;
                }
                if is_low_signal_stage(stage) {
                    return;
                }

                let key = format!("withdrawal:fallback:{}", event.stage);
                if self.seen_lines.insert(key) {
                    lines.push(NarrativeLine::new(
                        "withdrawal",
                        format!("observed {}", event.stage),
                    ));
                }
            }
        }
    }

    fn push_setup_banner(&mut self, lines: &mut Vec<NarrativeLine>) {
        if !self.seen_setup_banner {
            self.seen_setup_banner = true;
            lines.push(NarrativeLine::new(
                "setup",
                "protocol setup is now progressing across the cluster",
            ));
        }
    }

    fn push_withdrawal_banner(&mut self, lines: &mut Vec<NarrativeLine>) {
        if !self.seen_withdrawal_banner {
            self.seen_withdrawal_banner = true;
            lines.push(NarrativeLine::new(
                "withdrawal",
                "the coordinated withdrawal phase is underway",
            ));
        }
    }

    fn push_once(&mut self, lines: &mut Vec<NarrativeLine>, key: &str, line: NarrativeLine) {
        if self.seen_lines.insert(key.to_owned()) {
            lines.push(line);
        }
    }

    fn count_seen(&self, prefix: &str) -> usize {
        self.seen_lines
            .iter()
            .filter(|key| key.starts_with(prefix))
            .count()
    }

    fn handle_wt_ping_pong_round_step(
        &mut self,
        lines: &mut Vec<NarrativeLine>,
        round: usize,
        step: WtPingPongStep,
    ) {
        let (suffix, message) = match step {
            WtPingPongStep::SarPingDispatch => (
                "sar_ping_dispatch",
                format!("digging game round {round}: WT dispatched SAR pings"),
            ),
            WtPingPongStep::SarPongCollected => (
                "sar_pong_collected",
                format!("digging game round {round}: WT collected SAR pongs"),
            ),
            WtPingPongStep::PeerPongDispatch => (
                "peer_pong_dispatch",
                format!("digging game round {round}: WT dispatched peer pongs"),
            ),
            WtPingPongStep::PeerPingCollected => (
                "peer_ping_collected",
                format!("digging game round {round}: WT collected peer pings"),
            ),
        };

        self.push_once(
            lines,
            &format!("withdrawal:wt_ping_pong_round:{round}:{suffix}"),
            NarrativeLine::new("withdrawal", message),
        );
    }

    fn handle_peer_ping_pong_round_step(
        &mut self,
        lines: &mut Vec<NarrativeLine>,
        event: &ProgressEvent,
        round: usize,
        step: PeerPingPongStep,
    ) {
        let (prefix, verb) = match step {
            PeerPingPongStep::WtPongReceived => (
                format!("withdrawal:peer_round_wt_pong_received:{round}:"),
                "received the WT pong",
            ),
            PeerPingPongStep::DuressCheckComplete => (
                format!("withdrawal:peer_round_duress_check_complete:{round}:"),
                "completed the duress check",
            ),
            PeerPingPongStep::WtPingSent => (
                format!("withdrawal:peer_round_wt_ping_sent:{round}:"),
                "sent the WT ping",
            ),
        };
        let key = format!("{prefix}{}", event.instance_id);
        if self.seen_lines.insert(key) {
            lines.push(NarrativeLine::new(
                "withdrawal",
                format!(
                    "digging game round {round}: {} {} ({}/{})",
                    event.instance_id,
                    verb,
                    self.count_seen(&prefix),
                    self.expected_peers
                ),
            ));
        }
    }

    fn expected_non_initiators(&self) -> usize {
        self.expected_peers.saturating_sub(1)
    }
}

async fn read_new_progress_events(
    path: &Path,
    offset: u64,
) -> Result<(u64, Vec<ProgressEvent>), RuntimeError> {
    let metadata = match tokio::fs::metadata(path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((offset, Vec::new()));
        }
        Err(error) => return Err(error.into()),
    };

    let start_offset = if metadata.len() < offset { 0 } else { offset };
    let mut file = File::open(path).await?;
    file.seek(SeekFrom::Start(start_offset)).await?;
    let mut reader = BufReader::new(file);
    let mut events = Vec::new();
    let mut line = String::new();

    loop {
        line.clear();
        let read = reader.read_line(&mut line).await?;
        if read == 0 {
            break;
        }

        if let Some(event) = parse_progress_event(&line) {
            events.push(event);
        } else {
            debug!(
                path = %path.display(),
                raw_line = line.trim(),
                "ignored non-progress line in PoC narrative monitor",
            );
        }
    }

    Ok((reader.stream_position().await?, events))
}

fn parse_progress_event(line: &str) -> Option<ProgressEvent> {
    let mut stage = None;
    let mut role = None;
    let mut instance_id = None;

    for token in line.split_whitespace() {
        if let Some(value) = token.strip_prefix("stage=") {
            stage = Some(value.to_owned());
        } else if let Some(value) = token.strip_prefix("role=") {
            role = Some(value.to_owned());
        } else if let Some(value) = token.strip_prefix("instance_id=") {
            instance_id = Some(value.to_owned());
        }
    }

    Some(ProgressEvent {
        stage: stage?,
        role: role?,
        instance_id: instance_id?,
    })
}

fn is_low_signal_stage(stage: &str) -> bool {
    matches!(
        stage,
        "peer_withdrawal_start"
            | "peer_withdrawal_initiator_aggregation_start"
            | "peer_withdrawal_non_initiator_approval_start"
            | "peer_withdrawal_non_initiator_ack_start"
            | "peer_withdrawal_non_initiator_commit_start"
            | "sar_withdrawal_initiator_path"
            | "sar_withdrawal_non_initiator_path"
    )
}

fn wt_ping_pong_round_step(stage: &str) -> Option<(usize, WtPingPongStep)> {
    let (round, suffix) = parse_round_stage(stage, "wt_ping_pong_round_")?;
    let step = match suffix {
        "sar_ping_dispatch" => WtPingPongStep::SarPingDispatch,
        "sar_pong_collected" => WtPingPongStep::SarPongCollected,
        "peer_pong_dispatch" => WtPingPongStep::PeerPongDispatch,
        "peer_ping_collected" => WtPingPongStep::PeerPingCollected,
        _ => return None,
    };
    Some((round, step))
}

fn peer_ping_pong_round_step(stage: &str) -> Option<(usize, PeerPingPongStep)> {
    let (round, suffix) = parse_round_stage(stage, "peer_ping_pong_round_")?;
    let step = match suffix {
        "wt_pong_received" => PeerPingPongStep::WtPongReceived,
        "duress_check_complete" => PeerPingPongStep::DuressCheckComplete,
        "wt_ping_sent" => PeerPingPongStep::WtPingSent,
        _ => return None,
    };
    Some((round, step))
}

fn parse_round_stage<'a>(stage: &'a str, prefix: &str) -> Option<(usize, &'a str)> {
    let remainder = stage.strip_prefix(prefix)?;
    let (round, suffix) = remainder.split_once('_')?;
    Some((round.parse::<usize>().ok()?, suffix))
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        ColorMode, NarrativeState, format_narrative_line_with_mode, parse_progress_event,
        peer_ping_pong_round_step, read_new_progress_events, wt_ping_pong_round_step,
    };

    fn unique_temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "boomerang-poc-runtime-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime should build")
    }

    #[test]
    fn parses_stage_lines() {
        let event = parse_progress_event("stage=wt_setup_start role=wt instance_id=wt\n")
            .expect("well-formed progress lines should parse");

        assert_eq!(event.stage, "wt_setup_start");
        assert_eq!(event.role, "wt");
        assert_eq!(event.instance_id, "wt");
    }

    #[test]
    fn colorized_narrative_lines_style_the_phase_label() {
        let line = format_narrative_line_with_mode(
            ColorMode::Enabled,
            "withdrawal",
            "WT dispatched SAR pings",
        );

        assert!(line.contains("\u{1b}[1;33mwithdrawal\u{1b}[0m"));
        assert!(line.contains(": \u{1b}[1;36mWT dispatched SAR pings\u{1b}[0m"));
    }

    #[test]
    fn disabled_color_mode_keeps_the_line_plain() {
        let line =
            format_narrative_line_with_mode(ColorMode::Disabled, "setup", "WT setup complete");

        assert_eq!(line, "setup: WT setup complete");
    }

    #[test]
    fn approvals_are_colored_differently_from_ping_pong_steps() {
        let approvals = format_narrative_line_with_mode(
            ColorMode::Enabled,
            "withdrawal",
            "WT collected the non-initiator approvals",
        );
        let ping_pong = format_narrative_line_with_mode(
            ColorMode::Enabled,
            "withdrawal",
            "digging game round 7: peer-2 sent the WT ping (2/5)",
        );

        assert!(
            approvals.contains(": \u{1b}[1;35mWT collected the non-initiator approvals\u{1b}[0m")
        );
        assert!(ping_pong.contains(
            ": \u{1b}[1;36mdigging game round 7: peer-2 sent the WT ping (2/5)\u{1b}[0m"
        ));
    }

    #[test]
    fn duress_checks_are_colored_as_high_attention_events() {
        let line = format_narrative_line_with_mode(
            ColorMode::Enabled,
            "withdrawal",
            "peer-4 completed the commitment-phase duress check",
        );

        assert!(
            line.contains(
                ": \u{1b}[1;31mpeer-4 completed the commitment-phase duress check\u{1b}[0m"
            )
        );
    }

    #[test]
    fn tails_progress_logs_by_offset() {
        runtime().block_on(async {
            let path = unique_temp_path("progress-tail.log");
            fs::write(&path, "stage=wt_setup_start role=wt instance_id=wt\n")
                .expect("test progress log should be written");

            let (offset, first_events) = read_new_progress_events(&path, 0)
                .await
                .expect("first progress pass should succeed");
            assert_eq!(first_events.len(), 1);

            let mut file = OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("test progress log should reopen");
            writeln!(file, "stage=wt_setup_complete role=wt instance_id=wt")
                .expect("second progress line should append");

            let (_, second_events) = read_new_progress_events(&path, offset)
                .await
                .expect("second progress pass should succeed");
            assert_eq!(second_events.len(), 1);
            assert_eq!(second_events[0].stage, "wt_setup_complete");

            let _ = fs::remove_file(path);
        });
    }

    #[test]
    fn deduplicates_repeated_stage_messages() {
        let mut state = NarrativeState::default();
        state.known_processes.insert("wt:wt".to_owned());

        let first = state.lines_for_event(&super::ProgressEvent {
            stage: "wt_setup_start".to_owned(),
            role: "wt".to_owned(),
            instance_id: "wt".to_owned(),
        });
        let second = state.lines_for_event(&super::ProgressEvent {
            stage: "wt_setup_start".to_owned(),
            role: "wt".to_owned(),
            instance_id: "wt".to_owned(),
        });

        assert!(!first.is_empty());
        assert!(second.is_empty());
    }

    #[test]
    fn aggregates_peer_setup_completion_counts() {
        let mut state = NarrativeState {
            expected_peers: 2,
            ..Default::default()
        };
        state.known_processes.insert("peer:peer-1".to_owned());
        state.known_processes.insert("peer:peer-2".to_owned());

        let first = state.lines_for_event(&super::ProgressEvent {
            stage: "peer_setup_complete".to_owned(),
            role: "peer".to_owned(),
            instance_id: "peer-1".to_owned(),
        });
        let second = state.lines_for_event(&super::ProgressEvent {
            stage: "peer_setup_complete".to_owned(),
            role: "peer".to_owned(),
            instance_id: "peer-2".to_owned(),
        });

        assert!(
            first
                .iter()
                .any(|line| line.message.contains("Peers ready 1/2"))
        );
        assert!(
            second
                .iter()
                .any(|line| line.message.contains("Peers ready 2/2"))
        );
    }

    #[test]
    fn deduplicates_sar_identity_publication_per_instance() {
        let mut state = NarrativeState {
            expected_sars: 2,
            ..Default::default()
        };
        state.known_processes.insert("sar:sar-1".to_owned());
        state.known_processes.insert("sar:sar-2".to_owned());

        let first = state.lines_for_event(&super::ProgressEvent {
            stage: "identity_published".to_owned(),
            role: "sar".to_owned(),
            instance_id: "sar-1".to_owned(),
        });
        let duplicate = state.lines_for_event(&super::ProgressEvent {
            stage: "identity_published".to_owned(),
            role: "sar".to_owned(),
            instance_id: "sar-1".to_owned(),
        });
        let second = state.lines_for_event(&super::ProgressEvent {
            stage: "identity_published".to_owned(),
            role: "sar".to_owned(),
            instance_id: "sar-2".to_owned(),
        });

        assert!(
            first
                .iter()
                .any(|line| line.message.contains("SAR public identities ready 1/2"))
        );
        assert!(duplicate.is_empty());
        assert!(
            second
                .iter()
                .any(|line| line.message.contains("SAR public identities ready 2/2"))
        );
    }

    #[test]
    fn prints_fallback_for_unknown_stage_once() {
        let mut state = NarrativeState::default();
        state.known_processes.insert("wt:wt".to_owned());

        let first = state.lines_for_event(&super::ProgressEvent {
            stage: "future_stage".to_owned(),
            role: "wt".to_owned(),
            instance_id: "wt".to_owned(),
        });
        let second = state.lines_for_event(&super::ProgressEvent {
            stage: "future_stage".to_owned(),
            role: "wt".to_owned(),
            instance_id: "wt".to_owned(),
        });

        assert_eq!(first.len(), 1);
        assert!(first[0].message.contains("future_stage"));
        assert!(second.is_empty());
    }

    #[test]
    fn surfaces_all_wt_ping_pong_round_steps() {
        let mut state = NarrativeState::default();
        state.known_processes.insert("wt:wt".to_owned());

        let sar_ping = state.lines_for_event(&super::ProgressEvent {
            stage: "wt_ping_pong_round_12_sar_ping_dispatch".to_owned(),
            role: "wt".to_owned(),
            instance_id: "wt".to_owned(),
        });
        let sar_pong = state.lines_for_event(&super::ProgressEvent {
            stage: "wt_ping_pong_round_12_sar_pong_collected".to_owned(),
            role: "wt".to_owned(),
            instance_id: "wt".to_owned(),
        });
        let peer_pong = state.lines_for_event(&super::ProgressEvent {
            stage: "wt_ping_pong_round_12_peer_pong_dispatch".to_owned(),
            role: "wt".to_owned(),
            instance_id: "wt".to_owned(),
        });
        let peer_ping = state.lines_for_event(&super::ProgressEvent {
            stage: "wt_ping_pong_round_12_peer_ping_collected".to_owned(),
            role: "wt".to_owned(),
            instance_id: "wt".to_owned(),
        });

        assert!(
            sar_ping
                .iter()
                .any(|line| line.message.contains("round 12: WT dispatched SAR pings"))
        );
        assert!(
            sar_pong
                .iter()
                .any(|line| line.message.contains("round 12: WT collected SAR pongs"))
        );
        assert!(
            peer_pong
                .iter()
                .any(|line| line.message.contains("round 12: WT dispatched peer pongs"))
        );
        assert!(
            peer_ping
                .iter()
                .any(|line| line.message.contains("round 12: WT collected peer pings"))
        );
    }

    #[test]
    fn surfaces_digging_game_start_and_finish() {
        let mut state = NarrativeState::default();
        state.known_processes.insert("peer:peer-1".to_owned());

        let start = state.lines_for_event(&super::ProgressEvent {
            stage: "peer_withdrawal_ping_pong_start".to_owned(),
            role: "peer".to_owned(),
            instance_id: "peer-1".to_owned(),
        });
        let finish = state.lines_for_event(&super::ProgressEvent {
            stage: "peer_withdrawal_finish_signing_start".to_owned(),
            role: "peer".to_owned(),
            instance_id: "peer-1".to_owned(),
        });

        assert!(
            start
                .iter()
                .any(|line| line.message.contains("digging game has started"))
        );
        assert!(
            finish
                .iter()
                .any(|line| line.message.contains("digging game is complete"))
        );
    }

    #[test]
    fn surfaces_peer_duress_check_milestones() {
        let mut state = NarrativeState {
            expected_peers: 5,
            ..Default::default()
        };
        for peer in 1..=5 {
            state.known_processes.insert(format!("peer:peer-{peer}"));
        }

        let initiator = state.lines_for_event(&super::ProgressEvent {
            stage: "peer_withdrawal_initiator_duress_check_complete".to_owned(),
            role: "peer".to_owned(),
            instance_id: "peer-1".to_owned(),
        });

        let mut final_non_initiator = Vec::new();
        for peer in 2..=5 {
            final_non_initiator = state.lines_for_event(&super::ProgressEvent {
                stage: "peer_withdrawal_non_initiator_duress_check_complete".to_owned(),
                role: "peer".to_owned(),
                instance_id: format!("peer-{peer}"),
            });
        }

        assert!(
            initiator
                .iter()
                .any(|line| line.message.contains("commitment-phase duress check"))
        );
        assert!(final_non_initiator.iter().any(|line| {
            line.message
                .contains("peer-5 completed the non-initiator approval-phase duress check (4/4)")
        }));
    }

    #[test]
    fn surfaces_all_peer_ping_pong_and_duress_steps() {
        let mut state = NarrativeState {
            expected_peers: 2,
            ..Default::default()
        };
        state.known_processes.insert("peer:peer-1".to_owned());
        state.known_processes.insert("peer:peer-2".to_owned());

        let pong = state.lines_for_event(&super::ProgressEvent {
            stage: "peer_ping_pong_round_4_wt_pong_received".to_owned(),
            role: "peer".to_owned(),
            instance_id: "peer-1".to_owned(),
        });
        let duress = state.lines_for_event(&super::ProgressEvent {
            stage: "peer_ping_pong_round_4_duress_check_complete".to_owned(),
            role: "peer".to_owned(),
            instance_id: "peer-2".to_owned(),
        });
        let ping = state.lines_for_event(&super::ProgressEvent {
            stage: "peer_ping_pong_round_4_wt_ping_sent".to_owned(),
            role: "peer".to_owned(),
            instance_id: "peer-1".to_owned(),
        });
        let final_release = state.lines_for_event(&super::ProgressEvent {
            stage: "peer_ping_pong_final_reached_pings_received".to_owned(),
            role: "peer".to_owned(),
            instance_id: "peer-1".to_owned(),
        });

        assert!(pong.iter().any(|line| {
            line.message
                .contains("digging game round 4: peer-1 received the WT pong (1/2)")
        }));
        assert!(duress.iter().any(|line| {
            line.message
                .contains("digging game round 4: peer-2 completed the duress check (1/2)")
        }));
        assert!(ping.iter().any(|line| {
            line.message
                .contains("digging game round 4: peer-1 sent the WT ping (1/2)")
        }));
        assert!(final_release.iter().any(|line| {
            line.message
                .contains("peer-1 received the final reached-pings state (1/2)")
        }));
    }

    #[test]
    fn parses_ping_pong_round_steps() {
        assert_eq!(
            wt_ping_pong_round_step("wt_ping_pong_round_1_sar_ping_dispatch"),
            Some((1, super::WtPingPongStep::SarPingDispatch))
        );
        assert_eq!(
            wt_ping_pong_round_step("wt_ping_pong_round_4_peer_ping_collected"),
            Some((4, super::WtPingPongStep::PeerPingCollected))
        );
        assert_eq!(
            peer_ping_pong_round_step("peer_ping_pong_round_1_wt_ping_sent"),
            Some((1, super::PeerPingPongStep::WtPingSent))
        );
        assert_eq!(
            peer_ping_pong_round_step("peer_ping_pong_round_1_duress_check_complete"),
            Some((1, super::PeerPingPongStep::DuressCheckComplete))
        );
        assert_eq!(
            peer_ping_pong_round_step("peer_ping_pong_round_1_unknown"),
            None
        );
    }
}
