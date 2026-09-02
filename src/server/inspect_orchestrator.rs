// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! Suricata inspect orchestration: the system-level enable/disable sequence
//! (veth pair, EVE consumer, Suricata config/timer) wrapped around the
//! service-level BPF configuration.
//!
//! Shared by the GraphQL `configureInspect`/`disableInspect` resolvers and
//! the startup restore path, so an inspect mode persisted in state.json is
//! brought back with exactly the mutation semantics.  Both entry points are
//! idempotent: enabling an already-enabled mode (or the IPS↔IDS transition)
//! re-applies configuration without tearing the veth pair down, and
//! disabling twice is harmless.

use std::sync::Arc;

use anyhow::{anyhow, Result};

use super::graphql::AppState;
use super::policy_service::OperationResult;
use crate::types::InspectMode;

/// Bring the inspect subsystem up in `mode` (IPS or IDS).
///
/// Sequence: create the pe-inspect0/pe-inspect1 veth pair (warn-only if it
/// already exists), write the BPF inspect config via the service, start the
/// EVE consumer (must listen before Suricata restarts — Suricata's
/// unix_stream EVE output connects once at startup and never retries), apply
/// the Suricata config, and enable the rules-update timer.
///
/// A Suricata config-write failure is returned as an error: without
/// policy-engine.yaml Suricata inspects nothing while the mode would report
/// enabled.  Callers decide whether that is fatal (mutation) or logged
/// (startup restore).
pub async fn enable_inspect(state: &Arc<AppState>, mode: InspectMode) -> Result<OperationResult> {
    if mode == InspectMode::Disabled {
        return disable_inspect(state).await;
    }

    // Create the veth pair and resolve pe-inspect0's ifindex.  TC ingress
    // clone-redirects INSPECT-marked flows to pe-inspect0; Suricata listens
    // on pe-inspect1 (the peer) and sees the full stream.
    let mirror_ifindex = {
        let mut veth = state.veth_manager.lock().await;
        if let Err(e) = veth.create_pair() {
            log::warn!("Failed to create veth pair for INSPECT cloning: {}", e);
        }
        veth.get_ifindex().unwrap_or(0)
    };

    let op = {
        let mut service = state.service.lock().await;
        service.configure_inspect(mode, mirror_ifindex)?
    };

    // Start the EVE consumer first so the socket exists before Suricata
    // restarts; if the socket is absent Suricata silently disables EVE.
    {
        let mut eve = state.eve_consumer.lock().await;
        if !eve.is_running() {
            eve.start().await.ok();
        }
    }

    state
        .suricata_coordinator
        .apply_config("pe-inspect1")
        .map_err(|e| anyhow!("Failed to apply Suricata config: {:#}", e))?;
    if let Err(e) = state.suricata_coordinator.enable_update_timer() {
        log::warn!("Failed to enable Suricata update timer: {}", e);
    }

    Ok(op)
}

/// Tear the inspect subsystem down: disable the BPF inspect config, stop the
/// EVE consumer, remove the Suricata config/timer, and destroy the veth pair
/// (in that order, so Suricata stops using pe-inspect1 before it disappears).
/// Per-interface inspect flags are left in place — see
/// [`super::policy_service::PolicyService::disable_inspect`].
pub async fn disable_inspect(state: &Arc<AppState>) -> Result<OperationResult> {
    let op = {
        let mut service = state.service.lock().await;
        service.disable_inspect()?
    };

    {
        let mut eve = state.eve_consumer.lock().await;
        eve.stop();
    }

    if let Err(e) = state.suricata_coordinator.remove_config() {
        log::warn!("Failed to remove Suricata config: {}", e);
    }
    if let Err(e) = state.suricata_coordinator.disable_update_timer() {
        log::warn!("Failed to disable Suricata update timer: {}", e);
    }

    let mut veth = state.veth_manager.lock().await;
    if veth.is_up() {
        if let Err(e) = veth.destroy_pair() {
            log::warn!("Failed to destroy veth pair: {}", e);
        }
    }

    Ok(op)
}

/// Restore persisted inspect state at startup: re-run the enable sequence
/// for the persisted mode and re-apply the per-interface flags.  Failures
/// are logged, never fatal — the daemon must come up even if Suricata is
/// broken, and the persisted state is kept so a later retry (or operator
/// action) can recover.  Must run after attachments have been restored so
/// the per-interface TC auto-attach sees the XDP interfaces.
pub async fn restore_inspect_state(state: &Arc<AppState>) {
    let (mode_str, interfaces) = {
        let service = state.service.lock().await;
        service.persisted_inspect_state()
    };

    let Some(mode_str) = mode_str else {
        return;
    };
    let mode = match mode_str.as_str() {
        "ips" => InspectMode::Ips,
        "ids" => InspectMode::Ids,
        other => {
            log::warn!("Ignoring unknown persisted inspect mode {:?}", other);
            return;
        }
    };

    log::info!(
        "Restoring inspect state: mode={} interfaces={:?}",
        mode_str,
        interfaces
    );
    if let Err(e) = enable_inspect(state, mode).await {
        log::error!(
            "Failed to restore inspect mode {} (state kept for retry): {:#}",
            mode_str,
            e
        );
        return;
    }

    let mut service = state.service.lock().await;
    for iface in &interfaces {
        if let Err(e) = service.set_inspect_interface(iface, true) {
            log::warn!("Failed to restore inspect flag on {}: {:#}", iface, e);
        }
    }
}
