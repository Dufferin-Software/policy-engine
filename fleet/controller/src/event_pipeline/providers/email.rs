// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

//! SMTP email notifier (lettre).
//!
//! `receivers.config_json` schema:
//!
//! ```json
//! {
//!   "smtp_host": "smtp.example.com",
//!   "smtp_port": 587,                       // optional, default 587
//!   "username": "alertbot",                 // optional
//!   "password": "...",                      // optional
//!   "from":     "alerts@example.com",
//!   "to":       ["ops@example.com"],
//!   "starttls": true                        // optional, default true
//! }
//! ```
//!
//! One outbound message per notification. `Resolve` notifications get a
//! `[RESOLVED]` subject prefix so receivers can filter without re-parsing.

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use lettre::{
    message::Mailbox,
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::Deserialize;

use super::super::alert_store::Receiver;
use super::{NotificationKindStr, NotificationPayload, Notifier};

#[derive(Debug, Deserialize)]
struct EmailConfig {
    smtp_host: String,
    #[serde(default = "default_port")]
    smtp_port: u16,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    from: String,
    to: Vec<String>,
    #[serde(default = "default_starttls")]
    starttls: bool,
}

fn default_port() -> u16 {
    587
}
fn default_starttls() -> bool {
    true
}

pub struct EmailNotifier;

impl Default for EmailNotifier {
    fn default() -> Self {
        Self::new()
    }
}

impl EmailNotifier {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Notifier for EmailNotifier {
    fn kind(&self) -> &'static str {
        "email"
    }

    async fn send(&self, receiver: &Receiver, payload: &NotificationPayload) -> Result<()> {
        let cfg: EmailConfig = serde_json::from_str(&receiver.config_json).with_context(|| {
            format!(
                "receiver {} ({}): bad config_json",
                receiver.id, receiver.name
            )
        })?;
        let message = build_message(&cfg, payload)?;
        let transport = build_transport(&cfg)?;
        transport
            .send(message)
            .await
            .with_context(|| format!("smtp send to {}:{}", cfg.smtp_host, cfg.smtp_port))?;
        Ok(())
    }
}

fn build_message(cfg: &EmailConfig, payload: &NotificationPayload) -> Result<Message> {
    if cfg.to.is_empty() {
        bail!("email receiver: `to` must list at least one recipient");
    }
    let from: Mailbox = cfg
        .from
        .parse()
        .map_err(|e| anyhow!("invalid `from` ({}): {e}", cfg.from))?;
    let prefix = match payload.kind {
        NotificationKindStr::Resolve => "[RESOLVED]",
        NotificationKindStr::Refire => "[REFIRE]",
        NotificationKindStr::Initial => "[FIRING]",
    };
    let subject = format!(
        "{prefix} {sev} {name} ({group})",
        sev = payload.severity.to_uppercase(),
        name = payload.rule_name,
        group = payload.group_key,
    );
    let body = format!(
        "Alert: {name}\n\
         Severity: {sev}\n\
         Kind: {kind:?}\n\
         Fired at: {fired}\n\
         Group: {group}\n\
         Event count: {count}\n\
         Sample event ids: {samples:?}\n",
        name = payload.rule_name,
        sev = payload.severity,
        kind = payload.kind,
        fired = payload.fired_at.to_rfc3339(),
        group = payload.group_key,
        count = payload.event_count,
        samples = payload.sample_event_ids,
    );

    let mut builder = Message::builder().from(from).subject(subject);
    for addr in &cfg.to {
        let mailbox: Mailbox = addr
            .parse()
            .map_err(|e| anyhow!("invalid `to` entry ({addr}): {e}"))?;
        builder = builder.to(mailbox);
    }
    builder.body(body).context("build email body")
}

fn build_transport(cfg: &EmailConfig) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
    let mut builder =
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.smtp_host).port(cfg.smtp_port);
    if cfg.starttls {
        let tls = TlsParameters::new(cfg.smtp_host.clone())
            .with_context(|| format!("tls params for {}", cfg.smtp_host))?;
        builder = builder.tls(Tls::Required(tls));
    }
    if let (Some(u), Some(p)) = (cfg.username.as_deref(), cfg.password.as_deref()) {
        builder = builder.credentials(Credentials::new(u.into(), p.into()));
    }
    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_pipeline::grouper::NotificationKind;
    use chrono::TimeZone;

    fn payload(kind: NotificationKind) -> NotificationPayload {
        NotificationPayload {
            rule_id: 7,
            rule_name: "drops on n1".into(),
            severity: "critical".into(),
            group_key: "rule_id=7".into(),
            kind: kind.into(),
            fired_at: chrono::Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            event_count: 5,
            sample_event_ids: vec![1, 2, 3],
        }
    }

    fn cfg() -> EmailConfig {
        EmailConfig {
            smtp_host: "smtp.example.com".into(),
            smtp_port: 587,
            username: Some("u".into()),
            password: Some("p".into()),
            from: "Alerts <alerts@example.com>".into(),
            to: vec!["ops@example.com".into(), "secops@example.com".into()],
            starttls: true,
        }
    }

    fn raw_msg(kind: NotificationKind) -> String {
        let m = build_message(&cfg(), &payload(kind)).unwrap();
        String::from_utf8(m.formatted()).unwrap()
    }

    #[test]
    fn subject_prefix_reflects_kind() {
        assert!(raw_msg(NotificationKind::InitialFire).contains("[FIRING]"));
        assert!(raw_msg(NotificationKind::Refire).contains("[REFIRE]"));
        assert!(raw_msg(NotificationKind::Resolve).contains("[RESOLVED]"));
    }

    #[test]
    fn message_includes_all_recipients_and_body_fields() {
        let raw = raw_msg(NotificationKind::InitialFire);
        assert!(raw.contains("ops@example.com"));
        assert!(raw.contains("secops@example.com"));
        assert!(raw.contains("Severity: critical"));
        assert!(raw.contains("Event count: 5"));
        assert!(raw.contains("rule_id=7"));
    }

    #[test]
    fn empty_to_list_rejected() {
        let mut c = cfg();
        c.to.clear();
        let err = build_message(&c, &payload(NotificationKind::InitialFire)).unwrap_err();
        assert!(err.to_string().contains("at least one recipient"));
    }

    #[test]
    fn bad_from_rejected() {
        let mut c = cfg();
        c.from = "not-an-email".into();
        let err = build_message(&c, &payload(NotificationKind::InitialFire)).unwrap_err();
        assert!(err.to_string().contains("invalid `from`"));
    }

    #[tokio::test]
    async fn send_rejects_bad_config_json() {
        let notifier = EmailNotifier::new();
        let rcv = Receiver {
            id: 1,
            tenant_id: 1,
            name: "ops".into(),
            kind: "email".into(),
            config_json: "not json".into(),
        };
        let err = notifier
            .send(&rcv, &payload(NotificationKind::InitialFire))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("bad config_json"));
    }
}
