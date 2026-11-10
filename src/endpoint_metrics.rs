//! Exports iroh endpoint state (its own metrics, net report, home relay) as Prometheus metrics.

use iroh::{metrics::EndpointMetrics, Endpoint, NetReport};
use iroh_metrics::{MetricValue, MetricsGroupSet};
use metrics::{counter, describe_counter, describe_gauge, gauge};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;

const PREFIX: &str = "p2p_vpn_iroh";

/// Spawns a loop that periodically copies the endpoint's state into the `metrics` registry.
pub fn spawn_exporter(
    endpoint: Endpoint,
    period: Duration,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        describe_all(endpoint.metrics());
        let mut home_relay: Option<String> = None;
        let mut preferred_relay: Option<String> = None;
        let mut ticker = interval(period);
        loop {
            tokio::select! {
                _ = ticker.tick() => (),
                _ = cancel.cancelled() => break,
            };
            if endpoint.is_closed() {
                break;
            }
            export_iroh_metrics(endpoint.metrics());
            export_home_relay(&endpoint, &mut home_relay);
            if let Some(report) = endpoint.last_net_report() {
                export_net_report(&report, &mut preferred_relay);
            }
        }
    })
}

fn metric_name(group: &str, name: &str, is_counter: bool) -> String {
    if is_counter {
        format!("{PREFIX}_{group}_{name}_total")
    } else {
        format!("{PREFIX}_{group}_{name}")
    }
}

fn describe_all(metrics: &EndpointMetrics) {
    for (group, item) in metrics.iter() {
        let help = if item.help().is_empty() { item.name() } else { item.help() };
        match item.value() {
            MetricValue::Counter(_) => {
                describe_counter!(metric_name(group, item.name(), true), help)
            }
            MetricValue::Gauge(_) => describe_gauge!(metric_name(group, item.name(), false), help),
            _ => {}
        }
    }
    describe_gauge!(
        format!("{PREFIX}_home_relay"),
        "The relay this endpoint is currently homed on (1) or was homed on before (0)"
    );
    describe_gauge!(
        format!("{PREFIX}_local_direct_addrs"),
        "Number of direct addresses currently advertised by this endpoint"
    );
}

/// Mirrors every metric of the iroh endpoint (socket, net_report, portmapper) under `p2p_vpn_iroh_`.
fn export_iroh_metrics(metrics: &EndpointMetrics) {
    for (group, item) in metrics.iter() {
        match item.value() {
            MetricValue::Counter(v) => counter!(metric_name(group, item.name(), true)).absolute(v),
            MetricValue::Gauge(v) => gauge!(metric_name(group, item.name(), false)).set(v as f64),
            _ => {}
        }
    }
}

fn export_home_relay(endpoint: &Endpoint, current: &mut Option<String>) {
    let addr = endpoint.addr();
    gauge!(format!("{PREFIX}_local_direct_addrs")).set(addr.ip_addrs().count() as f64);
    let relay = addr.relay_urls().next().map(ToString::to_string);
    set_one_hot(&format!("{PREFIX}_home_relay"), current, relay);
}

fn export_net_report(report: &NetReport, preferred: &mut Option<String>) {
    gauge!(format!("{PREFIX}_net_report_udp_v4")).set(report.udp_v4 as u8 as f64);
    gauge!(format!("{PREFIX}_net_report_udp_v6")).set(report.udp_v6 as u8 as f64);
    for (family, varies) in
        [("v4", report.mapping_varies_by_dest_ipv4), ("v6", report.mapping_varies_by_dest_ipv6)]
    {
        if let Some(varies) = varies {
            gauge!(format!("{PREFIX}_net_report_mapping_varies_by_dest"), "family" => family)
                .set(varies as u8 as f64);
        }
    }
    if let Some(captive) = report.captive_portal {
        gauge!(format!("{PREFIX}_net_report_captive_portal")).set(captive as u8 as f64);
    }
    for (probe, relay, latency) in report.relay_latency.iter() {
        gauge!(
            format!("{PREFIX}_net_report_relay_latency_seconds"),
            "relay" => relay.to_string(),
            "probe" => format!("{probe:?}"),
        )
        .set(latency.as_secs_f64());
    }
    let relay = report.preferred_relay.as_ref().map(ToString::to_string);
    set_one_hot(&format!("{PREFIX}_net_report_preferred_relay"), preferred, relay);
}

/// Sets `name{relay=<new>}` to 1 and zeroes the previous label value, so only one is hot.
fn set_one_hot(name: &str, current: &mut Option<String>, new: Option<String>) {
    if *current == new {
        if let Some(relay) = new {
            gauge!(name.to_owned(), "relay" => relay).set(1.0);
        }
        return;
    }
    if let Some(old) = current.take() {
        gauge!(name.to_owned(), "relay" => old).set(0.0);
    }
    if let Some(relay) = &new {
        gauge!(name.to_owned(), "relay" => relay.clone()).set(1.0);
    }
    *current = new;
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::endpoint::presets;
    use metrics_exporter_prometheus::PrometheusBuilder;

    #[tokio::test]
    async fn iroh_metrics_are_exported() {
        let endpoint = Endpoint::builder(presets::Minimal).bind().await.unwrap();
        endpoint.metrics().socket.holepunch_attempts.inc_by(3);
        endpoint.metrics().socket.relay_home_change.inc();

        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            describe_all(endpoint.metrics());
            export_iroh_metrics(endpoint.metrics());
            let mut current = None;
            set_one_hot("p2p_vpn_iroh_home_relay", &mut current, Some("https://a/".into()));
            set_one_hot("p2p_vpn_iroh_home_relay", &mut current, Some("https://b/".into()));
        });
        let text = handle.render();

        assert!(text.contains("p2p_vpn_iroh_socket_holepunch_attempts_total 3"), "{text}");
        assert!(text.contains("p2p_vpn_iroh_socket_relay_home_change_total 1"), "{text}");
        assert!(text.contains("p2p_vpn_iroh_net_report_reports_total 0"), "{text}");
        assert!(text.contains("p2p_vpn_iroh_home_relay{relay=\"https://a/\"} 0"), "{text}");
        assert!(text.contains("p2p_vpn_iroh_home_relay{relay=\"https://b/\"} 1"), "{text}");
        endpoint.close().await;
    }
}
