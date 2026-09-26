use super::*;
use chrono::TimeZone;
use serde_json::json;

fn ts(hour: u32, min: u32, sec: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 26, hour, min, sec).unwrap()
}

fn sufficient_report() -> UnitHealthReport {
    UnitHealthReport {
        unit_id: "unit-a".to_string(),
        revision: Some("web-00007-xyz".to_string()),
        readiness: Readiness::Ready,
        window_start: Some(ts(12, 0, 0)),
        window_end: Some(ts(13, 0, 0)),
        requests: Some(RequestCounts {
            ok_2xx: 118,
            redirect_3xx: 0,
            client_4xx: 2,
            server_5xx: 0,
        }),
        latency_ms: Latency {
            p50: Some(45.0),
            p99: Some(210.0),
        },
        server_error_rate: Some(0.0),
        idle: false,
        evidence: Evidence::Sufficient,
        reported_at: ts(13, 0, 5),
    }
}

fn insufficient_report() -> UnitHealthReport {
    UnitHealthReport {
        unit_id: "unit-b".to_string(),
        revision: None,
        readiness: Readiness::Unknown,
        window_start: None,
        window_end: Some(ts(12, 0, 0)),
        requests: None,
        latency_ms: Latency::default(),
        server_error_rate: None,
        idle: false,
        evidence: Evidence::Insufficient {
            reason: InsufficientReason::NoRecordedRevision,
            detail: Some(
                "Designer recorded no Cloud Run revision for this unit's last deploy. \
                 Deploy the environment again to record one."
                    .to_string(),
            ),
            remediation: None,
        },
        reported_at: ts(12, 0, 1),
    }
}

#[test]
fn round_trips_a_sufficient_report() {
    let report = sufficient_report();
    let json = serde_json::to_string(&report).unwrap();
    let back: UnitHealthReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn round_trips_an_insufficient_report() {
    let report = insufficient_report();
    let json = serde_json::to_string(&report).unwrap();
    let back: UnitHealthReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn wire_shape_of_a_sufficient_report_is_pinned() {
    let value = serde_json::to_value(sufficient_report()).unwrap();
    assert_eq!(
        value,
        json!({
            "unit_id": "unit-a",
            "revision": "web-00007-xyz",
            "readiness": { "state": "ready" },
            "windowStart": "2026-09-26T12:00:00Z",
            "windowEnd": "2026-09-26T13:00:00Z",
            "requests": {
                "ok2xx": 118,
                "redirect3xx": 0,
                "client4xx": 2,
                "server5xx": 0
            },
            "latencyMs": { "p50": 45.0, "p99": 210.0 },
            "serverErrorRate": 0.0,
            "idle": false,
            "evidence": { "state": "sufficient" },
            "reported_at": "2026-09-26T13:00:05Z"
        })
    );
}

#[test]
fn wire_shape_of_an_insufficient_report_is_pinned() {
    let value = serde_json::to_value(insufficient_report()).unwrap();
    assert_eq!(
        value,
        json!({
            "unit_id": "unit-b",
            "revision": null,
            "readiness": { "state": "unknown" },
            "windowStart": null,
            "windowEnd": "2026-09-26T12:00:00Z",
            "requests": null,
            "latencyMs": { "p50": null, "p99": null },
            "serverErrorRate": null,
            "idle": false,
            "evidence": {
                "state": "insufficient",
                "reason": "no_recorded_revision",
                "detail": "Designer recorded no Cloud Run revision for this unit's last deploy. \
                            Deploy the environment again to record one."
            },
            "reported_at": "2026-09-26T12:00:01Z"
        })
    );
}

/// A literal JSON body shaped exactly like the designer's own
/// `orchestrate::env_deploy::unit_health::UnitHealth` — built from that
/// module's struct definitions rather than copied from one pinning test,
/// since no single test there pins the whole body (only
/// `the_wire_names_the_reason_in_snake_case` and the `RequestCounts` case in
/// `redirects_are_counted_and_uncounted_traffic_is_never_sufficient` each pin
/// a slice of it). `unit_id` and `reported_at` are appended, as the two
/// report-level fields the designer's reporting route adds on top.
#[test]
fn designer_unit_health_json_deserializes_unchanged() {
    let body = json!({
        "revision": null,
        "readiness": { "state": "unknown" },
        "windowStart": null,
        "windowEnd": "2026-09-26T02:51:52Z",
        "requests": null,
        "latencyMs": { "p50": null, "p99": null },
        "serverErrorRate": null,
        "idle": false,
        "evidence": {
            "state": "insufficient",
            "reason": "cannot_evaluate",
            "detail": "x"
        },
        "unit_id": "unit-a",
        "reported_at": "2026-09-26T02:51:52Z"
    });

    let report: UnitHealthReport = serde_json::from_value(body).unwrap();

    assert_eq!(report.unit_id, "unit-a");
    assert_eq!(report.revision, None);
    assert_eq!(report.readiness, Readiness::Unknown);
    assert_eq!(report.window_start, None);
    assert_eq!(report.window_end, Some(ts(2, 51, 52)));
    assert_eq!(report.requests, None);
    assert_eq!(report.latency_ms, Latency::default());
    assert_eq!(report.server_error_rate, None);
    assert!(!report.idle);
    assert_eq!(
        report.evidence,
        Evidence::Insufficient {
            reason: InsufficientReason::CannotEvaluate,
            detail: Some("x".to_string()),
            remediation: None,
        }
    );
    assert_eq!(report.reported_at, ts(2, 51, 52));
    // No evidence claim to break — insufficient tolerates everything.
    assert_eq!(report.validate(), Ok(()));
}

#[test]
fn wire_shape_of_a_not_ready_readiness_is_pinned() {
    let value = serde_json::to_value(Readiness::NotReady {
        reason: "container failed to start".to_string(),
    })
    .unwrap();
    assert_eq!(
        value,
        json!({ "state": "not_ready", "reason": "container failed to start" })
    );
}

#[test]
fn wire_shape_of_insufficient_evidence_with_remediation_is_pinned() {
    let value = serde_json::to_value(Evidence::Insufficient {
        reason: InsufficientReason::CannotEvaluate,
        detail: Some("Cloud Run refused reading the revision (HTTP 403).".to_string()),
        remediation: Some("gcloud projects add-iam-policy-binding ...".to_string()),
    })
    .unwrap();
    assert_eq!(
        value,
        json!({
            "state": "insufficient",
            "reason": "cannot_evaluate",
            "detail": "Cloud Run refused reading the revision (HTTP 403).",
            "remediation": "gcloud projects add-iam-policy-binding ..."
        })
    );
}

#[test]
fn a_valid_sufficient_report_validates() {
    assert_eq!(sufficient_report().validate(), Ok(()));
}

#[test]
fn a_valid_insufficient_report_validates() {
    assert_eq!(insufficient_report().validate(), Ok(()));
}

#[test]
fn a_window_with_no_end_is_never_inverted() {
    let mut report = sufficient_report();
    report.window_end = None;
    report.evidence = Evidence::Insufficient {
        reason: InsufficientReason::Unavailable,
        detail: None,
        remediation: None,
    };
    assert_eq!(report.validate(), Ok(()));
}

#[test]
fn a_window_with_no_start_is_never_inverted() {
    let mut report = sufficient_report();
    report.window_start = None;
    report.evidence = Evidence::Insufficient {
        reason: InsufficientReason::Unavailable,
        detail: None,
        remediation: None,
    };
    assert_eq!(report.validate(), Ok(()));
}

#[test]
fn refuses_a_window_that_ends_before_it_starts() {
    let mut report = sufficient_report();
    report.window_start = Some(ts(13, 0, 0));
    report.window_end = Some(ts(12, 0, 0));
    assert_eq!(
        report.validate(),
        Err(UnitHealthReportError::WindowInverted)
    );
}

#[test]
fn refuses_sufficient_evidence_over_a_not_ready_unit() {
    let mut report = sufficient_report();
    report.readiness = Readiness::NotReady {
        reason: "crash looping".to_string(),
    };
    assert_eq!(
        report.validate(),
        Err(UnitHealthReportError::SufficientWithoutReadyRevision)
    );
}

#[test]
fn refuses_sufficient_evidence_over_an_unknown_readiness() {
    let mut report = sufficient_report();
    report.readiness = Readiness::Unknown;
    assert_eq!(
        report.validate(),
        Err(UnitHealthReportError::SufficientWithoutReadyRevision)
    );
}

#[test]
fn refuses_sufficient_evidence_while_idle() {
    let mut report = sufficient_report();
    report.idle = true;
    assert_eq!(
        report.validate(),
        Err(UnitHealthReportError::SufficientWhileIdle)
    );
}

#[test]
fn refuses_sufficient_evidence_with_no_measured_requests() {
    let mut report = sufficient_report();
    report.requests = None;
    assert_eq!(
        report.validate(),
        Err(UnitHealthReportError::SufficientWithoutRequests)
    );
}

#[test]
fn insufficient_evidence_tolerates_idle_and_unmeasured_requests() {
    let mut report = insufficient_report();
    report.idle = true;
    assert_eq!(report.validate(), Ok(()));
}

#[test]
fn request_counts_counted_sums_every_bucket() {
    let counts = RequestCounts {
        ok_2xx: 10,
        redirect_3xx: 1,
        client_4xx: 2,
        server_5xx: 3,
    };
    assert_eq!(counts.counted(), 16);
}

#[test]
fn request_counts_wire_shape_matches_the_designer_exactly() {
    let counts = RequestCounts {
        ok_2xx: 0,
        redirect_3xx: 7,
        client_4xx: 0,
        server_5xx: 0,
    };
    let value = serde_json::to_value(counts).unwrap();
    assert_eq!(value["redirect3xx"], 7);
}

#[test]
fn error_display_is_stable() {
    assert_eq!(
        UnitHealthReportError::WindowInverted.to_string(),
        "window_end is before window_start"
    );
    assert_eq!(
        UnitHealthReportError::SufficientWithoutReadyRevision.to_string(),
        "evidence is `sufficient` but readiness is not `ready`"
    );
    assert_eq!(
        UnitHealthReportError::SufficientWhileIdle.to_string(),
        "evidence is `sufficient` but idle is true"
    );
    assert_eq!(
        UnitHealthReportError::SufficientWithoutRequests.to_string(),
        "evidence is `sufficient` but requests were never measured"
    );
}
