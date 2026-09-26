use super::*;
use chrono::TimeZone;
use serde_json::json;

fn ts(hour: u32, min: u32, sec: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 26, hour, min, sec).unwrap()
}

fn sufficient_report() -> UnitHealthReport {
    UnitHealthReport {
        unit_id: "unit-a".to_string(),
        observed_revision: Some("web-00007-xyz".to_string()),
        readiness: Readiness::Ready,
        window_start: ts(12, 0, 0),
        window_end: ts(13, 0, 0),
        requests: Some(RequestCounts {
            ok_2xx: 118,
            redirect_3xx: 0,
            client_4xx: 2,
            server_5xx: 0,
        }),
        latency_ms: Some(Latency {
            p50: Some(45.0),
            p99: Some(210.0),
        }),
        server_error_rate: Some(0.0),
        idle: false,
        evidence: Evidence::Sufficient,
        reported_at: ts(13, 0, 5),
    }
}

fn insufficient_report() -> UnitHealthReport {
    UnitHealthReport {
        unit_id: "unit-b".to_string(),
        observed_revision: None,
        readiness: Readiness::Unknown,
        window_start: ts(12, 0, 0),
        window_end: ts(12, 0, 0),
        requests: None,
        latency_ms: None,
        server_error_rate: None,
        idle: false,
        evidence: Evidence::Insufficient {
            reason: InsufficientReason::NoRecordedRevision,
            detail: Some("Designer recorded no revision for this unit's last deploy.".to_string()),
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
            "observed_revision": "web-00007-xyz",
            "readiness": { "status": "ready" },
            "window_start": "2026-09-26T12:00:00Z",
            "window_end": "2026-09-26T13:00:00Z",
            "requests": {
                "ok_2xx": 118,
                "redirect_3xx": 0,
                "client_4xx": 2,
                "server_5xx": 0
            },
            "latency_ms": { "p50": 45.0, "p99": 210.0 },
            "server_error_rate": 0.0,
            "idle": false,
            "evidence": { "kind": "sufficient" },
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
            "readiness": { "status": "unknown" },
            "window_start": "2026-09-26T12:00:00Z",
            "window_end": "2026-09-26T12:00:00Z",
            "idle": false,
            "evidence": {
                "kind": "insufficient",
                "reason": "no_recorded_revision",
                "detail": "Designer recorded no revision for this unit's last deploy."
            },
            "reported_at": "2026-09-26T12:00:01Z"
        })
    );
}

#[test]
fn wire_shape_of_a_not_ready_readiness_is_pinned() {
    let value = serde_json::to_value(Readiness::NotReady {
        reason: "container failed to start".to_string(),
    })
    .unwrap();
    assert_eq!(
        value,
        json!({ "status": "not_ready", "reason": "container failed to start" })
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
fn refuses_a_window_that_ends_before_it_starts() {
    let mut report = sufficient_report();
    report.window_start = ts(13, 0, 0);
    report.window_end = ts(12, 0, 0);
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
