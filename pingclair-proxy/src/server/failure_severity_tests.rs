// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📉 Request failures are logged at a level chosen by where they came from, so
//! a client hanging up never pages anyone.

use super::*;
use pingora_core::{ErrorSource, ErrorType};

fn error(source: &ErrorSource, etype: &ErrorType) -> Box<pingora_core::Error> {
    let mut error = pingora_core::Error::new(etype.clone());
    error.esource = source.clone();
    error
}

#[test]
fn a_client_that_hangs_up_is_not_an_error() {
    // 🚨 The regression this exists for. A `wrk -c200` run closing its
    // connections produced 225 ERROR lines in one second, describing
    // nothing an operator could fix, immediately after 727,414 requests
    // had succeeded. At the default filter those lines were the *only*
    // thing visible, because the successful access log sits at INFO.
    for etype in [
        ErrorType::ConnectionClosed,
        ErrorType::ReadError,
        ErrorType::WriteError,
    ] {
        assert_eq!(
            failure_severity(&error(&ErrorSource::Downstream, &etype)),
            tracing::Level::DEBUG,
            "a downstream {etype:?} is the client leaving, not a server error"
        );
    }
}

#[test]
fn a_client_sending_something_invalid_is_visible_but_not_an_error() {
    // 🚫 Nameable client misbehaviour stays reportable — an operator
    // chasing a broken integration wants to see it — without claiming the
    // server failed.
    for etype in [ErrorType::InvalidHTTPHeader, ErrorType::ConnectProxyFailure] {
        assert_eq!(
            failure_severity(&error(&ErrorSource::Downstream, &etype)),
            tracing::Level::WARN,
            "a downstream {etype:?} is the client's doing, so it is not ERROR"
        );
    }
}

#[test]
fn upstream_and_internal_failures_stay_at_error() {
    // 🛡️ The point of quieting client disconnects is that these become
    // findable again. If this test ever fails, the fix has gone too far.
    for source in [
        ErrorSource::Upstream,
        ErrorSource::Internal,
        ErrorSource::Unset,
    ] {
        for etype in [
            ErrorType::ConnectionClosed,
            ErrorType::ReadError,
            ErrorType::ConnectTimedout,
            ErrorType::InternalError,
        ] {
            assert_eq!(
                failure_severity(&error(&source, &etype)),
                tracing::Level::ERROR,
                "a {source:?} {etype:?} is ours or the origin's and must stay ERROR"
            );
        }
    }
}

#[test]
fn the_same_error_type_is_judged_by_its_source() {
    // 🧭 `ConnectionClosed` is the case that makes source-based
    // classification necessary rather than a type allowlist: the client
    // closing is routine, the origin closing mid-response is not.
    assert_eq!(
        failure_severity(&error(
            &ErrorSource::Downstream,
            &ErrorType::ConnectionClosed
        )),
        tracing::Level::DEBUG
    );
    assert_eq!(
        failure_severity(&error(&ErrorSource::Upstream, &ErrorType::ConnectionClosed)),
        tracing::Level::ERROR
    );
}
