//! 🌊 Response events applied after a write pass must wake the next pass.

use super::*;
use futures::FutureExt;
use tokio_quiche::ApplicationOverQuic;

#[tokio::test]
async fn an_applied_response_event_does_not_wait_for_another_packet() {
    let (resp_tx, resp_rx) = mpsc::channel(RESP_CHANNEL_CAPACITY);
    let mut app = H3App {
        proxy: Arc::new(PingclairProxy::new()),
        connector: Arc::new(pingora_core::connectors::http::Connector::new(None)),
        h3_config: Arc::new(quiche::h3::Config::new().unwrap()),
        h3: None,
        remote_addr: "127.0.0.1:443".parse().unwrap(),
        streams: HashMap::from([(0, StreamState::default())]),
        resp_tx,
        resp_rx,
        deferred: None,
        response_write_pending: false,
        body_notify: Arc::new(Notify::new()),
        tls_identity: None,
        _slot: ConnectionSlot(Arc::new(AtomicUsize::new(1))),
        goaway_from: None,
        last_request_stream: None,
        lingering: Vec::new(),
        open: None,
        close_woken: false,
        pending_headers: crate::h3_header_deadline::PendingHeaders::new(Duration::from_secs(20)),
    };
    let mut transport_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    let mut connection = quiche::connect_with_buffer_factory(
        None,
        &quiche::ConnectionId::from_ref(b"response-wakeup"),
        "127.0.0.1:443".parse().unwrap(),
        "127.0.0.1:444".parse().unwrap(),
        &mut transport_config,
    )
    .unwrap();

    // 🌊 Reproduce the late write-pass dequeue without a packet or a later event.
    app.resp_tx
        .try_send(RespEvent {
            stream_id: 0,
            msg: RespMsg::Body(Bytes::from_static(b"data: 2\n\n"), false),
        })
        .unwrap();
    assert!(app.apply_available_events());
    assert!(app.resp_rx.is_empty());
    assert_eq!(app.streams[&0].pending_body_bytes, 9);
    assert!(
        app.wait_for_data(&mut connection).now_or_never().is_some(),
        "a dequeued body must schedule its write without another network event"
    );

    // 🌊 Consume the wake once; flow-control-blocked bytes must not busy-spin.
    assert!(app.wait_for_data(&mut connection).now_or_never().is_none());
}
