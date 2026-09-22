// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 📝 Bounded access-log batches, flushed on size, age, rotation, or a barrier.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime};

use crossbeam_queue::ArrayQueue;

use super::{
    LogRotation, LogSink, LogWriter, MAX_REUSABLE_LINE_BYTES, WriterMessage, current_size, rotate,
    should_rotate,
};

// 📦 One batch has a byte ceiling and an independent deadline. A continuous
// stream must not postpone that deadline.
const BATCH_BYTES: usize = 64 * 1024;
const FLUSH_INTERVAL: Duration = Duration::from_millis(5);

fn registry() -> &'static Mutex<Vec<Weak<LogWriter>>> {
    static WRITERS: OnceLock<Mutex<Vec<Weak<LogWriter>>>> = OnceLock::new();
    WRITERS.get_or_init(|| Mutex::new(Vec::new()))
}

pub(super) fn register(writer: &Arc<LogWriter>) {
    let mut writers = registry().lock().unwrap_or_else(|e| e.into_inner());
    writers.retain(|writer| writer.strong_count() > 0);
    writers.push(Arc::downgrade(writer));
}

/// 🚿 Drain records accepted before each barrier, within one shutdown budget.
///
/// Called off the request path before process exit. A blocked sink must not
/// hang shutdown; `false` reports an incomplete drain. This does not wait for
/// requests still executing or make file writes durable against power loss.
///
/// 🚫 Every writer is offered a barrier even after one of them fails. Stopping
/// at the first failure would not drain the writers behind it late — it would
/// skip them, and the records their queues still held would be lost without a
/// write ever being attempted for them. One deadline is shared by the whole
/// drain, so a stalled sink still bounds how long shutdown can take.
pub fn flush_all(timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let writers: Vec<_> = registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter_map(Weak::upgrade)
        .collect();
    let mut complete = true;
    for writer in &writers {
        if !flush_writer(writer, deadline) {
            complete = false;
        }
    }
    complete
}

fn flush_writer(writer: &LogWriter, deadline: Instant) -> bool {
    let (ack, wait) = std::sync::mpsc::sync_channel(1);
    let mut message = WriterMessage::Flush(ack);
    loop {
        match writer.queue.try_send(message) {
            Ok(()) => break,
            Err(TrySendError::Full(returned)) => {
                if Instant::now() >= deadline {
                    return false;
                }
                message = returned;
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(TrySendError::Disconnected(_)) => return false,
        }
    }
    if wait
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .is_err()
    {
        return false;
    }
    true
}

pub(super) fn run(
    receiver: Receiver<WriterMessage>,
    sink: LogSink,
    rotation: LogRotation,
    path: Option<PathBuf>,
    buffers: Arc<ArrayQueue<String>>,
) {
    let rotating = rotation.is_enabled();
    let mut written = if rotating {
        path.as_ref().and_then(|p| current_size(p)).unwrap_or(0)
    } else {
        0
    };
    let mut opened_at = SystemTime::now();
    let mut batch = Vec::with_capacity(BATCH_BYTES);
    let mut deadline = Instant::now();

    loop {
        let message = match receiver.try_recv() {
            Ok(message) => message,
            Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {
                flush(&sink, &mut batch);
                match receiver.recv() {
                    Ok(message) => {
                        // 💤 Coalesce arrivals only after an idle queue. Waiting
                        // on the channel for each line would wake this thread
                        // for every request even though writes are buffered.
                        // A backlog drains immediately, without a per-batch nap
                        // that would impose a fixed throughput ceiling.
                        if matches!(message, WriterMessage::Line(_)) {
                            std::thread::sleep(FLUSH_INTERVAL);
                        }
                        message
                    }
                    Err(_) => break,
                }
            }
        };

        match message {
            WriterMessage::Line(line) => {
                if let (Some(path), LogSink::File(handle), true) = (path.as_ref(), &sink, rotating)
                    && should_rotate(&rotation, written, opened_at)
                {
                    // 🔄 Pending lines belong to the old inode. Rotate only
                    // after writing them, retaining the existing per-line limit.
                    flush(&sink, &mut batch);
                    if rotate(handle, path, &rotation).is_some() {
                        written = 0;
                        opened_at = SystemTime::now();
                    }
                }
                written += line.len() as u64 + 1;
                if batch.len() + line.len() + 1 > BATCH_BYTES {
                    flush(&sink, &mut batch);
                }
                if line.len() >= BATCH_BYTES {
                    // 🧱 An oversized existing record bypasses the fixed batch;
                    // it must not permanently enlarge its reusable allocation.
                    let mut line = line;
                    line.push('\n');
                    write(&sink, line.as_bytes());
                    continue;
                }
                if batch.is_empty() {
                    deadline = Instant::now() + FLUSH_INTERVAL;
                }
                batch.extend_from_slice(line.as_bytes());
                batch.push(b'\n');
                recycle(&buffers, line);
                if batch.len() == BATCH_BYTES {
                    flush(&sink, &mut batch);
                }
            }
            WriterMessage::Flush(ack) => {
                flush(&sink, &mut batch);
                let _ = ack.send(());
            }
        }
        // ⏱️ A continuously ready queue must not postpone a partial flush.
        if !batch.is_empty() && Instant::now() >= deadline {
            flush(&sink, &mut batch);
        }
    }
    flush(&sink, &mut batch);
}

fn recycle(buffers: &ArrayQueue<String>, mut line: String) {
    if line.capacity() > MAX_REUSABLE_LINE_BYTES {
        return;
    }
    line.clear();
    let _ = buffers.push(line);
}

fn flush(sink: &LogSink, batch: &mut Vec<u8>) {
    if !batch.is_empty() {
        write(sink, batch);
        batch.clear();
    }
}

fn write(sink: &LogSink, batch: &[u8]) {
    if let Err(error) = sink.write_batch(batch) {
        // 🚫 Do not retry partial writes: replaying the batch duplicates records.
        tracing::warn!(error = %error, "⚠️ Failed to write access log batch");
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::sync::{Arc, Mutex, mpsc};

    use super::*;

    #[test]
    fn shutdown_barrier_drains_live_writers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let sink = LogSink::File(Arc::new(Mutex::new(File::create(&path).unwrap())));
        let writer = LogWriter::spawn(sink, 16);
        writer.submit("accepted before shutdown".into());
        assert!(flush_writer(
            &writer,
            Instant::now() + Duration::from_secs(2)
        ));
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            "accepted before shutdown\n"
        );
    }

    #[test]
    fn shutdown_budget_bounds_a_stalled_queue() {
        let (queue, _receive) = mpsc::sync_channel(1);
        let writer = Arc::new(LogWriter {
            queue,
            buffers: Arc::new(ArrayQueue::new(1)),
            dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        });
        writer.submit("blocked".into());
        let start = Instant::now();
        assert!(!flush_writer(
            &writer,
            Instant::now() + Duration::from_millis(10)
        ));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    /// 🚫 A writer that fails must not cost the writers behind it their
    /// barrier. Skipping them is not a late drain, it is a lost one, and the
    /// `false` the drain returns says only that it did not complete.
    #[test]
    fn a_failed_writer_does_not_cost_the_next_one_its_barrier() {
        // 🧱 The first sink is stalled past the budget: its queue is full and
        // nothing consumes it, so no barrier can ever be delivered to it.
        let (stalled_queue, _stalled_receive) = mpsc::sync_channel(1);
        let stalled = Arc::new(LogWriter {
            queue: stalled_queue,
            buffers: Arc::new(ArrayQueue::new(1)),
            dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        });
        stalled.submit("blocked".into());
        register(&stalled);

        // 📝 The second sink still holds a record. This test plays its writer
        // thread, so the only thing that can drain that record is a barrier
        // reaching this end of the queue.
        let (queue, receive) = mpsc::sync_channel(4);
        let held = Arc::new(LogWriter {
            queue,
            buffers: Arc::new(ArrayQueue::new(4)),
            dropped: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        });
        held.submit("held until the barrier".into());
        register(&held);

        assert!(
            !flush_all(Duration::from_millis(20)),
            "a stalled sink must still report the drain as incomplete"
        );
        assert!(matches!(
            receive.try_recv(),
            Ok(WriterMessage::Line(line)) if line == "held until the barrier"
        ));
        assert!(
            matches!(receive.try_recv(), Ok(WriterMessage::Flush(_))),
            "the writer behind a failed one never received a barrier"
        );
    }

    #[test]
    fn barrier_preserves_lines_across_batch_and_oversized_boundaries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let sink = LogSink::File(Arc::new(Mutex::new(File::create(&path).unwrap())));
        let (send, receive) = mpsc::sync_channel(16);
        let lines = [
            "first".into(),
            "x".repeat(BATCH_BYTES - 1),
            "y".repeat(BATCH_BYTES + 1),
            "last".into(),
        ];
        for line in &lines {
            send.send(WriterMessage::Line(line.clone())).unwrap();
        }
        let (ack, wait) = mpsc::sync_channel(1);
        send.send(WriterMessage::Flush(ack)).unwrap();
        let buffers = Arc::new(ArrayQueue::new(16));
        let thread =
            std::thread::spawn(move || run(receive, sink, LogRotation::default(), None, buffers));
        wait.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            lines.join("\n") + "\n"
        );
        drop(send);
        thread.join().unwrap();
    }

    #[test]
    fn disconnect_drains_the_last_partial_batch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let sink = LogSink::File(Arc::new(Mutex::new(File::create(&path).unwrap())));
        let (send, receive) = mpsc::sync_channel(4);
        send.send(WriterMessage::Line("tail".into())).unwrap();
        drop(send);
        run(
            receive,
            sink,
            LogRotation::default(),
            None,
            Arc::new(ArrayQueue::new(4)),
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), "tail\n");
    }

    #[test]
    fn idle_record_flushes_without_another_event_or_barrier() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let sink = LogSink::File(Arc::new(Mutex::new(File::create(&path).unwrap())));
        let (send, receive) = mpsc::sync_channel(4);
        let buffers = Arc::new(ArrayQueue::new(4));
        let thread =
            std::thread::spawn(move || run(receive, sink, LogRotation::default(), None, buffers));
        send.send(WriterMessage::Line("idle".into())).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while std::fs::read_to_string(&path).unwrap() != "idle\n" {
            assert!(Instant::now() < deadline, "idle record never flushed");
            std::thread::sleep(FLUSH_INTERVAL);
        }
        drop(send);
        thread.join().unwrap();
    }

    /// ♻️ A completed record returns its allocation to the request side, so a
    /// steady stream does not call the allocator once per request.
    #[test]
    fn completed_lines_return_their_buffer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let sink = LogSink::File(Arc::new(Mutex::new(File::create(path).unwrap())));
        let writer = LogWriter::spawn(sink, 4);
        let mut line = String::with_capacity(1_024);
        line.push_str("reusable");

        writer.submit(line);
        writer.flush();

        let returned = writer.take_buffer(0);
        assert!(returned.capacity() >= 1_024);
        assert!(returned.is_empty());
    }
}
