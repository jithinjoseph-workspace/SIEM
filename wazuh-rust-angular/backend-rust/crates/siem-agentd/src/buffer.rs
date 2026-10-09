//! `client-agent/buffer.c`: the anti-flooding ring buffer between the
//! local event queue and the manager, its NORMAL/WARNING/FULL/FLOOD state
//! machine, the `dispatch_buffer` thread (paced by `events_per_second`),
//! and the resize/free done on configuration reload.

use std::sync::atomic::Ordering;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::sendmsg::send_msg;
use crate::state::Update;
use crate::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Level {
    #[default]
    Normal,
    Warning,
    Full,
    Flood,
}

#[derive(Default)]
struct Inner {
    /// `buffer` (`None` before `buffer_init` / after a free).
    slots: Option<Vec<Option<Vec<u8>>>>,
    /// `agt->buflength` the ring was sized for.
    buflength: usize,
    i: usize,
    j: usize,
    state: Level,
    full: bool,
    warn: bool,
    flood: bool,
    normal: bool,
    start: i64,
}

#[derive(Default)]
pub struct Buffer {
    inner: Mutex<Inner>,
    cond_no_empty: Condvar,
}

impl Inner {
    fn n(&self) -> i64 {
        self.buflength as i64 + 1
    }

    /// `(i - j + buflength + 1) % (buflength + 1) / buflength`
    fn usage(&self) -> f32 {
        let used = ((self.i as i64 - self.j as i64 + self.n()) % self.n()) as f32;
        used / self.buflength.max(1) as f32
    }

    fn is_full(&self) -> bool {
        (self.i + 1) % (self.buflength + 1) == self.j
    }

    fn is_empty(&self) -> bool {
        self.i == self.j
    }
}

fn level(v: &std::sync::atomic::AtomicI32) -> f32 {
    v.load(Ordering::SeqCst) as f32 / 100.0
}

/// `buffer_init`
pub fn buffer_init(ag: &Agentd) {
    {
        let mut b = ag.buffer.inner.lock().unwrap();
        if b.slots.is_none() {
            let len = ag.cfg.read().unwrap().buflength.max(0) as usize;
            b.slots = Some(vec![None; len + 1]);
            b.buflength = len;
        }
    }
    let warn = ag.define_int("agent", "warn_level", 1, 100);
    ag.ints.warn_level.store(warn, Ordering::SeqCst);
    let normal = ag.define_int("agent", "normal_level", 0, warn - 1);
    ag.ints.normal_level.store(normal, Ordering::SeqCst);
    let tolerance = ag.define_int("agent", "tolerance", 0, 600);
    ag.ints.tolerance.store(tolerance, Ordering::SeqCst);
    if tolerance == 0 {
        ag.log.warn(TOLERANCE_TIME);
    }
    ag.log.debug1("Agent buffer created.");
}

/// `buffer_append`
pub fn buffer_append(ag: &Agentd, msg: &[u8]) -> i32 {
    let mut b = ag.buffer.inner.lock().unwrap();
    let warn_level = level(&ag.ints.warn_level);
    match b.state {
        Level::Normal => {
            if b.is_full() {
                b.full = true;
                b.state = Level::Full;
                b.start = now();
            } else if b.usage() >= warn_level {
                b.state = Level::Warning;
                b.warn = true;
            }
        }
        Level::Warning => {
            if b.is_full() {
                b.full = true;
                b.state = Level::Full;
                b.start = now();
            }
        }
        Level::Full => {
            if now() - b.start >= ag.ints.tolerance.load(Ordering::SeqCst) as i64 {
                b.state = Level::Flood;
                b.flood = true;
            }
        }
        Level::Flood => {}
    }
    ag.state.update(Update::IncrementMsgCount);
    if b.is_full() {
        drop(b);
        ag.log.debug2("Unable to store new packet: Buffer is full.");
        return -1;
    }
    let i = b.i;
    let n = b.buflength + 1;
    if let Some(s) = b.slots.as_mut() {
        if i < s.len() {
            s[i] = Some(msg.to_vec());
        }
    }
    b.i = (i + 1) % n;
    ag.buffer.cond_no_empty.notify_one();
    0
}

/// `dispatch_buffer`
pub fn dispatch_buffer(ag: &Agentd) {
    loop {
        let ts0 = Instant::now();
        let mut b = ag.buffer.inner.lock().unwrap();
        while b.is_empty() && ag.buffer_enabled() {
            b = ag.buffer.cond_no_empty.wait(b).unwrap();
        }
        if !ag.buffer_enabled() {
            ag.log.info("Dispatch buffer thread received stop signal. Exiting.");
            break;
        }
        let warn_level = level(&ag.ints.warn_level);
        let normal_level = level(&ag.ints.normal_level);
        match b.state {
            Level::Normal => {}
            Level::Warning => {
                if b.usage() <= normal_level {
                    b.state = Level::Normal;
                    b.normal = true;
                }
            }
            Level::Full | Level::Flood => {
                if b.usage() <= warn_level {
                    b.state = Level::Warning;
                }
                if b.usage() <= normal_level {
                    b.state = Level::Normal;
                    b.normal = true;
                }
            }
        }
        let j = b.j;
        let n = b.buflength + 1;
        let msg_output = b.slots.as_mut().and_then(|s| s.get_mut(j).and_then(Option::take));
        b.j = (j + 1) % n;
        let (warn, full, flood, normal) = (b.warn, b.full, b.flood, b.normal);
        b.warn = false;
        b.full = false;
        b.flood = false;
        b.normal = false;
        drop(b);

        if warn {
            let wl = ag.ints.warn_level.load(Ordering::SeqCst);
            ag.log.warn(format!("Agent buffer at {wl} %."));
            send_msg(ag, agent_event(&format!("wazuh: Agent buffer: '{wl}%'.")).as_bytes());
        }
        if full {
            ag.log.warn(FULL_BUFFER);
            send_msg(ag, agent_event(OS_FULL_BUFFER).as_bytes());
        }
        if flood {
            ag.log.warn(FLOODED_BUFFER);
            send_msg(ag, agent_event(OS_FLOOD_BUFFER).as_bytes());
        }
        if normal {
            let nl = ag.ints.normal_level.load(Ordering::SeqCst);
            ag.log.info(format!("Agent buffer is under {nl} %. Working properly again."));
            send_msg(ag, agent_event(OS_NORMAL_BUFFER).as_bytes());
        }

        siem_ipc::mq_op::os_wait();

        if let Some(m) = msg_output {
            send_msg(ag, &m);
        }

        // delay(): sleep (1 / max_eps) - loop time
        let eps = ag.cfg.read().unwrap().events_persec.max(1) as u64;
        let interval = Duration::from_nanos(1_000_000_000 / eps);
        let spent = ts0.elapsed();
        if spent <= interval {
            std::thread::sleep(interval - spent);
        }
    }
}

/// `w_agentd_get_buffer_lenght`: -1 when the buffer is disabled.
pub fn get_buffer_length(ag: &Agentd) -> i32 {
    if !ag.buffer_enabled() {
        return -1;
    }
    let b = ag.buffer.inner.lock().unwrap();
    let n = b.buflength as i64 + 1;
    let mut r = (b.i as i64 - b.j as i64) % n;
    if r < 0 {
        r += n;
    }
    r as i32
}

/// `w_agentd_buffer_free`
pub fn buffer_free(ag: &Agentd, current_capacity: u32) {
    let mut b = ag.buffer.inner.lock().unwrap();
    if b.slots.is_none() || current_capacity == 0 {
        ag.log.warn("Buffer is already unallocated or invalid. Skipping free operation.");
        return;
    }
    ag.log.debug2("Freeing the client-buffer.");
    b.slots = None;
    b.buflength = 0;
    ag.cfg.write().unwrap().buflength = 0;
    b.i = 0;
    b.j = 0;
    ag.buffer.cond_no_empty.notify_one();
    drop(b);
    ag.log.info("Client buffer freed successfully.");
}

/// `w_agentd_buffer_resize`
pub fn buffer_resize(ag: &Agentd, current_capacity: u32, desired_capacity: u32) -> i32 {
    if desired_capacity == 0 {
        ag.log.error(format!("Invalid new buffer capacity requested: {desired_capacity}."));
        return -1;
    }
    if desired_capacity == current_capacity {
        return 0;
    }
    let count = get_buffer_length(ag);
    if count < 0 {
        ag.log.error("Failed to get buffer length.");
        return -1;
    }
    let mut agent_msg_count = count as u32;
    if agent_msg_count > current_capacity + 1 {
        ag.log.error(format!(
            "Agent message count ({agent_msg_count}) exceeds current buffer capacity ({}).",
            current_capacity + 1
        ));
        return -1;
    }

    let mut b = ag.buffer.inner.lock().unwrap();
    let cur = current_capacity as usize;
    let mut old = b.slots.take().unwrap_or_else(|| vec![None; cur + 1]);
    old.resize(cur + 1, None);
    let mut temp: Vec<Option<Vec<u8>>> = vec![None; desired_capacity as usize + 1];
    let (i, j) = (b.i, b.j);
    if desired_capacity > current_capacity {
        if j < i {
            ag.log.debug2(format!(
                "Copying contiguous data to new buffer. Count: {agent_msg_count} events, tail: {j}, head: {i}\n"
            ));
            for k in 0..agent_msg_count as usize {
                temp[k] = old[j + k].take();
            }
        } else {
            let first_part = (cur - j) + 1;
            ag.log.debug2("Wrapped buffer detected. Copying in two parts:\n");
            ag.log.debug2(format!("  Part 1: {first_part} bytes from old[tail={j}] → new[0]\n"));
            ag.log.debug2(format!("  Part 2: {i} bytes from old[0] → new[{first_part}]\n"));
            for k in 0..first_part {
                temp[k] = old[j + k].take();
            }
            for k in 0..i {
                temp[first_part + k] = old[k].take();
            }
        }
    } else {
        ag.log.warn(format!(
            "Shrinking client buffer from {current_capacity} to {desired_capacity} (messages: {agent_msg_count})."
        ));
        let retained = agent_msg_count.min(desired_capacity);
        for k in 0..retained as usize {
            let old_idx = (j + k) % (cur + 1);
            if let Some(m) = old[old_idx].take() {
                ag.log.debug2(format!("Moving message from old[{old_idx}] to new[{k}] (ptr: {:p})", m.as_ptr()));
                temp[k] = Some(m);
            }
        }
        ag.log.info(format!("Successfully copied {retained} messages to the new buffer."));
        for (idx, slot) in old.iter_mut().enumerate() {
            if let Some(m) = slot.take() {
                ag.log.debug2(format!("Freeing buffer[{idx}] (ptr: {:p})\n", m.as_ptr()));
            }
        }
        agent_msg_count = retained;
        ag.state.update(Update::ResetMsgCountOnShrink(agent_msg_count));
    }
    b.j = 0;
    b.i = agent_msg_count as usize;
    b.slots = Some(temp);
    b.buflength = desired_capacity as usize;
    drop(b);
    ag.log.info(format!("Client buffer resized from {current_capacity} to {desired_capacity} elements."));
    0
}
