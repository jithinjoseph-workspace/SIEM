//! EPS limits (analysisd/limits.c). The C version is a counting semaphore
//! of credits (`eps * timeframe` at start) that the decoder threads take one
//! by one (`get_eps_credit`, blocking when empty) and a circular buffer of
//! per-second consumption that the main thread rotates every second
//! (`update_limits`), giving back the credits spent `timeframe` seconds ago.
//! Here the semaphore is a plain counter: a consumer that finds no credit
//! waits for the next `update`.

/// Startup message of `load_limits` (level, text).
pub type LimitsMsg = (&'static str, String);

#[derive(Debug, Clone, Default)]
pub struct Limits {
    pub enabled: bool,
    eps: u32,
    timeframe: u32,
    current_cell: u32,
    circ_buf: Vec<u32>,
    credits: i64,
}

impl Limits {
    /// `load_limits`
    pub fn load(eps: u32, timeframe: u32, maximum_found: bool) -> (Self, LimitsMsg) {
        if eps > 0 && timeframe > 0 {
            let l = Limits {
                enabled: true,
                eps,
                timeframe,
                current_cell: 0,
                circ_buf: vec![0; timeframe as usize],
                credits: eps as i64 * timeframe as i64,
            };
            (l, ("INFO", format!("EPS limit enabled, EPS: '{eps}', timeframe: '{timeframe}'")))
        } else if !maximum_found && timeframe > 0 {
            (Limits::default(), ("WARNING", "EPS limit disabled. The maximum value is missing in the configuration block.".into()))
        } else {
            (Limits::default(), ("INFO", "EPS limit disabled".into()))
        }
    }

    /// `update_limits` (once per second).
    pub fn update(&mut self) {
        if !self.enabled {
            return;
        }
        if self.current_cell < self.timeframe - 1 {
            self.current_cell += 1;
        } else {
            // generate_eps_credits(circ_buf[0])
            self.credits += self.circ_buf[0] as i64;
            self.circ_buf.rotate_left(1);
            self.circ_buf[self.current_cell as usize] = 0;
        }
    }

    /// `get_eps_credit` without blocking: false when the caller has to wait.
    pub fn try_credit(&mut self) -> bool {
        if !self.enabled {
            return true;
        }
        if self.credits <= 0 {
            return false;
        }
        self.credits -= 1;
        // increase_event_counter
        self.circ_buf[self.current_cell as usize] += 1;
        true
    }

    /// `limit_reached`: (reached, available credits).
    pub fn limit_reached(&self) -> (bool, u32) {
        if self.enabled {
            let c = self.credits.max(0) as u32;
            (self.credits <= 0, c)
        } else {
            (false, 0)
        }
    }

    pub fn eps(&self) -> u32 {
        self.eps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credits_come_back_after_the_timeframe() {
        let (mut l, m) = Limits::load(2, 3, true);
        assert_eq!(m.1, "EPS limit enabled, EPS: '2', timeframe: '3'");
        for _ in 0..6 {
            assert!(l.try_credit());
        }
        assert!(!l.try_credit());
        assert_eq!(l.limit_reached(), (true, 0));
        l.update(); // cell 1
        l.update(); // cell 2
        assert!(!l.try_credit());
        l.update(); // cell 0's 6 credits return
        assert_eq!(l.limit_reached(), (false, 6));
    }

    #[test]
    fn disabled_messages() {
        assert_eq!(Limits::load(0, 10, false).1 .0, "WARNING");
        assert_eq!(Limits::load(0, 0, false).1 .1, "EPS limit disabled");
        assert!(Limits::load(0, 10, true).0.try_credit());
    }
}
