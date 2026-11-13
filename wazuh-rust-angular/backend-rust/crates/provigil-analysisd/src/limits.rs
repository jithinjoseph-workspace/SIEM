//! Events-per-second limit (spec section 2.20): `maximum × timeframe` credits; each decoded
//! message takes one, and the credits taken in a second come back `timeframe` seconds later.

#[derive(Debug, Clone, Default)]
pub struct Limits {
    pub enabled: bool,
    eps: u32,
    timeframe: u32,
    /// The second being counted (0 .. timeframe - 1).
    second: u32,
    /// Credits taken in each of the last `timeframe` seconds.
    taken: Vec<u32>,
    credits: i64,
}

impl Limits {
    /// The limit and the start message (level, text).
    pub fn new(eps: u32, timeframe: u32, maximum_given: bool) -> (Limits, (&'static str, String)) {
        if eps > 0 && timeframe > 0 {
            let l = Limits { enabled: true, eps, timeframe, second: 0, taken: vec![0; timeframe as usize], credits: i64::from(eps) * i64::from(timeframe) };
            (l, ("INFO", format!("EPS limit enabled, EPS: '{eps}', timeframe: '{timeframe}'")))
        } else if !maximum_given && timeframe > 0 {
            (Limits::default(), ("WARNING", "EPS limit disabled. The maximum value is missing in the configuration block.".into()))
        } else {
            (Limits::default(), ("INFO", "EPS limit disabled".into()))
        }
    }

    /// Once a second: once the window is full, the oldest second's credits come back.
    pub fn tick(&mut self) {
        if !self.enabled {
            return;
        }
        if self.second < self.timeframe - 1 {
            self.second += 1;
        } else {
            self.credits += i64::from(self.taken[0]);
            self.taken.rotate_left(1);
            self.taken[self.second as usize] = 0;
        }
    }

    /// Takes a credit; false when none is left (the caller waits for the next tick).
    pub fn take(&mut self) -> bool {
        if !self.enabled {
            return true;
        }
        if self.credits <= 0 {
            return false;
        }
        self.credits -= 1;
        self.taken[self.second as usize] += 1;
        true
    }

    /// (limit reached, credits left).
    pub fn reached(&self) -> (bool, u32) {
        if self.enabled {
            (self.credits <= 0, self.credits.max(0) as u32)
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
        let (mut l, m) = Limits::new(2, 3, true);
        assert_eq!(m.1, "EPS limit enabled, EPS: '2', timeframe: '3'");
        for _ in 0..6 {
            assert!(l.take());
        }
        assert!(!l.take());
        l.tick();
        l.tick();
        assert!(!l.take());
        l.tick();
        assert_eq!(l.reached(), (false, 6));
        assert_eq!(Limits::new(0, 10, false).1 .0, "WARNING");
        assert_eq!(Limits::new(0, 0, false).1 .1, "EPS limit disabled");
    }
}
