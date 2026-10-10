//! Deterministic PRNG (SplitMix64). All randomised search goes through this so
//! a run is reproducible from its recorded seed.

#[derive(Debug, Clone)]
pub struct Rng {
    state: u64,
    seed: u64,
}

/// Default seed: fixed, so runs are reproducible unless `--seed` says otherwise.
pub const DEFAULT_SEED: u64 = 1337;

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed, seed }
    }
    pub fn seed(&self) -> u64 {
        self.seed
    }
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform index in `0..n` (n > 0).
    pub fn below(&mut self, n: usize) -> usize {
        debug_assert!(n > 0);
        (self.next_u64() % n as u64) as usize
    }
    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> Option<&'a T> {
        if xs.is_empty() { None } else { xs.get(self.below(xs.len())) }
    }
    pub fn range_i64(&mut self, lo: i64, hi: i64) -> i64 {
        let span = (hi - lo + 1).max(1) as u64;
        lo + (self.next_u64() % span) as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic() {
        let a: Vec<u64> = {
            let mut r = Rng::new(42);
            (0..5).map(|_| r.next_u64()).collect()
        };
        let b: Vec<u64> = {
            let mut r = Rng::new(42);
            (0..5).map(|_| r.next_u64()).collect()
        };
        assert_eq!(a, b);
    }
}
