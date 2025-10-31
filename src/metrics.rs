use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    pub pulls: AtomicU64,
    pub pushes: AtomicU64,
    pub new_funcs: AtomicU64,
    pub queried_funcs: AtomicU64,
    pub active_connections: AtomicU64,
    pub lumina_v0_4: AtomicU64,
    pub lumina_v5p: AtomicU64,
    pub errors: AtomicU64,
    pub timeouts: AtomicU64,
    pub shutting_down: AtomicBool,
}

pub static METRICS: once_cell::sync::Lazy<&'static Metrics> = once_cell::sync::Lazy::new(|| {
    Box::leak(Box::new(Metrics::default()))
});

impl Metrics {
    pub fn render_prometheus(&self) -> String {
        let g = |name: &str, help: &str, val: u64| -> String {
            format!("# HELP {0} {1}\n# TYPE {0} counter\n{0} {2}\n", name, help, val)
        };
        let mut s = String::with_capacity(1024);
        s.push_str(&g("lumen_pulls_total","Number of functions successfully pulled", self.pulls.load(Ordering::Relaxed)));
        s.push_str(&g("lumen_pushes_total","Number of functions pushed", self.pushes.load(Ordering::Relaxed)));
        s.push_str(&g("lumen_new_funcs_total","New unique functions inserted", self.new_funcs.load(Ordering::Relaxed)));
        s.push_str(&g("lumen_queried_funcs_total","Requested function keys", self.queried_funcs.load(Ordering::Relaxed)));
        s.push_str(&g("lumen_active_connections","Active binary RPC connections", self.active_connections.load(Ordering::Relaxed)));
        s.push_str(&g("lumen_lumina_v0_4","Hello protocol versions 0..4", self.lumina_v0_4.load(Ordering::Relaxed)));
        s.push_str(&g("lumen_lumina_v5p","Hello protocol versions >=5", self.lumina_v5p.load(Ordering::Relaxed)));
        s.push_str(&g("lumen_errors_total","Errors", self.errors.load(Ordering::Relaxed)));
        s.push_str(&g("lumen_timeouts_total","Timeouts", self.timeouts.load(Ordering::Relaxed)));
        s
    }
}
