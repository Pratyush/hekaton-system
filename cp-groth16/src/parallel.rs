use ark_std::{boxed::Box, vec::Vec};

pub struct ExecutionPool<'a, T> {
    #[cfg(feature = "parallel")]
    jobs: Vec<Box<dyn 'a + FnOnce() -> T + Send>>,
    #[cfg(not(feature = "parallel"))]
    jobs: Vec<Box<dyn 'a + FnOnce() -> T>>,
}

impl<'a, T> ExecutionPool<'a, T> {
    pub fn new() -> Self {
        Self { jobs: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            jobs: Vec::with_capacity(cap),
        }
    }

    #[cfg(feature = "parallel")]
    pub fn add_job<F: 'a + FnOnce() -> T + Send>(&mut self, f: F) {
        self.jobs.push(Box::new(f));
    }

    #[cfg(not(feature = "parallel"))]
    pub fn add_job<F: 'a + FnOnce() -> T>(&mut self, f: F) {
        self.jobs.push(Box::new(f));
    }

    pub fn execute_all(self) -> Vec<T>
    where
        T: Send + Sync,
    {
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            let task_pool_size =
                (rayon::current_num_threads() as f64 / self.jobs.len() as f64).ceil() as usize;
            execute_with_max_available_threads(|| {
                self.jobs
                    .into_par_iter()
                    .map(|f| execute_with_threads(f, task_pool_size))
                    .collect()
            })
        }
        #[cfg(not(feature = "parallel"))]
        {
            self.jobs.into_iter().map(|f| f()).collect()
        }
    }
}

impl<'a, T> Default for ExecutionPool<'a, T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "parallel")]
pub fn max_available_threads() -> usize {
    rayon::current_num_threads()
}

#[inline(always)]
pub fn execute_with_max_available_threads<T: Sync + Send>(f: impl FnOnce() -> T + Send) -> T {
    #[cfg(feature = "parallel")]
    {
        execute_with_threads(f, max_available_threads())
    }
    #[cfg(not(feature = "parallel"))]
    {
        f()
    }
}

#[cfg(feature = "parallel")]
#[inline(always)]
fn execute_with_threads<T: Sync + Send>(f: impl FnOnce() -> T + Send, num_threads: usize) -> T {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(dbg!(num_threads))
        .build()
        .unwrap();
    pool.install(f)
}
