//! Multi-threaded offline password recovery for FRITZ!Box configuration backups.
//!
//! Uses dictionary / wordlist attacks against the pre-parsed encryption key
//! header (`Password=$$$$...`).

use std::{
    fs::File,
    io::{self, BufRead, BufReader},
    num::NonZeroUsize,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use crate::crypto::PasswordTester;

const BATCH_SIZE: usize = 2048;

/// Statistics returned after running a dictionary recovery.
#[derive(Debug, Clone)]
pub struct CrackStats {
    pub candidates_tested: u64,
    pub elapsed: Duration,
    pub found: Option<String>,
}

/// Recovers the backup password from a wordlist reader using multi-threading.
///
/// If `thread_count` is `None`, defaults to the number of available CPU cores.
#[must_use]
pub fn crack_wordlist<R: BufRead>(
    tester: &PasswordTester,
    mut reader: R,
    thread_count: Option<usize>,
    mut progress_callback: Option<&mut dyn FnMut(u64, Duration)>,
) -> CrackStats {
    let start_time = Instant::now();
    let num_threads = thread_count
        .unwrap_or_else(|| thread::available_parallelism().map_or(4, NonZeroUsize::get))
        .max(1);

    let tester = Arc::new(tester.clone());
    let found_flag = Arc::new(AtomicBool::new(false));
    let tested_counter = Arc::new(AtomicU64::new(0));

    let (batch_tx, batch_rx) = mpsc::sync_channel::<Vec<String>>(num_threads * 2);
    let (result_tx, result_rx) = mpsc::channel::<String>();
    let work_rx = Arc::new(Mutex::new(batch_rx));

    thread::scope(|s| {
        for _ in 0..num_threads {
            let tester = Arc::clone(&tester);
            let found_flag = Arc::clone(&found_flag);
            let tested_counter = Arc::clone(&tested_counter);
            let work_rx = Arc::clone(&work_rx);
            let result_tx = result_tx.clone();

            s.spawn(move || loop {
                if found_flag.load(Ordering::Relaxed) {
                    break;
                }
                let batch = {
                    let Ok(rx) = work_rx.lock() else { break };
                    match rx.recv() {
                        Ok(b) => b,
                        Err(_) => break,
                    }
                };
                for candidate in &batch {
                    if found_flag.load(Ordering::Relaxed) {
                        break;
                    }
                    if tester.test(candidate) {
                        found_flag.store(true, Ordering::Relaxed);
                        let _ = result_tx.send(candidate.clone());
                        break;
                    }
                }
                tested_counter.fetch_add(
                    u64::try_from(batch.len()).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );
            });
        }

        drop(result_tx);

        let mut byte_buf = Vec::new();
        let mut batch = Vec::with_capacity(BATCH_SIZE);
        let mut last_progress = Instant::now();

        while !found_flag.load(Ordering::Relaxed) {
            match reader.read_until(b'\n', &mut byte_buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    while byte_buf.last() == Some(&b'\n') || byte_buf.last() == Some(&b'\r') {
                        byte_buf.pop();
                    }
                    let candidate = match std::str::from_utf8(&byte_buf) {
                        Ok(s) => s.to_string(),
                        Err(_) => encoding_rs::WINDOWS_1252.decode(&byte_buf).0.into_owned(),
                    };
                    batch.push(candidate);
                    byte_buf.clear();

                    if batch.len() >= BATCH_SIZE {
                        let to_send = std::mem::replace(&mut batch, Vec::with_capacity(BATCH_SIZE));
                        if batch_tx.send(to_send).is_err() {
                            break;
                        }

                        if last_progress.elapsed() >= Duration::from_millis(250) {
                            if let Some(cb) = progress_callback.as_deref_mut() {
                                cb(tested_counter.load(Ordering::Relaxed), start_time.elapsed());
                            }
                            last_progress = Instant::now();
                        }
                    }
                }
            }
        }

        if !batch.is_empty() && !found_flag.load(Ordering::Relaxed) {
            let _ = batch_tx.send(batch);
        }
        drop(batch_tx);
    });

    let found = result_rx.try_recv().ok();
    let final_count = tested_counter.load(Ordering::Relaxed);
    if let Some(cb) = progress_callback {
        cb(final_count, start_time.elapsed());
    }

    CrackStats {
        candidates_tested: final_count,
        elapsed: start_time.elapsed(),
        found,
    }
}

/// Recovers the backup password from a wordlist file on disk.
///
/// # Errors
/// Returns an I/O error if the file cannot be opened.
pub fn crack_file<P: AsRef<Path>>(
    tester: &PasswordTester,
    path: P,
    thread_count: Option<usize>,
    progress_callback: Option<&mut dyn FnMut(u64, Duration)>,
) -> io::Result<CrackStats> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    Ok(crack_wordlist(
        tester,
        reader,
        thread_count,
        progress_callback,
    ))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::crypto::{
        encrypt_encryption_key, generate_boostrap_key, generate_random_encryption_key,
    };

    #[test]
    fn test_crack_wordlist_success() {
        let random_key = generate_random_encryption_key();
        let target_password = "correct_horse_battery_staple";
        let bootstrap_key = generate_boostrap_key(target_password);
        let encrypted_key = encrypt_encryption_key(random_key, bootstrap_key).unwrap();

        let tester = PasswordTester::new(&encrypted_key).unwrap();
        let wordlist_data = "admin\n123456\npassword\ncorrect_horse_battery_staple\nqwerty\n";
        let stats = crack_wordlist(&tester, Cursor::new(wordlist_data), Some(2), None);

        assert_eq!(stats.found.as_deref(), Some(target_password));
        assert!(stats.candidates_tested >= 4);
    }

    #[test]
    fn test_crack_wordlist_not_found() {
        let random_key = generate_random_encryption_key();
        let target_password = "unfindable_password";
        let bootstrap_key = generate_boostrap_key(target_password);
        let encrypted_key = encrypt_encryption_key(random_key, bootstrap_key).unwrap();

        let tester = PasswordTester::new(&encrypted_key).unwrap();
        let wordlist_data = "admin\n123456\npassword\nqwerty\n";
        let stats = crack_wordlist(&tester, Cursor::new(wordlist_data), Some(1), None);

        assert_eq!(stats.found, None);
        assert_eq!(stats.candidates_tested, 4);
    }
}
