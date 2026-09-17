//! Bounded, per-client admission. Waiting for one client never reserves global I/O.
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const CLIENT_CAPACITY: usize = 1024;
const CLIENT_IDLE: Duration = Duration::from_secs(300);
const WAIT_TIMEOUT: Duration = Duration::from_secs(5);

struct ClientLimit {
    streams: Arc<Semaphore>,
    requests: Arc<Semaphore>,
}

struct Entry {
    limit: Arc<ClientLimit>,
    accessed: Instant,
}

pub(crate) struct StreamAdmission {
    global: Arc<Semaphore>,
    clients: Mutex<HashMap<IpAddr, Entry>>,
}

pub(crate) struct StreamPermit {
    _client: Arc<ClientLimit>,
    _request: OwnedSemaphorePermit,
    _stream: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}

impl Default for StreamAdmission {
    fn default() -> Self {
        Self {
            global: Arc::new(Semaphore::new(16)),
            clients: Mutex::new(HashMap::new()),
        }
    }
}

impl StreamAdmission {
    fn client(&self, ip: IpAddr) -> Result<Arc<ClientLimit>, &'static str> {
        let now = Instant::now();
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = clients.get_mut(&ip) {
            entry.accessed = now;
            return Ok(entry.limit.clone());
        }
        // Reclaim idle entries on insertion; live/waiting permits retain their
        // entry so an IP can never acquire a second independent semaphore.
        clients.retain(|_, entry| {
            Arc::strong_count(&entry.limit) > 1 || now.duration_since(entry.accessed) < CLIENT_IDLE
        });
        if clients.len() >= CLIENT_CAPACITY {
            let oldest = clients
                .iter()
                .filter(|(_, e)| Arc::strong_count(&e.limit) == 1)
                .min_by_key(|(_, e)| e.accessed)
                .map(|(ip, _)| *ip);
            if let Some(ip) = oldest {
                clients.remove(&ip);
            } else {
                return Err("too many active clients; try again later");
            }
        }
        let limit = Arc::new(ClientLimit {
            streams: Arc::new(Semaphore::new(4)),
            requests: Arc::new(Semaphore::new(16)),
        });
        clients.insert(
            ip,
            Entry {
                limit: limit.clone(),
                accessed: now,
            },
        );
        Ok(limit)
    }

    pub async fn acquire(&self, ip: IpAddr) -> Result<StreamPermit, &'static str> {
        self.acquire_with_timeout(ip, WAIT_TIMEOUT).await
    }

    async fn acquire_with_timeout(
        &self,
        ip: IpAddr,
        timeout: Duration,
    ) -> Result<StreamPermit, &'static str> {
        let client = self.client(ip)?;
        let request = client
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| "too many pending requests from this client")?;
        tokio::time::timeout(timeout, async {
            let stream = client
                .streams
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| "gateway stopped")?;
            let global = self
                .global
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| "gateway stopped")?;
            Ok(StreamPermit {
                _client: client,
                _request: request,
                _stream: stream,
                _global: global,
            })
        })
        .await
        .map_err(|_| "download queue timed out; try again later")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_construction_requires_no_runtime() {
        let admission = StreamAdmission::default();
        assert_eq!(admission.global.available_permits(), 16);
    }

    #[tokio::test]
    async fn a_slow_client_cannot_reserve_other_clients_global_slots() {
        let admission = Arc::new(StreamAdmission::default());
        let first: IpAddr = "192.168.1.2".parse().unwrap();
        let second: IpAddr = "192.168.1.3".parse().unwrap();
        let mut active = Vec::new();
        for _ in 0..4 {
            active.push(admission.acquire(first).await.unwrap());
        }
        let mut waiting = Vec::new();
        for _ in 0..12 {
            let admission = admission.clone();
            waiting.push(tokio::spawn(async move { admission.acquire(first).await }));
        }
        tokio::task::yield_now().await;
        let other = admission
            .acquire_with_timeout(second, Duration::from_millis(100))
            .await
            .unwrap();
        assert_eq!(admission.global.available_permits(), 11);
        for task in waiting {
            task.abort();
        }
        drop((active, other));
    }

    #[tokio::test]
    async fn timed_out_waiters_release_their_request_slots() {
        let admission = StreamAdmission::default();
        let ip = "192.168.1.2".parse().unwrap();
        let mut permits = Vec::new();
        for _ in 0..4 {
            permits.push(admission.acquire(ip).await.unwrap());
        }
        assert!(admission
            .acquire_with_timeout(ip, Duration::from_millis(1))
            .await
            .is_err());
        assert_eq!(
            admission.client(ip).unwrap().requests.available_permits(),
            12
        );
        drop(permits);
        assert!(admission.acquire(ip).await.is_ok());
    }

    #[test]
    fn client_registry_is_bounded_and_retains_live_clients() {
        let admission = StreamAdmission::default();
        let live_ip = IpAddr::from([10, 0, 0, 1]);
        let live = admission.client(live_ip).unwrap();
        for index in 2..CLIENT_CAPACITY + 20 {
            admission
                .client(IpAddr::from([
                    10,
                    0,
                    (index / 256) as u8,
                    (index % 256) as u8,
                ]))
                .unwrap();
        }
        assert_eq!(admission.clients.lock().unwrap().len(), CLIENT_CAPACITY);
        assert!(Arc::ptr_eq(&live, &admission.client(live_ip).unwrap()));
        let old_ip = IpAddr::from([10, 0, 0, 2]);
        admission.client(old_ip).unwrap();
        admission
            .clients
            .lock()
            .unwrap()
            .get_mut(&old_ip)
            .unwrap()
            .accessed -= CLIENT_IDLE;
        admission.client(IpAddr::from([192, 168, 1, 1])).unwrap();
        assert!(!admission.clients.lock().unwrap().contains_key(&old_ip));
    }
}
