use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::RngCore as _;

const ABSOLUTE_SESSION_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug)]
struct Session {
    authorized_shares: HashMap<String, u64>,
    source_ip: IpAddr,
    created_at: Instant,
    last_access_at: Instant,
}

#[derive(Default)]
pub(crate) struct SessionStore {
    sessions: Mutex<HashMap<String, Session>>,
}

impl SessionStore {
    pub fn create_or_authorize(
        &self,
        existing_token: Option<&str>,
        source_ip: IpAddr,
        share_id: &str,
        credential_revision: u64,
        idle_lifetime: Duration,
    ) -> String {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        prune(&mut sessions, idle_lifetime);
        if let Some(token) = existing_token {
            if let Some(session) = sessions.get_mut(token) {
                if session.source_ip == source_ip {
                    session
                        .authorized_shares
                        .insert(share_id.to_string(), credential_revision);
                    session.last_access_at = Instant::now();
                    return token.to_string();
                }
            }
        }
        let token = random_token();
        sessions.insert(
            token.clone(),
            Session {
                authorized_shares: HashMap::from([(share_id.to_string(), credential_revision)]),
                source_ip,
                created_at: Instant::now(),
                last_access_at: Instant::now(),
            },
        );
        token
    }

    pub fn authorized(
        &self,
        token: Option<&str>,
        source_ip: IpAddr,
        share_id: &str,
        credential_revision: u64,
        idle_lifetime: Duration,
    ) -> bool {
        let Some(token) = token else { return false };
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        prune(&mut sessions, idle_lifetime);
        let Some(session) = sessions.get_mut(token) else {
            return false;
        };
        if session.source_ip != source_ip
            || session.authorized_shares.get(share_id) != Some(&credential_revision)
        {
            return false;
        }
        session.last_access_at = Instant::now();
        true
    }

    pub fn lock_share(&self, token: Option<&str>, share_id: &str) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(session) = token.and_then(|token| sessions.get_mut(token)) {
            session.authorized_shares.remove(share_id);
        }
    }

    pub fn logout(&self, token: Option<&str>) {
        if let Some(token) = token {
            self.sessions
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(token);
        }
    }

    pub fn revoke_share(&self, share_id: &str) -> usize {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut revoked = 0;
        for session in sessions.values_mut() {
            if session.authorized_shares.remove(share_id).is_some() {
                revoked += 1;
            }
        }
        revoked
    }

    pub fn revoke_all(&self) -> usize {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let count = sessions.len();
        sessions.clear();
        count
    }

    pub fn len(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len()
    }
}

fn prune(sessions: &mut HashMap<String, Session>, idle_lifetime: Duration) {
    let now = Instant::now();
    sessions.retain(|_, session| {
        now.duration_since(session.created_at) < ABSOLUTE_SESSION_LIFETIME
            && now.duration_since(session.last_access_at) < idle_lifetime
    });
}

fn random_token() -> String {
    let mut random = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut token = String::with_capacity(64);
    for byte in random {
        token.push(HEX[(byte >> 4) as usize] as char);
        token.push(HEX[(byte & 0x0f) as usize] as char);
    }
    token
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_revision_and_source_ip_invalidate_authorization() {
        let store = SessionStore::default();
        let source: IpAddr = "192.168.1.20".parse().unwrap();
        let token =
            store.create_or_authorize(None, source, "share-a", 7, Duration::from_secs(3600));
        assert_eq!(token.len(), 64);
        assert!(store.authorized(
            Some(&token),
            source,
            "share-a",
            7,
            Duration::from_secs(3600),
        ));
        assert!(!store.authorized(
            Some(&token),
            source,
            "share-a",
            8,
            Duration::from_secs(3600),
        ));
        assert!(!store.authorized(
            Some(&token),
            "192.168.1.21".parse().unwrap(),
            "share-a",
            7,
            Duration::from_secs(3600),
        ));
    }
}
