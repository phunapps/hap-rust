//! A thin typed-access layer over a caller-supplied request executor.
//!
//! `hap-model` stays transport-agnostic: [`AccessoryDatabase`] does not know
//! about sockets or sessions. The caller provides a [`RequestExecutor`] that
//! actually performs an HTTP request over a secure session; the database turns
//! that into typed `/accessories` and `/characteristics` operations.

use crate::error::Result;
use crate::format::CharValue;
use crate::tree::Accessory;
use crate::{
    build_read_request, build_subscribe_request, build_write_request, parse_accessories,
    parse_read_response,
};

/// One HAP request the executor must perform, described abstractly.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Request {
    /// `GET <path>` (used for `/accessories` and `/characteristics?...`).
    Get {
        /// Request path including any query string.
        path: String,
    },
    /// `PUT /characteristics` with a JSON body.
    Put {
        /// Request path.
        path: String,
        /// Request body bytes.
        body: Vec<u8>,
    },
}

/// Something that can perform a HAP [`Request`] and return the response body.
///
/// M7 implements this over a `SecureSession`; tests implement it in memory.
pub trait RequestExecutor {
    /// Perform `req`, returning the raw response body bytes.
    ///
    /// # Errors
    /// Implementations return a [`crate::ModelError::Executor`] (or map their
    /// own transport error into one) on failure.
    fn execute(&mut self, req: Request) -> Result<Vec<u8>>;
}

/// Typed access to an accessory's attribute database over an executor.
pub struct AccessoryDatabase<E: RequestExecutor> {
    executor: E,
    accessories: Vec<Accessory>,
}

impl<E: RequestExecutor> AccessoryDatabase<E> {
    /// Fetch `/accessories` through `executor` and build the typed tree.
    ///
    /// # Errors
    /// Propagates executor and parse errors.
    pub fn fetch(mut executor: E) -> Result<Self> {
        let body = executor.execute(Request::Get {
            path: "/accessories".to_string(),
        })?;
        let accessories = parse_accessories(&body)?;
        Ok(Self {
            executor,
            accessories,
        })
    }

    /// The cached accessory tree from the last fetch.
    pub fn accessories(&self) -> &[Accessory] {
        &self.accessories
    }

    /// Read the current values of the given `(aid, iid)` characteristics.
    ///
    /// # Errors
    /// Propagates executor and parse errors, including a non-zero per-
    /// characteristic HAP status as [`crate::ModelError::CharacteristicStatus`].
    pub fn read(&mut self, ids: &[(u64, u64)]) -> Result<Vec<((u64, u64), CharValue)>> {
        let path = build_read_request(ids);
        let body = self.executor.execute(Request::Get { path })?;
        parse_read_response(&body)
    }

    /// Write values to characteristics.
    ///
    /// # Errors
    /// Propagates executor errors.
    pub fn write(&mut self, writes: &[((u64, u64), CharValue)]) -> Result<()> {
        let body = build_write_request(writes);
        self.executor.execute(Request::Put {
            path: "/characteristics".to_string(),
            body,
        })?;
        Ok(())
    }

    /// Subscribe or unsubscribe to event notifications for characteristics.
    ///
    /// # Errors
    /// Propagates executor errors.
    pub fn subscribe(&mut self, ids: &[(u64, u64)], enable: bool) -> Result<()> {
        let body = build_subscribe_request(ids, enable);
        self.executor.execute(Request::Put {
            path: "/characteristics".to_string(),
            body,
        })?;
        Ok(())
    }
}
