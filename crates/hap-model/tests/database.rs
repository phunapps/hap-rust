//! `AccessoryDatabase` against a fake in-memory executor — no network.

// Test-code carve-out: unwrap/expect allowed with this documented justification.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use hap_model::{
    AccessoryDatabase, CharValue, CharacteristicType, Request, RequestExecutor, Result,
};

/// Records every request and replies from a scripted table.
struct FakeExecutor {
    seen: Vec<Request>,
}

impl RequestExecutor for FakeExecutor {
    fn execute(&mut self, req: Request) -> Result<Vec<u8>> {
        self.seen.push(req.clone());
        let reply: &[u8] = match &req {
            Request::Get { path } if path == "/accessories" => br#"{"accessories":[{"aid":1,
                "services":[{"iid":7,"type":"43","characteristics":[
                    {"iid":8,"type":"25","format":"bool","perms":["pr","pw","ev"],"value":false}
                ]}]}]}"#,
            Request::Get { path } if path.starts_with("/characteristics") => {
                br#"{"characteristics":[{"aid":1,"iid":8,"value":true,"format":"bool"}]}"#
            }
            Request::Put { .. } => br#"{"characteristics":[]}"#,
            other => panic!("unexpected request {other:?}"),
        };
        Ok(reply.to_vec())
    }
}

#[test]
fn fetch_read_write_subscribe_over_fake_executor() {
    let mut db = AccessoryDatabase::fetch(FakeExecutor { seen: Vec::new() }).unwrap();
    assert_eq!(db.accessories()[0].aid, 1);
    assert_eq!(
        db.accessories()[0].services[0].characteristics[0].char_type,
        CharacteristicType::On
    );

    let read = db.read(&[(1, 8)]).unwrap();
    assert_eq!(read, vec![((1, 8), CharValue::Bool(true))]);

    db.write(&[((1, 8), CharValue::Bool(true))]).unwrap();
    db.subscribe(&[(1, 8)], true).unwrap();
}
