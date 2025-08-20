use candid::CandidType;
use ciborium::{from_reader, into_writer};
use ic_canister_sig_creation::{
    signature_map::{CanisterSigInputs, SignatureMap, LABEL_SIG},
    DELEGATION_SIG_DOMAIN,
};
use ic_cdk::api::certified_data_set;
use ic_certification::labeled_hash;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl, StableCell,
};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;

type Memory = VirtualMemory<DefaultMemoryImpl>;

#[derive(CandidType, Clone, Default, Deserialize, Serialize)]
pub struct State {
    pub name: String,
    pub session_expires_in_ms: u64,
    pub sign_in_count: u64,
}

const STATE_MEMORY_ID: MemoryId = MemoryId::new(0);

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
    static SIGNATURES : RefCell<SignatureMap> = RefCell::new(SignatureMap::default());


    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static STATE_STORE: RefCell<StableCell<Vec<u8>, Memory>> = RefCell::new(
        StableCell::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(STATE_MEMORY_ID)),
            Vec::new()
        )
    );
}

pub mod state {
    use super::*;

    pub fn with<R>(f: impl FnOnce(&State) -> R) -> R {
        STATE.with_borrow(f)
    }

    pub fn with_mut<R>(f: impl FnOnce(&mut State) -> R) -> R {
        STATE.with_borrow_mut(f)
    }

    pub fn load() {
        STATE_STORE.with(|r| {
            STATE.with(|h| {
                let v: State =
                    from_reader(&r.borrow().get()[..]).expect("failed to decode STATE_STORE data");
                *h.borrow_mut() = v;
            });
        });
    }

    pub fn save() {
        STATE.with(|h| {
            STATE_STORE.with(|r| {
                let mut buf = vec![];
                into_writer(&(*h.borrow()), &mut buf).expect("failed to encode STATE_STORE data");
                r.borrow_mut().set(buf);
            });
        });
    }

    pub fn add_signature(seed: &[u8], message: &[u8]) {
        SIGNATURES.with_borrow_mut(|sigs| {
            let sig_inputs = CanisterSigInputs {
                domain: DELEGATION_SIG_DOMAIN,
                seed,
                message,
            };
            sigs.add_signature(&sig_inputs);

            certified_data_set(labeled_hash(LABEL_SIG, &sigs.root_hash()));
        });
    }

    pub fn get_signature(seed: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
        SIGNATURES.with_borrow(|sigs| {
            let sig_inputs = CanisterSigInputs {
                domain: DELEGATION_SIG_DOMAIN,
                seed,
                message,
            };
            sigs.get_signature_as_cbor(&sig_inputs, None)
                .map_err(|err| format!("failed to get signature: {:?}", err))
        })
    }
}
