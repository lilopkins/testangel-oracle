use std::sync::Mutex;

use lazy_static::lazy_static;
use testangel_engine::*;
use thiserror::Error;

#[derive(Default)]
struct State {
}

#[derive(Error, Debug)]
pub enum EngineError {

}

lazy_static! {
    static ref ENGINE: Mutex<Engine<'static, Mutex<State>>> = Mutex::new(
        Engine::new("Oracle SQL", env!("CARGO_PKG_VERSION"))
    );
}

expose_engine!(ENGINE);
