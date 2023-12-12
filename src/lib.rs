use std::sync::Mutex;

use lazy_static::lazy_static;
use oracle::{sql_type::ToSql, Connection};
use testangel_engine::*;
use thiserror::Error;

#[derive(Default)]
struct State {
    conn: Option<Connection>,
    params: Vec<SqlValue>,
}

#[derive(Clone)]
enum SqlValue {
    String(String),
    Integer(i64),
    Boolean(bool),
}

#[derive(Error, Debug)]
pub enum EngineError {
    #[error("The state was poisoned critically.")]
    PoisonedState,
    #[error("An oracle error occurred: {0}")]
    Oracle(#[from] oracle::Error),
    #[error("A dangerous query was submitted and allow dangerous wasn't enabled.")]
    DangerousQuery,
    #[error("A query was made but a connection doens't exist")]
    NotYetConnected,
}

lazy_static! {
    static ref ENGINE: Mutex<Engine<'static, Mutex<State>>> = Mutex::new(
        Engine::new("Oracle SQL", env!("CARGO_PKG_VERSION"))
        /* Connect */
        .with_instruction(
            Instruction::new("oracle-connect", "Connect", "Connect to an Oracle SQL server.")
                .with_parameter("username", "Username", ParameterKind::String)
                .with_parameter("password", "Password", ParameterKind::String)
                .with_parameter("connect_string", "Connection String", ParameterKind::String),
            |state: &mut Mutex<State>, params, _output, _evidence| {
                let state = state.get_mut().map_err(|_| EngineError::PoisonedState)?;

                let username = params["username"].value_string();
                let password = params["password"].value_string();
                let connect_string = params["connect_string"].value_string();

                state.conn = Some(Connection::connect(username, password, connect_string)?);
                Ok(())
            }
        )

        /* Add Parameters */
        .with_instruction(
            Instruction::new("oracle-query-add-parameter-string", "Add Query Parameter: String", "Add a parameter to be used later in a query.")
                .with_parameter("sql_param", "Parameter Value", ParameterKind::String),
            |state: &mut Mutex<State>, params, _output, _evidence| {
                let state = state.get_mut().map_err(|_| EngineError::PoisonedState)?;

                let sql_param = params["sql_param"].value_string();

                state.params.push(SqlValue::String(sql_param));
                Ok(())
            }
        )
        .with_instruction(
            Instruction::new("oracle-query-add-parameter-integer", "Add Query Parameter: Integer", "Add a parameter to be used later in a query.")
                .with_parameter("sql_param", "Parameter Value", ParameterKind::Integer),
            |state: &mut Mutex<State>, params, _output, _evidence| {
                let state = state.get_mut().map_err(|_| EngineError::PoisonedState)?;

                let sql_param = params["sql_param"].value_i32();

                state.params.push(SqlValue::Integer(sql_param as i64));
                Ok(())
            }
        )
        .with_instruction(
            Instruction::new("oracle-query-add-parameter-boolean", "Add Query Parameter: Boolean", "Add a parameter to be used later in a query.")
                .with_parameter("sql_param", "Parameter Value", ParameterKind::Boolean),
            |state: &mut Mutex<State>, params, _output, _evidence| {
                let state = state.get_mut().map_err(|_| EngineError::PoisonedState)?;

                let sql_param = params["sql_param"].value_bool();

                state.params.push(SqlValue::Boolean(sql_param));
                Ok(())
            }
        )

        /* Run Query */
        .with_instruction(
            Instruction::new("oracle-query", "Execute Query", "Execute a query. If the query contains dangerous words, you must allow dangerous queries.")
                .with_parameter("query", "Query", ParameterKind::String)
                .with_parameter("dangerous", "Allow Dangerous Queries", ParameterKind::Boolean),
            |state: &mut Mutex<State>, params, _output, evidence| {
                let state = state.get_mut().map_err(|_| EngineError::PoisonedState)?;

                let danger_queries = ["truncate", "delete", "drop"];

                let query = params["query"].value_string();
                let danger_allowed = params["dangerous"].value_bool();

                if !danger_allowed {
                    for word in query.split(' ') {
                        let word = word.trim();
                        if danger_queries.contains(&word.to_ascii_lowercase().as_str()) {
                            return Err(Box::new(EngineError::DangerousQuery));
                        }
                    }
                }

                let conn = state.conn.as_ref().ok_or(EngineError::NotYetConnected)?;
                let sql_params_vec = state.params.clone();
                state.params.clear();

                let mut sql_params: Vec<&dyn ToSql> = vec![];
                for param in sql_params_vec.iter() {
                    match param {
                        SqlValue::String(s) => sql_params.push(s),
                        SqlValue::Integer(i) => sql_params.push(i),
                        SqlValue::Boolean(b) => sql_params.push(b),
                    };
                }
                conn.query(&query, sql_params.as_slice())?;
                evidence.push(Evidence { label: "Ran Query".to_string(), content: EvidenceContent::Textual(query.clone()) });

                Ok(())
            }
        )
        .with_instruction(
            Instruction::new("oracle-query-with-string-result", "Execute Query with String Result", "Execute a query. If the query contains dangerous words, you must allow dangerous queries.")
                .with_parameter("query", "Query", ParameterKind::String)
                .with_parameter("column", "Return Column", ParameterKind::String)
                .with_parameter("dangerous", "Allow Dangerous Queries", ParameterKind::Boolean)
                .with_output("result", "Result", ParameterKind::String),
            |state: &mut Mutex<State>, params, output, evidence| {
                let state = state.get_mut().map_err(|_| EngineError::PoisonedState)?;

                let danger_queries = ["truncate", "delete", "drop"];

                let query = params["query"].value_string();
                let column = params["column"].value_string();
                let danger_allowed = params["dangerous"].value_bool();

                if !danger_allowed {
                    for word in query.split(' ') {
                        let word = word.trim();
                        if danger_queries.contains(&word.to_ascii_lowercase().as_str()) {
                            return Err(Box::new(EngineError::DangerousQuery));
                        }
                    }
                }

                let conn = state.conn.as_ref().ok_or(EngineError::NotYetConnected)?;
                let sql_params_vec = state.params.clone();
                state.params.clear();

                let mut sql_params: Vec<&dyn ToSql> = vec![];
                for param in sql_params_vec.iter() {
                    match param {
                        SqlValue::String(s) => sql_params.push(s),
                        SqlValue::Integer(i) => sql_params.push(i),
                        SqlValue::Boolean(b) => sql_params.push(b),
                    };
                }
                let row = conn.query_row(&query, sql_params.as_slice())?;
                evidence.push(Evidence { label: "Ran Query".to_string(), content: EvidenceContent::Textual(query.clone()) });
                output.insert("result".to_string(), ParameterValue::String(row.get(column.as_str())?));

                Ok(())
            }
        )
        .with_instruction(
            Instruction::new("oracle-query-with-integer-result", "Execute Query with Integer Result", "Execute a query. If the query contains dangerous words, you must allow dangerous queries.")
                .with_parameter("query", "Query", ParameterKind::String)
                .with_parameter("column", "Return Column", ParameterKind::Integer)
                .with_parameter("dangerous", "Allow Dangerous Queries", ParameterKind::Boolean)
                .with_output("result", "Result", ParameterKind::String),
            |state: &mut Mutex<State>, params, output, evidence| {
                let state = state.get_mut().map_err(|_| EngineError::PoisonedState)?;

                let danger_queries = ["truncate", "delete", "drop"];

                let query = params["query"].value_string();
                let column = params["column"].value_string();
                let danger_allowed = params["dangerous"].value_bool();

                if !danger_allowed {
                    for word in query.split(' ') {
                        let word = word.trim();
                        if danger_queries.contains(&word.to_ascii_lowercase().as_str()) {
                            return Err(Box::new(EngineError::DangerousQuery));
                        }
                    }
                }

                let conn = state.conn.as_ref().ok_or(EngineError::NotYetConnected)?;
                let sql_params_vec = state.params.clone();
                state.params.clear();

                let mut sql_params: Vec<&dyn ToSql> = vec![];
                for param in sql_params_vec.iter() {
                    match param {
                        SqlValue::String(s) => sql_params.push(s),
                        SqlValue::Integer(i) => sql_params.push(i),
                        SqlValue::Boolean(b) => sql_params.push(b),
                    };
                }
                let row = conn.query_row(&query, sql_params.as_slice())?;
                evidence.push(Evidence { label: "Ran Query".to_string(), content: EvidenceContent::Textual(query.clone()) });
                output.insert("result".to_string(), ParameterValue::Integer(row.get(column.as_str())?));

                Ok(())
            }
        )
    );
}

expose_engine!(ENGINE);
