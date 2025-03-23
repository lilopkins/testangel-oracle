#![warn(clippy::pedantic)]

use oracle::{sql_type::ToSql, Connection};
use testangel_engine::{Evidence, EvidenceContent, engine};
use thiserror::Error;

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

engine! {
    /// Access and manipulate Oracle databases.
    #[engine(
        name = "Oracle SQL",
        lua_name = "OracleDB",
        version = env!("CARGO_PKG_VERSION"),
    )]
    #[derive(Default)]
    struct Oracle {
        conn: Option<Connection>,
        params: Vec<SqlValue>,
    }

    impl Oracle {
        /// Connect to an Oracle SQL server.
        #[instruction(
            id = "oracle-connect",
            name = "Connect",
            lua_name = "Connect",
            flags = InstructionFlags::AUTOMATIC,
        )]
        fn connect(
            username: String,
            password: String,
            #[arg(name = "Connection String")] connect_string: String,
        ) {
            if !dry_run {
                state.conn = Some(Connection::connect(username, password, connect_string)?);
            }
        }

        /* Add Parameters */
        /// Add a parameter to be used later in a query.
        #[instruction(
            id = "oracle-query-add-parameter-string",
            name = "AddQueryParameterString",
            lua_name = "Add Query Parameter: String",
            flags = InstructionFlags::INFALLIBLE | InstructionFlags::AUTOMATIC,
        )]
        fn add_parameter_string(
            #[arg(name = "Parameter Value")] sql_param: String,
        ) {
            if !dry_run {
                state.params.push(SqlValue::String(sql_param));
            }
        }

        /// Add a parameter to be used later in a query.
        #[instruction(
            id = "oracle-query-add-parameter-integer",
            name = "AddQueryParameterInteger",
            lua_name = "Add Query Parameter: Integer",
            flags = InstructionFlags::INFALLIBLE | InstructionFlags::AUTOMATIC,
        )]
        fn add_parameter_int(
            #[arg(name = "Parameter Value")] sql_param: i32,
        ) {
            if !dry_run {
                state.params.push(SqlValue::Integer(i64::from(sql_param)));
            }
        }

        /// Add a parameter to be used later in a query.
        #[instruction(
            id = "oracle-query-add-parameter-boolean",
            name = "AddQueryParameterBoolean",
            lua_name = "Add Query Parameter: Boolean",
            flags = InstructionFlags::INFALLIBLE | InstructionFlags::AUTOMATIC,
        )]
        fn add_parameter_bool(
            #[arg(name = "Parameter Value")] sql_param: bool,
        ) {
            if !dry_run {
                state.params.push(SqlValue::Boolean(sql_param));
            }
        }

        /* Run Query */
        /// Execute a query. If the query contains dangerous words, you must allow dangerous queries.
        #[instruction(
            id = "oracle-query",
            name = "ExecuteQuery",
            lua_name = "Execute Query",
            flags = InstructionFlags::AUTOMATIC,
        )]
        fn query(
            query: String,
            #[arg(id = "dangerous", name = "Allow Dangerous Queries")] danger_allowed: bool,
        ) {
            let danger_queries = ["truncate", "delete", "drop"];
            if !danger_allowed {
                for word in query.split(' ') {
                    let word = word.trim();
                    if danger_queries.contains(&word.to_ascii_lowercase().as_str()) {
                        return Err(Box::new(EngineError::DangerousQuery));
                    }
                }
            }

            if !dry_run {
                let conn = state.conn.as_ref().ok_or(EngineError::NotYetConnected)?;
                let sql_params_vec = state.params.clone();
                state.params.clear();

                let mut sql_params: Vec<&dyn ToSql> = vec![];
                for param in &sql_params_vec {
                    match param {
                        SqlValue::String(s) => sql_params.push(s),
                        SqlValue::Integer(i) => sql_params.push(i),
                        SqlValue::Boolean(b) => sql_params.push(b),
                    };
                }
                conn.query(&query, sql_params.as_slice())?;
                evidence.push(Evidence { label: "Ran Query".to_string(), content: EvidenceContent::Textual(query.clone()) });
            }
        }

        /// Execute a query. If the query contains dangerous words, you must allow dangerous queries.
        #[instruction(
            id = "oracle-query-with-string-result",
            name = "ExecuteQueryWithStringResult",
            lua_name = "Execute Query with String Result",
            flags = InstructionFlags::AUTOMATIC,
        )]
        fn query_with_string_result(
            query: String,
            #[arg(name = "Return Column")] column: String,
            #[arg(id = "dangerous", name = "Allow Dangerous Queries")] danger_allowed: bool,
        ) -> #[output(id = "result", name = "Result")] String {
            let danger_queries = ["truncate", "delete", "drop"];

            if !danger_allowed {
                for word in query.split(' ') {
                    let word = word.trim();
                    if danger_queries.contains(&word.to_ascii_lowercase().as_str()) {
                        return Err(Box::new(EngineError::DangerousQuery));
                    }
                }
            }

            if dry_run {
                String::new()
            } else {
                let conn = state.conn.as_ref().ok_or(EngineError::NotYetConnected)?;
                let sql_params_vec = state.params.clone();
                state.params.clear();

                let mut sql_params: Vec<&dyn ToSql> = vec![];
                for param in &sql_params_vec {
                    match param {
                        SqlValue::String(s) => sql_params.push(s),
                        SqlValue::Integer(i) => sql_params.push(i),
                        SqlValue::Boolean(b) => sql_params.push(b),
                    };
                }
                let row = conn.query_row(&query, sql_params.as_slice())?;
                evidence.push(Evidence { label: "Ran Query".to_string(), content: EvidenceContent::Textual(query.clone()) });
                row.get(column.as_str())?
            }
        }

        /// Execute a query. If the query contains dangerous words, you must allow dangerous queries.
        #[instruction(
            id = "oracle-query-with-integer-result",
            name = "ExecuteQueryWithIntegerResult",
            lua_name = "Execute Query with Integer Result",
            flags = InstructionFlags::AUTOMATIC,
        )]
        fn query_with_integer_result(
            query: String,
            #[arg(name = "Return Column")] column: String,
            #[arg(id = "dangerous", name = "Allow Dangerous Queries")] danger_allowed: bool,
        ) -> #[output(id = "result", name = "Result")] i32 {
            let danger_queries = ["truncate", "delete", "drop"];

            if !danger_allowed {
                for word in query.split(' ') {
                    let word = word.trim();
                    if danger_queries.contains(&word.to_ascii_lowercase().as_str()) {
                        return Err(Box::new(EngineError::DangerousQuery));
                    }
                }
            }

            if dry_run {
                0
            } else {
                let conn = state.conn.as_ref().ok_or(EngineError::NotYetConnected)?;
                let sql_params_vec = state.params.clone();
                state.params.clear();

                let mut sql_params: Vec<&dyn ToSql> = vec![];
                for param in &sql_params_vec {
                    match param {
                        SqlValue::String(s) => sql_params.push(s),
                        SqlValue::Integer(i) => sql_params.push(i),
                        SqlValue::Boolean(b) => sql_params.push(b),
                    };
                }
                let row = conn.query_row(&query, sql_params.as_slice())?;
                evidence.push(Evidence { label: "Ran Query".to_string(), content: EvidenceContent::Textual(query.clone()) });
                row.get(column.as_str())?
            }
        }
    }
}
