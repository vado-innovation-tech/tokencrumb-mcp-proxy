//! The JavaScript sandbox a Code Mode script runs in (client side, ADR 0007).
//!
//! One QuickJS runtime per script, dropped afterwards. The engine has no host module:
//! no file system, no network, no timers, no `require`/`import`. The only ways out are
//! the two functions this module installs, both of which pass JSON strings:
//!
//! - `codemode.<tool>(args)` reaches the caller-provided [`Caller`], which decides what
//!   a call does (in practice: a signed `tools/call` through the gateway);
//! - `console.log(...)` appends to a bounded log.
//!
//! Limits bound memory, stack, wall-clock time (checked by the interpreter and before
//! every call), the number of calls and the size of the output.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use rquickjs::{Context, Function, Promise, Runtime};
use serde_json::{Value, json};

use crate::json::strict_json;

/// Bounds applied to one script.
#[derive(Debug, Clone)]
pub struct Limits {
    pub max_calls: usize,
    pub timeout: Duration,
    /// Characters of the serialized result returned to the model.
    pub max_output: usize,
    pub memory_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_calls: 50,
            timeout: Duration::from_secs(60),
            // About 6,000 tokens.
            max_output: 24_000,
            memory_bytes: 64 * 1024 * 1024,
        }
    }
}

const MAX_LOG_LINES: usize = 200;
const MAX_LOG_LINE: usize = 2_000;
const MAX_SCRIPT: usize = 256 * 1024;
const STACK_BYTES: usize = 1024 * 1024;
pub const TRUNCATED: &str = "--- TRUNCATED ---";

/// What one tool call returned, as the script sees it.
#[derive(Debug, Clone)]
pub enum CallOutcome {
    /// The call succeeded with this value.
    Value(Value),
    /// The call failed; the script receives an exception it may catch.
    Error(String),
    /// The call needs a person's approval: the script stops here (ADR 0007, point 11).
    Held(Value),
}

/// Performs a call on behalf of the script: tool name, then arguments.
pub type Caller = Rc<RefCell<dyn FnMut(&str, &Value) -> CallOutcome>>;

/// One call the script issued, in order.
#[derive(Debug, Clone, PartialEq)]
pub struct CallRecord {
    pub tool: String,
    /// `ok`, `error`, `held` or `refused` (limits, unknown after a hold).
    pub status: &'static str,
}

/// Everything a script run produced.
#[derive(Debug, Clone, Default)]
pub struct Run {
    /// The script's return value, when it completed.
    pub result: Option<Value>,
    /// Why the script did not complete.
    pub error: Option<String>,
    pub logs: Vec<String>,
    pub calls: Vec<CallRecord>,
    /// The held call's approval request, when the script stopped on one.
    pub held: Option<Value>,
}

struct State {
    caller: Option<Caller>,
    limits: Limits,
    deadline: Instant,
    logs: Vec<String>,
    calls: Vec<CallRecord>,
    held: Option<Value>,
}

impl State {
    fn call(&mut self, tool: &str, raw_arguments: &str) -> Value {
        let refuse = |calls: &mut Vec<CallRecord>, message: &str| {
            calls.push(CallRecord {
                tool: tool.to_owned(),
                status: "refused",
            });
            json!({"ok": false, "name": "LimitError", "error": message})
        };
        let Some(caller) = self.caller.clone() else {
            return json!({"ok": false, "name": "Error",
                          "error": "tool calls are not available in search; use execute"});
        };
        if self.held.is_some() {
            return refuse(
                &mut self.calls,
                "the script is stopped: an earlier call awaits approval",
            );
        }
        if self.calls.len() >= self.limits.max_calls {
            return refuse(
                &mut self.calls,
                &format!("call limit reached ({})", self.limits.max_calls),
            );
        }
        if Instant::now() >= self.deadline {
            return refuse(&mut self.calls, "time limit reached");
        }
        let arguments = match strict_json(raw_arguments.as_bytes()) {
            Ok(value @ Value::Object(_)) => value,
            _ => {
                return json!({"ok": false, "name": "TypeError",
                              "error": "tool arguments must be a plain object"});
            }
        };
        let outcome = (caller.borrow_mut())(tool, &arguments);
        let (status, reply) = match outcome {
            CallOutcome::Value(value) => ("ok", json!({"ok": true, "value": value})),
            CallOutcome::Error(message) => (
                "error",
                json!({"ok": false, "name": "ToolError", "error": message}),
            ),
            CallOutcome::Held(request) => {
                self.held = Some(request);
                (
                    "held",
                    json!({"ok": false, "name": "ApprovalRequired",
                           "error": "this call awaits a person's approval; the script stops here"}),
                )
            }
        };
        self.calls.push(CallRecord {
            tool: tool.to_owned(),
            status,
        });
        reply
    }

    fn log(&mut self, line: String) {
        if self.logs.len() < MAX_LOG_LINES {
            self.logs.push(truncate_chars(&line, MAX_LOG_LINE));
        } else if self.logs.len() == MAX_LOG_LINES {
            self.logs.push(TRUNCATED.to_owned());
        }
    }
}

/// The global `codemode` and `console` objects. The host functions are captured in a
/// closure and removed from the global scope before the script runs.
const PRELUDE: &str = r#"
var codemode, console;
(() => {
  const hostCall = globalThis.__tc_call, hostLog = globalThis.__tc_log;
  const catalog = JSON.parse(globalThis.__tc_catalog);
  delete globalThis.__tc_call; delete globalThis.__tc_log; delete globalThis.__tc_catalog;
  const show = (x) => typeof x === "string" ? x : (() => { try { return JSON.stringify(x); } catch (_) { return String(x); } })();
  const call = (name, args) => {
    const reply = JSON.parse(hostCall(name, JSON.stringify(args === undefined ? {} : args)));
    if (reply.ok) return reply.value;
    const error = new Error(reply.error);
    error.name = reply.name || "ToolError";
    throw error;
  };
  const base = Object.freeze({ tools: () => JSON.parse(JSON.stringify(catalog)) });
  codemode = new Proxy(base, {
    get(target, property) {
      if (typeof property !== "string" || property === "then") return undefined;
      if (Object.prototype.hasOwnProperty.call(target, property)) return target[property];
      return async (args) => call(property, args);
    },
  });
  const log = (...items) => hostLog(items.map(show).join(" "));
  console = Object.freeze({ log, info: log, warn: log, error: log, debug: log });
})();
"#;

/// Run `code`, an async arrow function (or an expression), in a fresh sandbox.
///
/// `catalog` is what `codemode.tools()` returns. Without a `caller` the script may only
/// read the catalog (the `search` tool).
pub fn run(code: &str, catalog: &Value, caller: Option<Caller>, limits: &Limits) -> Run {
    if code.len() > MAX_SCRIPT {
        return Run {
            error: Some(format!("script too large (over {MAX_SCRIPT} bytes)")),
            ..Run::default()
        };
    }
    let deadline = Instant::now() + limits.timeout;
    let state = Rc::new(RefCell::new(State {
        caller,
        limits: limits.clone(),
        deadline,
        logs: Vec::new(),
        calls: Vec::new(),
        held: None,
    }));
    let outcome = evaluate(code, catalog, &state, limits, deadline);
    let state = Rc::try_unwrap(state)
        .map(RefCell::into_inner)
        .unwrap_or_else(|shared| {
            // The runtime is gone; a leftover reference only happens on engine failure.
            let state = shared.borrow();
            State {
                caller: None,
                limits: state.limits.clone(),
                deadline,
                logs: state.logs.clone(),
                calls: state.calls.clone(),
                held: state.held.clone(),
            }
        });
    let mut run = Run {
        logs: state.logs,
        calls: state.calls,
        held: state.held,
        ..Run::default()
    };
    match outcome {
        Ok(Ok(value)) => run.result = Some(value),
        Ok(Err(message)) | Err(message) => run.error = Some(message),
    }
    run
}

/// `Ok(Ok(value))` when the script returned, `Ok(Err(..))` when it threw, `Err(..)`
/// when the engine stopped it (time limit, memory, syntax).
fn evaluate(
    code: &str,
    catalog: &Value,
    state: &Rc<RefCell<State>>,
    limits: &Limits,
    deadline: Instant,
) -> Result<Result<Value, String>, String> {
    let runtime = Runtime::new().map_err(|e| format!("sandbox unavailable: {e}"))?;
    runtime.set_memory_limit(limits.memory_bytes);
    runtime.set_max_stack_size(STACK_BYTES);
    runtime.set_interrupt_handler(Some(Box::new(move || Instant::now() >= deadline)));
    let context = Context::full(&runtime).map_err(|e| format!("sandbox unavailable: {e}"))?;
    let timed_out = || Instant::now() >= deadline;
    let script = format!(
        "(async () => {{\n  try {{\n    const __tc_fn = (\n{code}\n);\n    \
         const __tc_v = typeof __tc_fn === \"function\" ? await __tc_fn() : await __tc_fn;\n    \
         return JSON.stringify({{ ok: true, value: __tc_v === undefined ? null : __tc_v }});\n  \
         }} catch (e) {{\n    \
         const m = (e && e.message !== undefined) ? String(e.name || \"Error\") + \": \" + String(e.message) : String(e);\n    \
         return JSON.stringify({{ ok: false, error: m }});\n  }}\n}})()"
    );
    let raw: String = context.with(|ctx| {
        let globals = ctx.globals();
        let install = || -> rquickjs::Result<()> {
            let calls = state.clone();
            globals.set(
                "__tc_call",
                Function::new(ctx.clone(), move |tool: String, arguments: String| {
                    calls.borrow_mut().call(&tool, &arguments).to_string()
                })?,
            )?;
            let logs = state.clone();
            globals.set(
                "__tc_log",
                Function::new(ctx.clone(), move |line: String| {
                    logs.borrow_mut().log(line);
                })?,
            )?;
            globals.set("__tc_catalog", catalog.to_string())?;
            ctx.eval::<(), _>(PRELUDE)
        };
        install().map_err(|e| format!("sandbox unavailable: {e}"))?;
        let promise: Promise = match ctx.eval(script.as_str()) {
            Ok(promise) => promise,
            Err(_) if timed_out() => return Err("time limit reached".to_owned()),
            Err(_) => return Err(format!("script error: {}", describe(&ctx.catch()))),
        };
        match promise.finish::<String>() {
            Ok(raw) => Ok(raw),
            Err(_) if timed_out() => Err("time limit reached".to_owned()),
            Err(rquickjs::Error::WouldBlock) => {
                Err("script error: the script awaited something that never settles".to_owned())
            }
            Err(_) => Err(format!("script error: {}", describe(&ctx.catch()))),
        }
    })?;
    let reply = strict_json(raw.as_bytes()).map_err(|_| "script error: unreadable result")?;
    if reply["ok"] == json!(true) {
        Ok(Ok(reply["value"].clone()))
    } else {
        Ok(Err(reply["error"]
            .as_str()
            .unwrap_or("script error")
            .to_owned()))
    }
}

fn describe(value: &rquickjs::Value) -> String {
    if let Some(object) = value.as_object() {
        let name: Option<String> = object.get("name").ok();
        let message: Option<String> = object.get("message").ok();
        if let Some(message) = message {
            return format!("{}: {message}", name.unwrap_or_else(|| "Error".to_owned()));
        }
    }
    value
        .as_string()
        .and_then(|s| s.to_string().ok())
        .unwrap_or_else(|| "uncaught exception".to_owned())
}

/// At most `max` characters, the last ones replaced by [`TRUNCATED`] when cut.
pub fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let keep = max.saturating_sub(TRUNCATED.len() + 1);
    let mut out: String = text.chars().take(keep).collect();
    out.push('\n');
    out.push_str(TRUNCATED);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(f: impl FnMut(&str, &Value) -> CallOutcome + 'static) -> Option<Caller> {
        Some(Rc::new(RefCell::new(f)))
    }

    fn quick() -> Limits {
        Limits {
            timeout: Duration::from_millis(500),
            ..Limits::default()
        }
    }

    #[test]
    fn a_script_returns_a_value_and_logs() {
        let run = run(
            "async () => { console.log('hi', {a: 1}); return [1, 2].map(x => x * 2); }",
            &json!([]),
            None,
            &quick(),
        );
        assert_eq!(run.result, Some(json!([2, 4])));
        assert_eq!(run.logs, ["hi {\"a\":1}"]);
        assert!(run.error.is_none());
    }

    #[test]
    fn search_reads_the_catalog_but_cannot_call() {
        let catalog = json!([{"name": "kdrive_list"}, {"name": "github_issue"}]);
        let run = run(
            "async () => codemode.tools().filter(t => t.name.startsWith('kdrive')).map(t => t.name)",
            &catalog,
            None,
            &quick(),
        );
        assert_eq!(run.result, Some(json!(["kdrive_list"])));
        let run = run2("async () => codemode.kdrive_list({})", &catalog);
        assert!(run.error.unwrap().contains("not available in search"));
    }

    fn run2(code: &str, catalog: &Value) -> Run {
        run(code, catalog, None, &quick())
    }

    #[test]
    fn calls_reach_the_caller_and_errors_are_catchable() {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let log = seen.clone();
        let run = run(
            "async () => {
               const a = await codemode.svc_read({path: '/a'});
               let b;
               try { await codemode.svc_fail({}); } catch (e) { b = e.name + ':' + e.message; }
               const [c, d] = await Promise.all([codemode.svc_read({path: '/c'}), codemode.svc_read({path: '/d'})]);
               return {a, b, c, d};
             }",
            &json!([]),
            caller(move |tool, arguments| {
                log.borrow_mut().push((tool.to_owned(), arguments.clone()));
                match tool {
                    "svc_fail" => CallOutcome::Error("boom".into()),
                    _ => CallOutcome::Value(arguments["path"].clone()),
                }
            }),
            &quick(),
        );
        assert_eq!(
            run.result,
            Some(json!({"a": "/a", "b": "ToolError:boom", "c": "/c", "d": "/d"}))
        );
        assert_eq!(seen.borrow().len(), 4);
        assert_eq!(run.calls[1].status, "error");
    }

    #[test]
    fn a_held_call_stops_every_later_call() {
        let run = run(
            "async () => {
               await codemode.svc_read({});
               try { await codemode.svc_delete({path: '/x'}); } catch (_) {}
               await codemode.svc_read({});
               return 'unreachable';
             }",
            &json!([]),
            caller(|tool, _| match tool {
                "svc_delete" => CallOutcome::Held(json!({"request_id": "r1"})),
                _ => CallOutcome::Value(json!(1)),
            }),
            &quick(),
        );
        assert_eq!(run.held, Some(json!({"request_id": "r1"})));
        let statuses: Vec<_> = run.calls.iter().map(|c| c.status).collect();
        assert_eq!(statuses, ["ok", "held", "refused"]);
        assert!(run.error.unwrap().contains("awaits approval"));
    }

    #[test]
    fn the_call_limit_is_enforced() {
        let limits = Limits {
            max_calls: 2,
            ..quick()
        };
        let run = run(
            "async () => { for (let i = 0; i < 5; i++) await codemode.svc_x({}); }",
            &json!([]),
            caller(|_, _| CallOutcome::Value(json!(null))),
            &limits,
        );
        assert!(run.error.unwrap().contains("call limit reached (2)"));
        assert_eq!(run.calls.len(), 3);
    }

    #[test]
    fn an_endless_loop_hits_the_time_limit() {
        let run = run2("async () => { while (true) {} }", &json!([]));
        assert_eq!(run.error.as_deref(), Some("time limit reached"));
        // Even a script that catches everything cannot swallow the interrupt.
        let run = run2(
            "async () => { for (;;) { try { while (true) {} } catch (_) {} } }",
            &json!([]),
        );
        assert_eq!(run.error.as_deref(), Some("time limit reached"));
    }

    #[test]
    fn memory_is_bounded() {
        let limits = Limits {
            memory_bytes: 8 * 1024 * 1024,
            ..quick()
        };
        let run = run(
            "async () => { const a = []; for (;;) a.push('x'.repeat(1024)); }",
            &json!([]),
            None,
            &limits,
        );
        assert!(run.error.is_some());
        assert!(run.result.is_none());
    }

    #[test]
    fn the_sandbox_has_no_host_access() {
        let run = run2(
            "async () => [typeof require, typeof process, typeof fetch, typeof std, typeof os,
                          typeof setTimeout, typeof __tc_call, typeof __tc_log]",
            &json!([]),
        );
        assert_eq!(run.result, Some(Value::Array(vec![json!("undefined"); 8])));
        let run = run2("async () => { await import('os'); }", &json!([]));
        assert!(run.error.is_some());
    }

    #[test]
    fn syntax_errors_and_unsettled_promises_are_reported() {
        let run = run2("async () => {", &json!([]));
        assert!(run.error.unwrap().starts_with("script error"));
        let run = run2("async () => await new Promise(() => {})", &json!([]));
        assert!(run.error.unwrap().contains("never settles"));
    }

    #[test]
    fn truncation_marks_the_cut() {
        assert_eq!(truncate_chars("short", 100), "short");
        let cut = truncate_chars(&"x".repeat(100), 40);
        assert!(cut.ends_with(TRUNCATED));
        assert!(cut.chars().count() <= 40);
    }
}
