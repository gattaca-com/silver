use std::time::Duration;

use tracing::warn;

/// A single ClickHouse table over the blocking HTTP interface: statements go
/// in the `query` parameter, rows in the body. Runs its DDL on first use and
/// again after any failure, so a ClickHouse that appears late still gets its
/// schema. Each `ddl` statement is posted on its own — the HTTP endpoint takes
/// one per request — and every one must be re-runnable against a live table.
pub struct ChTable {
    agent: ureq::Agent,
    url: String,
    name: &'static str,
    ddl: &'static [&'static str],
    created: bool,
}

impl ChTable {
    pub fn new(url: &str, name: &'static str, ddl: &'static [&'static str]) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_millis(150))
            .timeout(Duration::from_secs(250))
            .build();
        Self { agent, url: url.to_owned(), name, ddl, created: false }
    }

    pub fn insert(&mut self, json_lines: &str) {
        if !self.created {
            self.created = self.ddl.iter().all(|stmt| self.post(stmt, None).is_ok());
        }

        let query = format!("INSERT INTO {} FORMAT JSONEachRow", self.name);
        if let Err(e) = self.post(json_lines, Some(&query)) {
            warn!(%e, table = self.name, "insert failed; batch dropped");
            self.created = false;
        }
    }

    fn post(&self, body: &str, query: Option<&str>) -> Result<(), String> {
        let mut req = self.agent.post(&self.url);
        if let Some(query) = query {
            req = req.query("query", query);
        }
        req.send_string(body).map(|_| ()).map_err(|e| e.to_string())
    }
}
