mod common;

use std::path::Path;
use std::process::Command;

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_safe-anything"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

fn fixture(name: &str) -> String {
    common::fixtures().join(name).to_string_lossy().into_owned()
}

#[test]
fn json_output_lists_every_finding_and_fails_on_high() {
    let (code, out) = run(&[&fixture("code"), "--json", "--offline"]);
    let report: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    let expected = std::fs::read_to_string(Path::new(&fixture("code")).join("EXPECTED"))
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty())
        .count();
    assert_eq!(report["findings"].as_array().unwrap().len(), expected);
    let first = &report["findings"][0];
    for key in [
        "rule", "severity", "path", "line", "message", "fix", "snippet",
    ] {
        assert!(!first[key].is_null(), "finding has {key}");
    }
    assert_eq!(report["dependency_check"]["status"], "skipped");
    assert_eq!(code, 1);
}

#[test]
fn terminal_report_shows_file_line_rule_and_fix() {
    let (_, out) = run(&[&fixture("agent"), "--offline"]);
    assert!(out.contains(".mcp.json:5"), "{out}");
    assert!(out.contains("agent.mcp-unpinned"), "{out}");
    assert!(out.contains("Pin an exact version"), "{out}");
    let expected = std::fs::read_to_string(Path::new(&fixture("agent")).join("EXPECTED"))
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .count();
    assert!(
        out.lines()
            .any(|l| l.starts_with(&format!("{expected} findings"))),
        "{out}"
    );
}

#[test]
fn fail_on_and_severity_filter() {
    let (code, _) = run(&[&fixture("config"), "--offline", "--fail-on", "never"]);
    assert_eq!(code, 0);
    let (_, out) = run(&[
        &fixture("config"),
        "--offline",
        "--json",
        "--severity",
        "high",
    ]);
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["severity"] == "high" || f["severity"] == "critical")
    );
}

#[test]
fn clean_folder_exits_zero_and_says_so() {
    let dir = std::env::temp_dir().join(format!("safe-anything-clean-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("main.py"), "print('hello')\n").unwrap();
    let (code, out) = run(&[dir.to_str().unwrap(), "--offline"]);
    assert_eq!(code, 0);
    assert!(out.contains("No problems found"), "{out}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn every_rule_has_a_cwe_and_a_reference() {
    let (_, out) = run(&["--list-rules", "--json"]);
    let rules: serde_json::Value = serde_json::from_str(&out).expect("valid JSON");
    let rules = rules.as_array().unwrap();
    assert!(rules.len() >= 69);
    for r in rules {
        assert!(
            r["cwe"].as_str().is_some_and(|c| c.starts_with("CWE-")),
            "{r}"
        );
        assert!(
            r["learn_more"]
                .as_str()
                .is_some_and(|u| u.starts_with("https://")),
            "{r}"
        );
    }
}

#[test]
fn sarif_output_for_code_scanning() {
    let (_, out) = run(&[&fixture("code"), "--sarif", "--offline"]);
    let sarif: serde_json::Value = serde_json::from_str(&out).expect("valid SARIF JSON");
    assert_eq!(sarif["version"], "2.1.0");
    let run = &sarif["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "safe-anything");
    let expected = std::fs::read_to_string(Path::new(&fixture("code")).join("EXPECTED"))
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty())
        .count();
    let results = run["results"].as_array().unwrap();
    assert_eq!(results.len(), expected);
    let r = &results[0];
    assert!(r["ruleId"].as_str().is_some());
    assert!(
        r["locations"][0]["physicalLocation"]["region"]["startLine"]
            .as_u64()
            .unwrap()
            >= 1
    );
    assert!(
        run["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["id"] == r["ruleId"])
    );
}

#[test]
fn mcp_server_scans_over_stdio() {
    use std::io::{BufRead, BufReader, Write};
    let mut child = Command::new(env!("CARGO_BIN_EXE_safe-anything"))
        .arg("mcp")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut ask = |msg: serde_json::Value| -> serde_json::Value {
        writeln!(stdin, "{msg}").unwrap();
        serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap()
    };
    let init = ask(
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}}),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "safe-anything");
    let tools = ask(serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"scan") && names.contains(&"list_rules"),
        "{names:?}"
    );
    let call = ask(
        serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "scan", "arguments": {"path": fixture("agent"), "offline": true}}}),
    );
    let text = call["result"]["content"][0]["text"].as_str().unwrap();
    let report: serde_json::Value = serde_json::from_str(text).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule"] == "agent.mcp-unpinned")
    );
    drop(stdin);
    child.wait().unwrap();
}

#[test]
fn secrets_are_redacted_in_every_output() {
    let token = common::fake("github");
    let token_tail = &token[token.len() - 16..];
    let password = common::fake("password");
    let aws = common::fake("aws");
    for args in [
        vec![fixture("agent"), "--offline".into()],
        vec![fixture("agent"), "--offline".into(), "--json".into()],
        vec![fixture("secrets"), "--offline".into(), "--sarif".into()],
        vec![fixture("secrets"), "--offline".into()],
    ] {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let (_, out) = run(&args);
        assert!(!out.contains(token_tail), "token leaked with {args:?}");
        assert!(!out.contains(&password), "password leaked with {args:?}");
        assert!(!out.contains(&aws[4..]), "AWS key leaked with {args:?}");
    }
    let (_, out) = run(&[&fixture("agent"), "--offline"]);
    assert!(
        out.contains("\"GITHUB_TOKEN\": \"ghp_"),
        "only the value is masked:\n{out}"
    );
}

#[test]
fn public_env_secret_value_is_redacted() {
    // `secret.public-env-secret` matches the variable name; the value given to it must not be
    // printed either, in any output.
    let value = common::fake("db-password");
    let dir = std::env::temp_dir().join(format!("safe-anything-public-env-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // One finding per line; every way of giving the name a value must hide that value.
    let lines = [
        format!("export NEXT_PUBLIC_STRIPE_SECRET_KEY=\"{value}\""),
        format!("VITE_ADMIN_PASSWORD={value}"),
        format!("NUXT_PUBLIC_SMTP_PASSWORD = \"{value} and more\""),
        format!("GATSBY_API_SECRET=pa,ss;{value}"),
        "PUBLIC_PIN_PASSWORD=zq7Kx".to_string(),
        // A short value with a comment after it, a second name, a one-letter value.
        "VITE_PIN_PASSWORD=Qv7k # dev pin".to_string(),
        format!("VITE_A_SECRET=Jq9xW; VITE_B_SECRET={value}"),
        "echo NEXT_PUBLIC_ECHO_SECRET e".to_string(),
        // Values that start with, or are made of, operator and bracket characters.
        "VITE_QM_PASSWORD=\"?Wz8k\"".to_string(),
        "VITE_EQS_PASSWORD=\"====\"".to_string(),
        "VITE_PUN_PASSWORD=\":;,\"".to_string(),
        "VITE_BARE_PASSWORD=;,)]}".to_string(),
        "ENV NEXT_PUBLIC_QUOTED_SECRET \":= 'Hk4w'\"".to_string(),
        "VITE_COLON_PASSWORD:=Lm2z".to_string(),
        format!("const NEXT_PUBLIC_API_SECRET: string = \"{value}\";"),
        format!("$cfg = ['VITE_HASH_PASSWORD' => '{value}'];"),
        format!("const k = process.env.VITE_FALLBACK_SECRET || \"{value}\";"),
        format!("process.env[\"REACT_APP_IDX_SECRET\"] = \"{value}\";"),
        format!("ENV NEXT_PUBLIC_DOCKER_SECRET {value}"),
        format!("{{\"VITE_A_SECRET\": \"Jq9xW\", \"VITE_B_SECRET\": \"{value}\"}}"),
        format!("if (NEXT_PUBLIC_CMP_SECRET === \"{value}\") {{}}"),
        format!("REACT_APP_DB_PASSWORD: '{value}'"),
        format!("{{\"EXPO_PUBLIC_SERVICE_ROLE\": \"{value}\"}}"),
        // Nothing after the name but punctuation: printed as is, still reported.
        "const key = process.env.NEXT_PUBLIC_OPENAI_KEY;".to_string(),
        "NEXT_PUBLIC_EMPTY_SECRET=".to_string(),
    ];
    std::fs::write(dir.join("vars.sh"), lines.join("\n") + "\n").unwrap();
    let path = dir.to_string_lossy().into_owned();
    for extra in [None, Some("--json"), Some("--sarif")] {
        let mut args = vec![path.as_str(), "--offline"];
        args.extend(extra);
        let (_, out) = run(&args);
        assert!(!out.contains(&value), "value leaked with {args:?}:\n{out}");
        for part in [
            "and more", "pa,ss", "zq7Kx", "Qv7k", "Jq9x", "?Wz8", "\"====", ":;,", ";,)]}", "Hk4w",
            "Lm2z", ":= '",
        ] {
            assert!(!out.contains(part), "{part:?} leaked with {args:?}:\n{out}");
        }
        assert!(
            out.matches("secret.public-env-secret").count() >= lines.len(),
            "findings missing with {args:?}:\n{out}"
        );
    }
    let (_, out) = run(&[&path, "--offline"]);
    for kept in [
        "VITE_ADMIN_PASSWORD****\n",
        "echo NEXT_PUBLIC_ECHO_SECRET ****\n",
        "ENV NEXT_PUBLIC_DOCKER_SECRET ****\n",
        "process.env.NEXT_PUBLIC_OPENAI_KEY;",
        "NEXT_PUBLIC_EMPTY_SECRET=\n",
    ] {
        assert!(
            out.contains(kept),
            "{kept:?} expected in the output:\n{out}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
