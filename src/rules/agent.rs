use serde_json::Value;

use super::{FileInfo, Meta, Rule, Text, finding};
use crate::{Family, Finding, Severity};

pub fn is_mcp_config(f: &FileInfo) -> bool {
    f.name == ".mcp.json"
        || f.name == "mcp.json"
        || f.name == "claude_desktop_config.json"
        || f.name == "opencode.json"
        || f.name == "opencode.jsonc"
        || (f.name.starts_with("settings")
            && f.ext == "json"
            && (f.under(".gemini/") || f.under(".claude/")))
}

fn claude_settings(f: &FileInfo) -> bool {
    f.under(".claude/") && f.name.starts_with("settings") && f.ext == "json"
}

pub fn is_agent_file(f: &FileInfo) -> bool {
    is_mcp_config(f)
        || matches!(
            f.name.as_str(),
            "skill.md"
                | "claude.md"
                | "agents.md"
                | "gemini.md"
                | ".cursorrules"
                | ".windsurfrules"
                | "copilot-instructions.md"
        )
        || (f.under(".codex/") && f.ext == "toml")
        || f.under(".claude/commands/")
        || f.under(".claude/agents/")
        || f.under(".claude/skills/")
        || f.under(".claude/hooks/")
        || f.under(".cursor/rules/")
        || f.under(".gemini/commands/")
}

macro_rules! rule {
    ($id:literal, $sev:ident, $files:ident, $pat:literal, $unless:expr, $msg:literal, $fix:literal) => {
        Rule {
            id: $id,
            family: Family::Agent,
            severity: Severity::$sev,
            files: $files,
            pattern: $pat,
            unless: $unless,
            message: $msg,
            fix: $fix,
        }
    };
}

pub static RULES: &[Rule] = &[
    rule!(
        "agent.bypass-permissions",
        High,
        is_agent_file,
        r#""defaultMode"\s*:\s*"bypassPermissions"|--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|sandbox_mode\s*=\s*"danger-full-access"|--yolo\b"#,
        None,
        "The agent is set to run every action without asking, so one bad instruction can do anything on this machine.",
        "Use the default or an accept-edits mode and allow specific commands instead of skipping all approvals."
    ),
    rule!(
        "agent.unrestricted-shell",
        High,
        claude_settings,
        r#""Bash(?:\(\*\)|\(:\*\))?""#,
        None,
        "Every shell command is pre-approved, so the agent can run anything without asking.",
        "Allow specific commands, for example \"Bash(npm test:*)\"."
    ),
    rule!(
        "agent.remote-script",
        High,
        is_agent_file,
        r"\b(?:curl|wget)\b[^|\n]*?(?:https?://|\$\{?\w)[^|\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|node)\b",
        None,
        "A script is downloaded and run straight from the internet; whoever controls that URL controls this machine.",
        "Download, review and pin the script (or a checksum), or install the tool from a package manager."
    ),
    rule!(
        "agent.prompt-injection",
        Medium,
        is_agent_file,
        r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|directions|prompts?)|\b(?:do\s+not|don't|never)\s+(?:tell|inform|notify|alert)\s+the\s+user|\bwithout\s+(?:telling|asking|informing|notifying)\s+the\s+user|\bexfiltrat",
        Some(
            r#"(?i)["“'‘(]\s*(?:ignore|disregard|forget)|\b(?:never|don't|do not|must not|should not|shouldn't|not)\b[^.]{0,80}\bwithout\s+(?:asking|telling|informing|notifying)|\b(?:must not|never|do not|don't)\s+(?:contain|follow|obey|act on|comply)|\b(?:malware|injection|attack|malicious|treat\b[^.]*\bas data)"#
        ),
        "Instruction text tells the agent to override its rules or hide actions from the user (prompt injection).",
        "Remove the text, and do not install skills or rules from sources you have not read."
    ),
    rule!(
        "agent.sensitive-file-access",
        High,
        is_agent_file,
        r"~/\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws/credentials|\.netrc\b|\.git-credentials|/etc/shadow|\bLogin Data\b|security\s+find-(?:generic|internet)-password",
        None,
        "Agent instructions read credential files such as SSH keys or cloud credentials.",
        "Remove the step; an agent never needs your private keys or credential stores."
    ),
    rule!(
        "agent.hidden-unicode",
        High,
        is_agent_file,
        r"[\x{E0000}-\x{E007F}\x{200B}\x{200C}\x{200E}\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}]",
        None,
        "Invisible Unicode characters are in agent instructions; they can hide text the agent reads but you don't see.",
        "Delete the invisible characters and review what they spelled out."
    ),
];

pub static STRUCTURED: &[(&str, Severity, &str)] = &[
    (
        "agent.mcp-unpinned",
        Severity::Medium,
        "An MCP server is started from a package or image with no pinned version.",
    ),
    (
        "agent.mcp-plaintext-secret",
        Severity::High,
        "An MCP server's token or key is written in plain text in the config.",
    ),
    (
        "agent.mcp-insecure-url",
        Severity::High,
        "A remote MCP server is reached over plain HTTP.",
    ),
];

pub fn structured(file: &FileInfo, text: &Text) -> Vec<Finding> {
    if !is_mcp_config(file) {
        return Vec::new();
    }
    let Ok(json) = serde_json::from_str::<Value>(&strip_jsonc(text.src)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for key in ["mcpServers", "servers", "mcp", "context_servers"] {
        let Some(servers) = json.get(key).and_then(Value::as_object) else {
            continue;
        };
        for (name, server) in servers {
            let start = text.src.find(&format!("\"{name}\"")).unwrap_or(0);
            check_server(file, text, start, server, &mut out);
        }
    }
    out
}

fn check_server(
    file: &FileInfo,
    text: &Text,
    start: usize,
    server: &Value,
    out: &mut Vec<Finding>,
) {
    let mut argv: Vec<String> = Vec::new();
    match server.get("command") {
        Some(Value::String(c)) => argv.push(c.clone()),
        Some(Value::Array(a)) => argv.extend(a.iter().filter_map(|v| v.as_str().map(String::from))),
        _ => {}
    }
    if let Some(Value::Array(a)) = server.get("args") {
        argv.extend(a.iter().filter_map(|v| v.as_str().map(String::from)));
    }
    if let Some(spec) = unpinned(&argv) {
        let line = line_after(text, start, &format!("\"{spec}\""));
        out.push(finding(
            file,
            text,
            line,
            Meta {
                id: "agent.mcp-unpinned",
                family: Family::Agent,
                severity: Severity::Medium,
                message: &format!("The MCP server runs `{spec}` without a pinned version, so every start installs whatever was published last."),
                fix: "Pin an exact version (pkg@1.2.3, pkg==1.2.3, or an image digest) and update on purpose.",
                secret: None,
            },
        ));
    }
    for env_key in ["env", "environment"] {
        let Some(env) = server.get(env_key).and_then(Value::as_object) else {
            continue;
        };
        for (k, v) in env {
            let Some(v) = v.as_str() else { continue };
            if secret_like_key(k)
                && v.len() >= 8
                && !v.starts_with('$')
                && !v.starts_with('<')
                && !v.contains("{env:")
            {
                let line = line_after(text, start, &format!("\"{k}\""));
                out.push(finding(
                    file,
                    text,
                    line,
                    Meta {
                        id: "agent.mcp-plaintext-secret",
                        family: Family::Agent,
                        severity: Severity::High,
                        message: &format!("The MCP server's {k} is written in plain text in the config."),
                        fix: "Reference an environment variable (\"${VAR}\") and keep the value out of files that get shared or committed.",
                        secret: Some(v),
                    },
                ));
            }
        }
    }
    if let Some(url) = server
        .get("url")
        .or_else(|| server.get("serverUrl"))
        .and_then(Value::as_str)
        && let Some(rest) = url.strip_prefix("http://")
    {
        let host = rest.split(['/', ':']).next().unwrap_or("");
        if !matches!(host, "localhost" | "127.0.0.1" | "[") && !host.starts_with("[::1") {
            let line = line_after(text, start, url);
            out.push(finding(
            file,
            text,
            line,
            Meta {
                id: "agent.mcp-insecure-url",
                family: Family::Agent,
                severity: Severity::High,
                message: "A remote MCP server is reached over plain HTTP, so its tools and your data can be read or changed on the way.",
                fix: "Use https:// for every MCP server that is not on this machine.",
                secret: None,
            },
        ));
        }
    }
}

/// Whether an env key names a credential. Each part of the key (split at every character that
/// is not a letter or digit) is searched for the credential words, as before, except where the
/// word only shows up as part of an ordinary one: a part that starts with `monkey`, `keyboard`
/// or `author`, and `pat` in `path`, `patch` or `compat`. A camelCase word of its own always
/// counts. So `PATH`, `DISPATCH_MODE`, `AUTHOR` and `MONKEY_PATCH` don't count, and
/// `daemonKey`, `patHash`, `GITHUB_PAT` and `PATv2` do.
fn secret_like_key(key: &str) -> bool {
    // Found anywhere in a part, as on main: these don't hide inside ordinary words.
    const ANYWHERE: &[&str] = &["token", "secret", "password", "credential"];
    // Ordinary words that start a part and contain `key` or `auth`. Only taken out at the start,
    // so `snapshotKey` and `apiKeyChain` still count.
    const NOT_KEY: &[&str] = &[
        "monkey",
        "donkey",
        "turkey",
        "hockey",
        "jockey",
        "whiskey",
        "lackey",
        "latchkey",
        "keychain",
        "keyboard",
        "keynote",
        "keyword",
        "keystroke",
    ];
    const NOT_AUTH: &[&str] = &["authority", "authorities", "authors", "author"];
    let after_word = |part: &str, words: &[&str]| -> String {
        let rest = words
            .iter()
            .find_map(|w| part.strip_prefix(w))
            .unwrap_or(part);
        rest.to_string()
    };
    key.split(|c: char| !c.is_alphanumeric())
        .filter(|part| !part.is_empty())
        .any(|original| {
            let part = original.to_lowercase();
            let part = part.as_str();
            // `hotKey`, `patHash`, `gitlabComPat`: a camelCase word that is the credential word.
            let camel = camel_words(original);
            camel.iter().any(|w| {
                let w = w.strip_suffix('s').unwrap_or(w);
                matches!(w, "key" | "pat" | "auth")
            }) || ANYWHERE.iter().any(|w| part.contains(w))
                || after_word(part, NOT_KEY).contains("key")
                // `authorization` and `authentication` start like `author` but are credentials.
                || ["authoriz", "authoris", "authent"]
                    .iter()
                    .any(|w| part.contains(w))
                || after_word(part, NOT_AUTH).contains("auth")
                || pat_word(part)
        })
}

/// The lower-case words of a camelCase part: `githubPatHash` gives `github`, `pat`, `hash`. A
/// part with no lower-to-upper change (`GITHUBPAT`, `pythonpath`) is one word.
fn camel_words(part: &str) -> Vec<String> {
    let mut words = vec![String::new()];
    let mut prev_lower = false;
    for c in part.chars() {
        if c.is_uppercase() && prev_lower {
            words.push(String::new());
        }
        prev_lower = c.is_lowercase() || c.is_ascii_digit();
        words.last_mut().unwrap().extend(c.to_lowercase());
    }
    words
}

/// Whether a lower-case part has `pat` other than inside `path`, `patch`, `pattern`, `patient`,
/// `patron`, `patio`, `patent`, `spatial`, `spatula` or `compat`.
fn pat_word(part: &str) -> bool {
    const NOT_AFTER: &[&str] = &["h", "ch", "tern", "ien", "ron", "io", "ent", "ial", "ula"];
    part.match_indices("pat").any(|(i, _)| {
        let after = &part[i + 3..];
        !part[..i].ends_with("com") && !NOT_AFTER.iter().any(|w| after.starts_with(w))
    })
}

fn unpinned(argv: &[String]) -> Option<String> {
    let cmd = argv.first()?;
    let base = cmd
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(cmd)
        .trim_end_matches(".cmd")
        .trim_end_matches(".exe");
    let rest = &argv[1..];
    let positional = |skip: &[&str]| {
        rest.iter()
            .find(|a| !a.is_empty() && !a.starts_with('-') && !skip.contains(&a.as_str()))
            .cloned()
    };
    match base {
        "npx" | "bunx" | "pnpx" => {
            let pkg = positional(&[])?;
            (!npm_pinned(&pkg)).then_some(pkg)
        }
        "pnpm" | "yarn" | "bun"
            if rest.first().map(String::as_str) == Some("dlx")
                || rest.first().map(String::as_str) == Some("x") =>
        {
            let pkg = rest[1..]
                .iter()
                .find(|a| !a.is_empty() && !a.starts_with('-'))
                .cloned()?;
            (!npm_pinned(&pkg)).then_some(pkg)
        }
        "uvx" | "pipx" => {
            let pkg = match rest.iter().position(|a| a == "--from") {
                Some(i) => rest.get(i + 1).cloned()?,
                None => positional(&["run"])?,
            };
            (!(pkg.contains("==")
                || pkg.contains('@')
                || pkg.starts_with('.')
                || pkg.starts_with('/')))
            .then_some(pkg)
        }
        "docker" | "podman" => {
            let i = rest.iter().position(|a| a == "run")?;
            let mut it = rest[i + 1..].iter();
            let image = loop {
                let a = it.next()?;
                if a.starts_with('-') {
                    if matches!(
                        a.as_str(),
                        "-e" | "-v"
                            | "-p"
                            | "--env"
                            | "--volume"
                            | "--name"
                            | "--network"
                            | "-w"
                            | "--mount"
                            | "--env-file"
                    ) {
                        it.next();
                    }
                    continue;
                }
                break a.clone();
            };
            let last = image.rsplit('/').next().unwrap_or(&image);
            let pinned =
                image.contains("@sha256:") || (last.contains(':') && !last.ends_with(":latest"));
            (!pinned).then_some(image)
        }
        _ => None,
    }
}

fn npm_pinned(pkg: &str) -> bool {
    if pkg.starts_with('.') || pkg.starts_with('/') {
        return true;
    }
    // The first character is skipped so the `@` of a scope is not taken for a version.
    let Some((start, _)) = pkg.char_indices().nth(1) else {
        return false;
    };
    match pkg[start..].rfind('@') {
        Some(i) => {
            let v = &pkg[start + i + 1..];
            !v.is_empty() && v != "latest" && v.chars().next().is_some_and(|c| c.is_ascii_digit())
        }
        None => false,
    }
}

fn line_after(text: &Text, start: usize, needle: &str) -> usize {
    let at = text.src[start..]
        .find(needle)
        .map(|i| start + i)
        .unwrap_or(start);
    text.line_of(at)
}

fn strip_jsonc(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    let mut in_str = false;
    while let Some(c) = chars.next() {
        if in_str {
            out.push(c);
            if c == '\\' {
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            } else if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
            out.push(c);
        } else if c == '/' && chars.peek() == Some(&'/') {
            for n in chars.by_ref() {
                if n == '\n' {
                    out.push('\n');
                    break;
                }
            }
        } else if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut prev = ' ';
            for n in chars.by_ref() {
                if n == '\n' {
                    out.push('\n');
                }
                if prev == '*' && n == '/' {
                    break;
                }
                prev = n;
            }
        } else {
            out.push(c);
        }
    }
    out
}
