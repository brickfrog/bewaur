use crate::shared::scoring::{ScanResult, Tier};
use colored::Colorize;
use std::borrow::Cow;
use std::fmt::Write as _;
use std::io::Write;

/// Print scan result as colored terminal text to stderr.
pub fn print_text(result: &ScanResult, verbose: bool) {
    write_text(&mut std::io::stderr(), result, verbose);
}

/// Write scan result as colored terminal text to an arbitrary writer.
pub fn write_text(w: &mut dyn Write, result: &ScanResult, verbose: bool) {
    let tier_colored = match result.tier {
        Tier::Trusted => result.tier.to_string().green(),
        Tier::Ok => result.tier.to_string().yellow(),
        Tier::Sketchy => result.tier.to_string().truecolor(255, 165, 0), // orange
        Tier::Suspicious => result.tier.to_string().red(),
        Tier::Malicious => result.tier.to_string().red().bold(),
    };

    let package = terminal_safe(&result.package);
    let _ = writeln!(
        w,
        "{} {} (trust: {}/100)",
        "bewaur:".bold(),
        package.as_ref().bold(),
        result.score
    );
    let _ = writeln!(w, "  Trust: {tier_colored}");

    if let Some(ref gate) = result.override_gate_fired {
        let gate = terminal_safe(gate);
        let _ = writeln!(
            w,
            "  {} Override gate fired: {}",
            "!!".red().bold(),
            gate.as_ref()
        );
    }

    if result.signals.is_empty() {
        let _ = writeln!(w, "  No negative signals found.");
    } else {
        let _ = writeln!(w, "  Negative signals:");
        for signal in &result.signals {
            let id = terminal_safe(&signal.id);
            let description = terminal_safe(&signal.description);
            let prefix = if signal.is_override_gate {
                "!!".red().bold().to_string()
            } else if signal.points >= 60 {
                "!!".red().to_string()
            } else if signal.points >= 30 {
                " !".yellow().to_string()
            } else {
                "  ".to_string()
            };
            let _ = writeln!(
                w,
                "    {prefix} {}: {}",
                id.as_ref(),
                description.as_ref()
            );
            if verbose
                && let Some(ref line) = signal.matched_line
            {
                let line = terminal_safe(line);
                let _ = writeln!(w, "         {} {}", ">".dimmed(), line.as_ref().dimmed());
            }
        }
    }
}

fn terminal_safe(value: &str) -> Cow<'_, str> {
    if !value.chars().any(is_terminal_affecting) {
        return Cow::Borrowed(value);
    }

    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if !is_terminal_affecting(character) {
            escaped.push(character);
            continue;
        }
        match character {
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character as u32 <= 0xff => {
                let _ = write!(escaped, "\\x{:02x}", character as u32);
            }
            character => {
                let _ = write!(escaped, "\\u{{{:x}}}", character as u32);
            }
        }
    }
    Cow::Owned(escaped)
}

fn is_terminal_affecting(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

/// Print scan result as JSON.
pub fn print_json(result: &ScanResult) {
    let json = serde_json::to_string_pretty(result).expect("Failed to serialize");
    println!("{json}");
}
