use serde::Serialize;

/// Format and print a serializable value according to the chosen format.
pub fn print_json<T: Serialize>(value: &T) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).unwrap_or_default()
    );
}
