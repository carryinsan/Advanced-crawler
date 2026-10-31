//! Reversible, content-preserving context packing for ArixAI.
//!
//! The original extracted page remains untouched in CrawlResponse.text. This
//! formatter only creates the optional ai_context representation. It may
//! replace repeated title-cased names and verbatim long prose blocks with
//! reversible aliases when the glossary + packed body is shorter. Code blocks,
//! Markdown tables, and blockquote lines are never rewritten. No stop words,
//! numbers, negations, punctuation, or logical connectors are deleted.

use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct CompressionStats {
    pub method: &'static str,
    pub content_preserved: bool,
    pub reversible: bool,
    pub aliases_used: usize,
    pub original_text_bytes: usize,
    pub packed_body_bytes: usize,
    pub glossary_bytes: usize,
    pub context_bytes: usize,
    /// Positive only when the complete LLM context (including its glossary
    /// and structural headers) is shorter than the original body. This is a
    /// byte metric, not a tokenizer-specific token estimate.
    pub net_bytes_saved: usize,
}

#[derive(Debug, Clone)]
struct Candidate {
    phrase: String,
}

/// Produce a compact, LLM-oriented context while preserving every fact in a
/// reversible alias glossary. The caller must continue returning `text`
/// separately and unchanged.
pub fn format_context(
    source: &str,
    title: &str,
    quality: u8,
    word_count: usize,
    original_text: &str,
) -> (String, CompressionStats) {
    let (packed_body, glossary, aliases_used) = pack_repeated_phrases(original_text);
    let input_bytes = original_text.len();

    // Do not inflate ordinary pages with wrappers when there is nothing safe
    // and profitable to compress. The exact source text is then used as the
    // LLM context, byte-for-byte.
    if aliases_used == 0 {
        let stats = CompressionStats {
            method: "lossless-identity-no-profitable-aliases",
            content_preserved: true,
            reversible: true,
            aliases_used: 0,
            original_text_bytes: input_bytes,
            packed_body_bytes: input_bytes,
            glossary_bytes: 0,
            context_bytes: input_bytes,
            net_bytes_saved: 0,
        };
        return (original_text.to_string(), stats);
    }

    let glossary_bytes = glossary.len();
    let packed_body_bytes = packed_body.len();
    let mut context = String::with_capacity(
        source.len() + title.len() + packed_body.len() + glossary.len() + 240,
    );
    context.push_str("[ARIXAI CONTEXT v4.1]\n");
    context.push_str("[SOURCE] ");
    context.push_str(source);
    context.push_str("\n[TITLE] ");
    context.push_str(title);
    context.push_str("\n[QUALITY] ");
    context.push_str(&quality.to_string());
    context.push_str("/100\n[WORD COUNT] ");
    context.push_str(&word_count.to_string());
    context.push_str("\n[CONTENT PRESERVATION] Original extracted text is also returned unchanged in the `text` field. Aliases in this context are reversible using the fact ledger.\n");
    context.push_str("\n[FACT LEDGER — REVERSIBLE ALIASES]\n");
    context.push_str(&glossary);
    context.push_str("[END FACT LEDGER]\n");

    let jump_map = markdown_jump_map(&packed_body);
    if !jump_map.is_empty() {
        context.push_str("\n[JUMP-MAP]\n");
        context.push_str(&jump_map);
    }

    context.push_str("\n[CONTENT — PRESERVE ORDER; EXPAND ALIASES FROM LEDGER]\n");
    context.push_str(&packed_body);

    // A glossary that costs more than it saves is not compression. Fall back
    // to the original text rather than claiming a saving that does not exist.
    if context.len() >= input_bytes {
        let stats = CompressionStats {
            method: "lossless-identity-glossary-overhead-exceeded-savings",
            content_preserved: true,
            reversible: true,
            aliases_used: 0,
            original_text_bytes: input_bytes,
            packed_body_bytes: input_bytes,
            glossary_bytes: 0,
            context_bytes: input_bytes,
            net_bytes_saved: 0,
        };
        return (original_text.to_string(), stats);
    }

    let context_bytes = context.len();
    let stats = CompressionStats {
        method: "reversible-repeated-phrase-aliases",
        content_preserved: true,
        reversible: true,
        aliases_used,
        original_text_bytes: input_bytes,
        packed_body_bytes,
        glossary_bytes,
        context_bytes,
        net_bytes_saved: input_bytes.saturating_sub(context_bytes),
    };
    (context, stats)
}

fn pack_repeated_phrases(input: &str) -> (String, String, usize) {
    let mut candidates = collect_candidates(input);
    candidates.sort_by(|a, b| b.phrase.len().cmp(&a.phrase.len()).then_with(|| a.phrase.cmp(&b.phrase)));

    let mut body = input.to_string();
    let mut ledger = String::new();
    let mut aliases_used = 0usize;
    let mut alias_index = 1usize;

    for candidate in candidates.into_iter().take(32) {
        // Recount after longer aliases have been applied, preventing nested
        // phrases from being double-rewritten.
        let occurrences = count_eligible_occurrences(&body, &candidate.phrase);
        if occurrences < 3 {
            continue;
        }

        let alias = loop {
            let value = format!("§A{}", alias_index);
            alias_index += 1;
            if !input.contains(&value) && !ledger.contains(&value) {
                break value;
            }
        };

        let estimated_replacement_bytes = occurrences.saturating_mul(candidate.phrase.len().saturating_sub(alias.len()));
        let ledger_entry_bytes = alias.len() + candidate.phrase.len() + 7;
        // Never apply a transform unless the full glossary cost is repaid.
        if estimated_replacement_bytes <= ledger_entry_bytes {
            continue;
        }

        let updated = replace_eligible_occurrences(&body, &candidate.phrase, &alias);
        if updated == body {
            continue;
        }
        body = updated;
        ledger.push_str(&alias);
        ledger.push_str(" = \"");
        ledger.push_str(&candidate.phrase);
        ledger.push_str("\"\n");
        aliases_used += 1;
    }

    // A tiny, explicit symbol vocabulary can save space without losing the
    // original word: every symbol is defined in the reversible ledger. Only
    // lowercase whole-word matches are changed, and only when net bytes fall.
    const SYMBOLS: [(&str, &str); 5] = [
        ("approximately", "≈"),
        ("therefore", "∴"),
        ("increase", "↑"),
        ("decrease", "↓"),
        ("percentage", "%"),
    ];
    for (phrase, symbol) in SYMBOLS {
        if input.contains(symbol) {
            continue; // don't collide with a symbol already present in the source
        }
        let occurrences = count_eligible_occurrences(&body, phrase);
        if occurrences < 3 {
            continue;
        }
        let saved = occurrences.saturating_mul(phrase.len().saturating_sub(symbol.len()));
        let glossary_cost = symbol.len() + phrase.len() + 7;
        if saved <= glossary_cost {
            continue;
        }
        let updated = replace_eligible_occurrences(&body, phrase, symbol);
        if updated == body {
            continue;
        }
        body = updated;
        ledger.push_str(symbol);
        ledger.push_str(" = \"");
        ledger.push_str(phrase);
        ledger.push_str("\"\n");
        aliases_used += 1;
    }

    if aliases_used > 0 {
        ledger.push_str("Reconstruction: replace each alias above with its exact quoted value.\n");
    }
    (body, ledger, aliases_used)
}

fn collect_candidates(input: &str) -> Vec<Candidate> {
    let mut counts: Vec<(String, usize)> = Vec::new();
    let mut repeated_prose_lines: Vec<(String, usize)> = Vec::new();
    let mut in_fence = false;

    for raw_line in input.split_inclusive('\n') {
        let line = raw_line.trim_end_matches(|ch| ch == '\n' || ch == '\r');
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if is_protected_line(line, in_fence) {
            continue;
        }

        // Exact repeated long prose blocks commonly represent boilerplate
        // disclaimers, notices, or repeated specifications. Keep them only
        // when they recur verbatim; the alias ledger makes reconstruction exact.
        let prose_line = line.trim();
        if prose_line.len() >= 64 && prose_line.split_whitespace().count() >= 10 {
            if let Some((_, count)) = repeated_prose_lines.iter_mut().find(|(existing, _)| existing == prose_line) {
                *count += 1;
            } else {
                repeated_prose_lines.push((prose_line.to_string(), 1));
            }
        }

        let words: Vec<String> = line
            .split_whitespace()
            .map(clean_candidate_word)
            .filter(|word| !word.is_empty())
            .collect();

        for start in 0..words.len() {
            for width in 2..=4 {
                if start + width > words.len() {
                    break;
                }
                let phrase_words = &words[start..start + width];
                if phrase_words.iter().all(|word| is_title_word(word)) {
                    let phrase = phrase_words.join(" ");
                    if phrase.len() >= 18 && !starts_with_generic_word(&phrase) {
                        if let Some((_, count)) = counts.iter_mut().find(|(existing, _)| *existing == phrase) {
                            *count += 1;
                        } else {
                            counts.push((phrase, 1));
                        }
                    }
                }
            }
        }
    }

    let mut candidates: Vec<Candidate> = counts
        .into_iter()
        .filter_map(|(phrase, _)| {
            let count = count_eligible_occurrences(input, &phrase);
            (count >= 3).then_some(Candidate { phrase })
        })
        .collect();

    for (phrase, line_count) in repeated_prose_lines {
        if line_count >= 3 && count_eligible_occurrences(input, &phrase) >= 3
            && !candidates.iter().any(|candidate| candidate.phrase == phrase)
        {
            candidates.push(Candidate { phrase });
        }
    }
    candidates
}

fn clean_candidate_word(word: &str) -> String {
    word.trim_matches(|ch: char| !ch.is_alphanumeric() && ch != '-' && ch != '&' && ch != '.')
        .to_string()
}

fn is_title_word(word: &str) -> bool {
    let Some(first) = word.chars().next() else { return false; };
    first.is_uppercase() && word.chars().any(char::is_alphanumeric)
}

fn starts_with_generic_word(phrase: &str) -> bool {
    let first = phrase.split_whitespace().next().unwrap_or("");
    matches!(
        first,
        "The" | "This" | "These" | "Those" | "However" | "According" | "After" | "Before"
            | "When" | "While" | "Where" | "What" | "Why" | "How" | "Figure" | "Table"
            | "Section" | "Chapter" | "Source" | "Title" | "Note" | "For" | "From" | "With"
    )
}

fn is_protected_line(line: &str, in_fence: bool) -> bool {
    let trimmed = line.trim_start();
    in_fence
        || trimmed.starts_with('>')
        || line.contains('|')
        || line.contains('`')
        || line.contains('"')
        || line.contains('\'')
        || line.contains('“')
        || line.contains('”')
        || line.contains('‘')
        || line.contains('’')
}

fn is_word_char(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

fn has_word_boundaries(text: &str, start: usize, end: usize) -> bool {
    let before_ok = text[..start].chars().next_back().map_or(true, |ch| !is_word_char(ch));
    let after_ok = text[end..].chars().next().map_or(true, |ch| !is_word_char(ch));
    before_ok && after_ok
}

fn count_phrase_in_line(line: &str, phrase: &str) -> usize {
    let mut count = 0usize;
    let mut offset = 0usize;
    while let Some(relative) = line[offset..].find(phrase) {
        let start = offset + relative;
        let end = start + phrase.len();
        if has_word_boundaries(line, start, end) {
            count += 1;
            offset = end;
        } else {
            offset = start + phrase.chars().next().map(char::len_utf8).unwrap_or(1);
        }
        if offset >= line.len() {
            break;
        }
    }
    count
}

fn count_eligible_occurrences(input: &str, phrase: &str) -> usize {
    let mut total = 0usize;
    let mut in_fence = false;
    for raw_line in input.split_inclusive('\n') {
        let line = raw_line.trim_end_matches(|ch| ch == '\n' || ch == '\r');
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if !is_protected_line(line, in_fence) {
            total += count_phrase_in_line(line, phrase);
        }
    }
    total
}

fn replace_line(line: &str, phrase: &str, alias: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut offset = 0usize;
    while let Some(relative) = line[offset..].find(phrase) {
        let start = offset + relative;
        let end = start + phrase.len();
        if has_word_boundaries(line, start, end) {
            out.push_str(&line[offset..start]);
            out.push_str(alias);
            offset = end;
        } else {
            let next = start + phrase.chars().next().map(char::len_utf8).unwrap_or(1);
            out.push_str(&line[offset..next]);
            offset = next;
        }
        if offset >= line.len() {
            break;
        }
    }
    out.push_str(&line[offset..]);
    out
}

fn replace_eligible_occurrences(input: &str, phrase: &str, alias: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut in_fence = false;
    for raw_line in input.split_inclusive('\n') {
        let (content, ending) = if let Some(without_lf) = raw_line.strip_suffix('\n') {
            (without_lf.strip_suffix('\r').unwrap_or(without_lf), if without_lf.ends_with('\r') { "\r\n" } else { "\n" })
        } else {
            (raw_line, "")
        };
        let trimmed = content.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fence = !in_fence;
            output.push_str(content);
        } else if is_protected_line(content, in_fence) {
            output.push_str(content);
        } else {
            output.push_str(&replace_line(content, phrase, alias));
        }
        output.push_str(ending);
    }
    output
}

fn markdown_jump_map(text: &str) -> String {
    let mut output = String::new();
    let mut in_fence = false;
    let mut section = 0usize;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence || !trimmed.starts_with('#') {
            continue;
        }
        let heading = trimmed.trim_start_matches('#').trim();
        if heading.is_empty() {
            continue;
        }
        section += 1;
        output.push_str(&format!("[§{}] {}\n", section, heading));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_entity_aliases_are_reversible_and_only_used_when_net_saving() {
        let input = "ArixAI Core Engine powers search. ArixAI Core Engine ranks pages. ArixAI Core Engine returns sources.";
        let (packed, ledger, aliases) = pack_repeated_phrases(input);
        assert!(aliases > 0);
        assert!(packed.contains("§A1"));
        assert!(ledger.contains("ArixAI Core Engine"));
        assert!(packed.len() + ledger.len() < input.len());
        let restored = packed.replace("§A1", "ArixAI Core Engine");
        assert_eq!(restored, input);
    }

    #[test]
    fn code_tables_and_quotes_are_not_rewritten() {
        let input = "ArixAI Core Engine appears here. ArixAI Core Engine appears again. ArixAI Core Engine appears again.\n\n| ArixAI Core Engine | status |\n> ArixAI Core Engine quoted text\n```\nArixAI Core Engine in code\n```\n";
        let (packed, ledger, aliases) = pack_repeated_phrases(input);
        assert!(aliases > 0);
        assert!(packed.contains("| ArixAI Core Engine | status |"));
        assert!(packed.contains("> ArixAI Core Engine quoted text"));
        assert!(packed.contains("ArixAI Core Engine in code"));
        assert!(ledger.contains("ArixAI Core Engine"));
    }

    #[test]
    fn symbolic_abbreviations_are_defined_and_reversible() {
        let input = (1..=12)
            .map(|value| format!("The value is approximately {} and therefore increase by 5 percentage.", value))
            .collect::<Vec<_>>()
            .join("\n");
        let (packed, ledger, aliases) = pack_repeated_phrases(&input);
        assert!(aliases > 0);
        assert!(packed.contains('≈'));
        assert!(packed.contains('∴'));
        assert!(packed.contains('↑'));
        assert!(packed.contains('%'));
        assert!(ledger.contains("approximately"));
        assert!(ledger.contains("therefore"));
        assert!(ledger.contains("increase"));
        assert!(ledger.contains("percentage"));
        let mut restored = packed;
        for (symbol, word) in [("≈", "approximately"), ("∴", "therefore"), ("↑", "increase"), ("%", "percentage")] {
            restored = restored.replace(symbol, word);
        }
        assert_eq!(restored, input);
    }

    #[test]
    fn repeated_verbatim_boilerplate_paragraphs_are_reversible() {
        let disclaimer = "This information is provided for general informational purposes only and does not constitute legal advice or a binding offer.";
        let input = std::iter::repeat(disclaimer).take(4).collect::<Vec<_>>().join("\n\n");
        let (packed, ledger, aliases) = pack_repeated_phrases(&input);
        assert!(aliases > 0);
        assert!(ledger.contains(disclaimer));
        let alias = ledger.split(" = ").next().expect("alias should exist");
        let restored = packed.replace(alias, disclaimer);
        assert_eq!(restored, input);
    }

    #[test]
    fn directly_quoted_lines_are_never_rewritten() {
        let quote = "\"ArixAI Core Engine is quoted exactly and should remain untouched.\"";
        let input = std::iter::repeat(quote).take(6).collect::<Vec<_>>().join("\n");
        let (packed, ledger, aliases) = pack_repeated_phrases(&input);
        assert_eq!(packed, input);
        assert!(ledger.is_empty());
        assert_eq!(aliases, 0);
    }

    #[test]
    fn identity_mode_keeps_input_exact_when_aliasing_would_not_save_bytes() {
        let input = "This is a short sentence with no repeated entity.";
        let (packed, ledger, aliases) = pack_repeated_phrases(input);
        assert_eq!(packed, input);
        assert!(ledger.is_empty());
        assert_eq!(aliases, 0);
    }

    #[test]
    fn context_includes_metadata_and_preservation_contract_when_net_saving_exists() {
        let repeated = std::iter::repeat("ArixAI Core Engine is described in this paragraph. ")
            .take(120)
            .collect::<String>();
        let (context, stats) = format_context("https://example.com", "Example", 91, 960, &repeated);
        assert!(context.contains("[FACT LEDGER — REVERSIBLE ALIASES]"));
        assert!(context.contains("[CONTENT — PRESERVE ORDER"));
        assert!(stats.content_preserved);
        assert!(stats.reversible);
        assert!(stats.aliases_used > 0);
        assert!(stats.net_bytes_saved > 0);
        assert!(context.len() < repeated.len());
    }
}
