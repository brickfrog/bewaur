use regex::Regex;
use std::sync::LazyLock;

static COMMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"<div\b[^>]*\bclass\s*=\s*["'][^"']*\barticle-content\b[^"']*["'][^>]*>([\s\S]*?)</div>"#,
    )
    .unwrap()
});

static HTML_TAG_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]+>").unwrap());

/// Fetch recent comments from an AUR package page.
/// Returns comment text strings (HTML stripped). Empty vec on error.
pub fn fetch_recent_comments(pkgbase: &str) -> Vec<String> {
    let url = format!("https://aur.archlinux.org/packages/{pkgbase}");

    let resp = match reqwest::blocking::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
    {
        Ok(r) if r.status().is_success() => r,
        _ => return Vec::new(),
    };

    let html = match resp.text() {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };

    extract_comments(&html)
}

/// Extract comment text from AUR package page HTML.
fn extract_comments(html: &str) -> Vec<String> {
    COMMENT_RE
        .captures_iter(html)
        .map(|cap| {
            let raw = &cap[1];
            let text = HTML_TAG_RE.replace_all(raw, " ");
            let text = html_entities_decode(&text);
            // Collapse whitespace
            text.split_whitespace().collect::<Vec<_>>().join(" ")
        })
        .filter(|s| !s.is_empty())
        .take(10)
        .collect()
}

/// Decode common HTML entities.
fn html_entities_decode(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Representative of current AUR package-page markup: the comment id appears
    // before the article-content class, and the body contains nested elements.
    const CURRENT_AUR_COMMENT_HTML: &str = r##"
        <div id="comment-2563149" class="comment-header">
            <h4><a href="#comment-2563149">user commented on 2026-07-06</a></h4>
        </div>
        <div id="comment-2563149-content" class="article-content">
            <p>The package now works with <code>foo &amp; bar</code> successfully.</p>
        </div>
    "##;

    #[test]
    fn extracts_comments_from_html() {
        let html = r#"
        <div class="comment-header">User commented</div>
        <div class="article-content">This package works great!</div>
        <div class="comment-header">Another user</div>
        <div class="article-content">Found a <b>bug</b> in v2.</div>
        "#;
        let comments = extract_comments(html);
        assert_eq!(comments.len(), 2);
        assert!(comments[0].contains("works great"));
        assert!(comments[1].contains("Found a bug"));
    }

    #[test]
    fn handles_empty_html() {
        assert!(extract_comments("").is_empty());
    }

    #[test]
    fn extracts_comment_when_id_precedes_article_content_class() {
        assert_eq!(
            extract_comments(CURRENT_AUR_COMMENT_HTML),
            vec!["The package now works with foo & bar successfully."]
        );
    }

    #[test]
    fn recognizes_article_content_among_multiple_classes() {
        let html =
            r#"<div id="comment-1-content" class="prose article-content formatted">Body</div>"#;
        assert_eq!(extract_comments(html), vec!["Body"]);
    }

    #[test]
    fn decodes_html_entities() {
        let html = r#"<div class="article-content">&amp; &lt;test&gt;</div>"#;
        let comments = extract_comments(html);
        assert_eq!(comments[0], "& <test>");
    }
}
