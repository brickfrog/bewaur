use crate::shared::models::AurPackage;
use reqwest::Url;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::RETRY_AFTER;
use serde::Deserialize;
use std::error::Error;
use std::io::Read;
use std::sync::OnceLock;
use std::time::Duration;

const AUR_RPC_BASE: &str = "https://aur.archlinux.org/rpc/v5";
const AUR_RPC_INFO_URL: &str = "https://aur.archlinux.org/rpc/v5/info";
const ERROR_BODY_LIMIT: usize = 1024;
const USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    " (AUR trust-scoring CLI)"
);

static AUR_CLIENT: OnceLock<Result<Client, String>> = OnceLock::new();

#[derive(Debug, Deserialize)]
struct RpcResponse {
    #[serde(rename = "type")]
    response_type: String,
    #[serde(default)]
    error: Option<String>,
    results: Vec<AurPackage>,
}

fn aur_client() -> Result<&'static Client, String> {
    AUR_CLIENT
        .get_or_init(|| {
            Client::builder()
                .user_agent(USER_AGENT)
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(|e| {
                    format!(
                        "Failed to build AUR HTTP client: {}",
                        format_error_chain(&e)
                    )
                })
        })
        .as_ref()
        .map_err(Clone::clone)
}

fn format_error_chain(error: &dyn Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();

    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }

    message
}

fn build_info_url_at(base: &str, names: &[&str]) -> Result<Url, String> {
    if names.is_empty() {
        return Err("AUR package info request requires at least one package name".to_string());
    }

    let mut url = Url::parse(base).map_err(|e| format!("Invalid AUR RPC URL '{base}': {e}"))?;
    {
        let mut query = url.query_pairs_mut();
        for name in names {
            query.append_pair("arg[]", name);
        }
    }

    Ok(url)
}

fn build_info_url(names: &[&str]) -> Result<Url, String> {
    build_info_url_at(AUR_RPC_INFO_URL, names)
}

pub(crate) fn info_url_len(names: &[&str]) -> Result<usize, String> {
    build_info_url(names).map(|url| url.as_str().len())
}

fn response_body_excerpt(mut response: Response) -> Result<String, String> {
    let mut bytes = Vec::with_capacity(ERROR_BODY_LIMIT + 1);
    response
        .by_ref()
        .take((ERROR_BODY_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("Failed to read AUR error response: {e}"))?;

    let truncated = bytes.len() > ERROR_BODY_LIMIT;
    bytes.truncate(ERROR_BODY_LIMIT);

    let mut body = String::from_utf8_lossy(&bytes).trim().to_string();
    if body.is_empty() {
        body.push_str("<empty body>");
    }
    if truncated {
        body.push_str("...");
    }

    Ok(body)
}

fn text_excerpt(body: &str) -> String {
    let body = body.trim();
    if body.is_empty() {
        return "<empty body>".to_string();
    }
    if body.len() <= ERROR_BODY_LIMIT {
        return body.to_string();
    }

    let mut end = ERROR_BODY_LIMIT;
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &body[..end])
}

fn parse_rpc_response(body: &str) -> Result<RpcResponse, String> {
    let response: RpcResponse = serde_json::from_str(body).map_err(|e| {
        format!(
            "Failed to parse AUR response: {e}; body: {}",
            text_excerpt(body)
        )
    })?;

    if response.response_type == "error" || response.error.is_some() {
        return Err(format!(
            "AUR RPC returned an error: {}",
            response.error.as_deref().unwrap_or("unknown API error")
        ));
    }

    Ok(response)
}

fn send_rpc_request(request: RequestBuilder) -> Result<RpcResponse, String> {
    let response = request
        .send()
        .map_err(|e| format!("HTTP request failed: {}", format_error_chain(&e)))?;
    let status = response.status();
    let retry_after = response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    if !status.is_success() {
        let body = response_body_excerpt(response)?;
        let retry = retry_after
            .map(|value| format!("; Retry-After: {value}"))
            .unwrap_or_default();
        return Err(format!(
            "AUR RPC request failed with HTTP {status}{retry}; body: {body}"
        ));
    }

    let body = response.text().map_err(|e| {
        format!(
            "Failed to read AUR response body: {}",
            format_error_chain(&e)
        )
    })?;
    parse_rpc_response(&body)
}

fn fetch_packages_info_at(
    client: &Client,
    base: &str,
    names: &[&str],
) -> Result<Vec<AurPackage>, String> {
    let url = build_info_url_at(base, names)?;
    send_rpc_request(client.get(url)).map(|response| response.results)
}

/// Fetch info for a single package from the AUR RPC API.
pub fn fetch_package_info(package_name: &str) -> Result<AurPackage, String> {
    fetch_packages_info(&[package_name])?
        .into_iter()
        .next()
        .ok_or_else(|| format!("Package '{package_name}' not found on AUR"))
}

/// Fetch info for multiple packages in a single request.
pub fn fetch_packages_info(names: &[&str]) -> Result<Vec<AurPackage>, String> {
    fetch_packages_info_at(aur_client()?, AUR_RPC_INFO_URL, names)
}

/// Fetch all packages maintained by a given user.
pub fn fetch_maintainer_packages(maintainer: &str) -> Result<Vec<AurPackage>, String> {
    let mut url = Url::parse(&format!("{AUR_RPC_BASE}/search/"))
        .map_err(|e| format!("Invalid AUR RPC URL: {e}"))?;
    url.path_segments_mut()
        .map_err(|_| "AUR RPC URL cannot be used as a base URL".to_string())?
        .push(maintainer);
    url.query_pairs_mut().append_pair("by", "maintainer");

    send_rpc_request(aur_client()?.get(url)).map(|response| response.results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn info_url_encodes_repeated_args_and_plus_signs() {
        let url = build_info_url(&["plain", "libc++"]).unwrap();

        assert_eq!(
            url.as_str(),
            "https://aur.archlinux.org/rpc/v5/info?arg%5B%5D=plain&arg%5B%5D=libc%2B%2B"
        );
        assert_eq!(
            url.query_pairs().collect::<Vec<_>>(),
            vec![
                ("arg[]".into(), "plain".into()),
                ("arg[]".into(), "libc++".into())
            ]
        );
    }

    #[test]
    fn empty_info_request_is_rejected() {
        let error = build_info_url(&[]).unwrap_err();
        assert!(error.contains("at least one package name"));
    }

    #[test]
    fn http_error_reports_status_retry_after_and_bounded_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).unwrap();

            let body = "x".repeat(ERROR_BODY_LIMIT + 100);
            write!(
                stream,
                "HTTP/1.1 429 Too Many Requests\r\nContent-Length: {}\r\nRetry-After: 7\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });

        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let error = fetch_packages_info_at(
            &client,
            &format!("http://{address}/rpc/v5/info"),
            &["test-package"],
        )
        .unwrap_err();

        server.join().unwrap();
        assert!(error.contains("HTTP 429 Too Many Requests"), "{error}");
        assert!(error.contains("Retry-After: 7"), "{error}");
        let body = error.split("body: ").nth(1).unwrap();
        assert!(body.ends_with("..."), "{error}");
        assert!(body.len() <= ERROR_BODY_LIMIT + 3, "{error}");
    }

    #[test]
    fn rpc_error_payload_is_not_treated_as_an_empty_success() {
        let error = parse_rpc_response(
            r#"{"type":"error","resultcount":0,"results":[],"error":"invalid arguments"}"#,
        )
        .unwrap_err();

        assert_eq!(error, "AUR RPC returned an error: invalid arguments");
    }
}
