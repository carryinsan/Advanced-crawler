use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use futures_util::{stream, StreamExt};
use http_body_util::BodyExt;
use reqwest::{header, Client, StatusCode};
use scraper::{ElementRef, Html, Selector};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{net::lookup_host, sync::Semaphore, time::timeout};
use url::Url;
use vercel_runtime::{run, service_fn, Error, Request, Response, ResponseBody};

const MAX_REDIRECTS: usize = 8;
const MAX_HTML_BYTES: usize = 2 * 1024 * 1024;
const MAX_INPUT_BYTES: usize = 128 * 1024;
const MAX_URL_LEN: usize = 4096;
const MAX_URLS_PER_REQUEST: usize = 100;
const REQUEST_CONCURRENCY: usize = 24;
const GLOBAL_CONCURRENCY: usize = 64;
const CLIENT_POOL_CAPACITY: usize = 128;
const FETCH_TIMEOUT_SECS: u64 = 10;
const CONNECT_TIMEOUT_SECS: u64 = 3;
const MAX_JSON_TEXT_BYTES: usize = 120 * 1024;
const MAX_TAG_BUFFER_BYTES: usize = 64 * 1024;
const USER_AGENT: &str = "ArixAI-WebIntelligence/4.0";

static GLOBAL_GATE: OnceLock<Arc<Semaphore>> = OnceLock::new();
static CLIENT_POOL: OnceLock<Mutex<ClientPool>> = OnceLock::new();

#[derive(Debug, Deserialize)]
struct CrawlRequest {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    urls: Option<Vec<String>>,
    #[serde(default)]
    max_text: Option<usize>,
    #[serde(default)]
    include_ai_context: bool,
}

#[derive(Debug, Serialize, Clone)]
struct CrawlResponse {
    ok: bool,
    url: String,
    final_url: Option<String>,
    title: Option<String>,
    description: Option<String>,
    language: Option<String>,
    content_type: Option<String>,
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ai_context: Option<String>,
    word_count: usize,
    character_count: usize,
    source_html_bytes: usize,
    quality: u8,
    method: String,
    latency_ms: u128,
    stages: Stages,
    warnings: Vec<String>,
    error: Option<Failure>,
}

#[derive(Debug, Default, Serialize, Clone)]
struct Stages {
    validation_ms: u128,
    dns_ms: u128,
    fetch_ms: u128,
    redirect_ms: u128,
    read_ms: u128,
    parse_ms: u128,
    extraction_ms: u128,
    audit_ms: u128,
}

#[derive(Debug, Serialize, Clone)]
struct Failure {
    code: String,
    message: String,
    retryable: bool,
}

#[derive(Debug, Serialize)]
struct BatchResponse {
    ok: bool,
    count: usize,
    succeeded: usize,
    failed: usize,
    latency_ms: u128,
    scheduler: SchedulerInfo,
    results: Vec<CrawlResponse>,
}

#[derive(Debug, Serialize)]
struct SchedulerInfo {
    requested: usize,
    max_urls_per_request: usize,
    concurrency_ceiling: usize,
    strategy: &'static str,
}

#[derive(Debug)]
struct SafeTarget {
    url: Url,
    ip: IpAddr,
}

#[derive(Debug)]
struct FetchResult {
    response: reqwest::Response,
    final_target: SafeTarget,
    redirect_ms: u128,
    dns_ms: u128,
    archive_fallback: bool,
}

#[derive(Debug, Default)]
struct ExtractionStats {
    emitted_blocks: usize,
    emitted_words: usize,
    skipped_noise_nodes: usize,
    hidden_nodes: usize,
    paragraphs: usize,
    headings: usize,
    links: usize,
    density_blocks_skipped: usize,
}

#[derive(Debug, Default)]
struct DensityMetrics {
    words: usize,
    punctuation: usize,
    links: usize,
    linked_words: usize,
}

#[derive(Default)]
struct ClientPool {
    clients: HashMap<String, Client>,
    order: VecDeque<String>,
}

impl ClientPool {
    fn touch(&mut self, key: &str) {
        if let Some(pos) = self.order.iter().position(|v| v == key) {
            self.order.remove(pos);
        }
        self.order.push_back(key.to_string());
    }

    fn insert(&mut self, key: String, client: Client) {
        while self.clients.len() >= CLIENT_POOL_CAPACITY {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.clients.remove(&oldest);
        }
        self.clients.insert(key.clone(), client);
        self.touch(&key);
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(service_fn(handler)).await
}

async fn handler(req: Request) -> Result<Response<ResponseBody>, Error> {
    if req.method() == http::Method::OPTIONS {
        return Ok(Response::builder()
            .status(http::StatusCode::NO_CONTENT)
            .header("access-control-allow-origin", "*")
            .header("access-control-allow-methods", "POST, OPTIONS")
            .header("access-control-allow-headers", "content-type, authorization, x-arix-crawler-token")
            .header("cache-control", "no-store")
            .body(ResponseBody::from(Vec::new()))?);
    }

    if req.method() != http::Method::POST {
        return json_response(405, &serde_json::json!({
            "ok": false,
            "error": {"code": "METHOD_NOT_ALLOWED"}
        }));
    }

    if !request_authorized(&req) {
        return json_response(401, &serde_json::json!({
            "ok": false,
            "error": {"code": "UNAUTHORIZED", "message": "Crawler API token is missing or invalid"}
        }));
    }

    let started = Instant::now();
    let body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return json_response(400, &serde_json::json!({
                "ok": false,
                "error": {"code": "INVALID_BODY", "message": "Could not read request body"}
            }));
        }
    };

    if body.len() > MAX_INPUT_BYTES {
        return json_response(413, &serde_json::json!({
            "ok": false,
            "error": {"code": "REQUEST_TOO_LARGE", "message": "Request body is too large"}
        }));
    }

    let input: CrawlRequest = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            return json_response(400, &serde_json::json!({
                "ok": false,
                "error": {
                    "code": "INVALID_JSON",
                    "message": "Send JSON: { url: string } or { urls: string[] }"
                }
            }));
        }
    };

    let mut supplied_urls = Vec::new();
    for entry in input.urls.unwrap_or_default() {
        split_url_field(&entry, &mut supplied_urls);
    }
    if let Some(url) = input.url {
        split_url_field(&url, &mut supplied_urls);
    }

    let mut urls = Vec::with_capacity(supplied_urls.len().min(MAX_URLS_PER_REQUEST));
    let mut seen = HashSet::new();
    for raw in supplied_urls {
        let value = raw.trim().to_string();
        if !value.is_empty() && value.len() <= MAX_URL_LEN && seen.insert(value.clone()) {
            urls.push(value);
        }
    }

    if urls.is_empty() {
        return json_response(400, &serde_json::json!({
            "ok": false,
            "error": {"code": "NO_URLS", "message": "Provide at least one HTTP(S) URL"}
        }));
    }
    if urls.len() > MAX_URLS_PER_REQUEST {
        return json_response(413, &serde_json::json!({
            "ok": false,
            "error": {
                "code": "TOO_MANY_URLS",
                "message": format!("Maximum {} URLs per request", MAX_URLS_PER_REQUEST)
            }
        }));
    }

    let max_text = input.max_text;
    let include_ai_context = input.include_ai_context;
    let requested = urls.len();
    let gate = GLOBAL_GATE
        .get_or_init(|| Arc::new(Semaphore::new(GLOBAL_CONCURRENCY)))
        .clone();
    let concurrency = requested.min(REQUEST_CONCURRENCY).max(1);

    let results = stream::iter(urls.into_iter().map(|url| {
        let gate = gate.clone();
        async move {
            let _permit = match gate.acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => {
                    return failed_response(url, "CRAWLER_SHUTDOWN", "Crawler scheduler is unavailable", false);
                }
            };
            crawl_one(&url, max_text, include_ai_context).await
        }
    }))
    .buffer_unordered(concurrency)
    .collect::<Vec<_>>()
    .await;

    let succeeded = results.iter().filter(|result| result.ok).count();
    let failed = results.len().saturating_sub(succeeded);
    eprintln!(
        "{{\"event\":\"batch_complete\",\"requested\":{},\"succeeded\":{},\"failed\":{},\"latency_ms\":{}}}",
        requested,
        succeeded,
        failed,
        started.elapsed().as_millis()
    );

    json_response(
        200,
        &BatchResponse {
            ok: failed == 0,
            count: results.len(),
            succeeded,
            failed,
            latency_ms: started.elapsed().as_millis(),
            scheduler: SchedulerInfo {
                requested,
                max_urls_per_request: MAX_URLS_PER_REQUEST,
                concurrency_ceiling: GLOBAL_CONCURRENCY,
                strategy: "global bounded concurrency with per-host pooled clients and isolated results",
            },
            results,
        },
    )
}

fn request_authorized(req: &Request) -> bool {
    let expected = std::env::var("ARIX_CRAWLER_API_TOKEN").unwrap_or_default();
    if expected.is_empty() {
        return true;
    }
    let supplied = req
        .headers()
        .get("x-arix-crawler-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    constant_time_eq(expected.as_bytes(), supplied.as_bytes())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for index in 0..max_len {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(a ^ b);
    }
    difference == 0
}

async fn crawl_one(raw: &str, max_text: Option<usize>, include_ai_context: bool) -> CrawlResponse {
    let started = Instant::now();
    match crawl(raw, max_text, include_ai_context).await {
        Ok(mut response) => {
            response.latency_ms = started.elapsed().as_millis();
            eprintln!(
                "{{\"event\":\"page_complete\",\"url\":{},\"ok\":true,\"latency_ms\":{},\"quality\":{},\"words\":{},\"source_bytes\":{}}}",
                serde_json::to_string(raw).unwrap_or_else(|_| "\"?\"".into()),
                response.latency_ms,
                response.quality,
                response.word_count,
                response.source_html_bytes
            );
            response
        }
        Err(error) => {
            let retryable = is_retryable_error(&error);
            let message = safe_error(&error);
            failed_response_with_latency(raw.to_string(), "CRAWL_FAILED", &message, retryable, started.elapsed().as_millis())
        }
    }
}

fn failed_response(url: String, code: &str, message: &str, retryable: bool) -> CrawlResponse {
    failed_response_with_latency(url, code, message, retryable, 0)
}

fn failed_response_with_latency(
    url: String,
    code: &str,
    message: &str,
    retryable: bool,
    latency_ms: u128,
) -> CrawlResponse {
    CrawlResponse {
        ok: false,
        url,
        final_url: None,
        title: None,
        description: None,
        language: None,
        content_type: None,
        text: None,
        ai_context: None,
        word_count: 0,
        character_count: 0,
        source_html_bytes: 0,
        quality: 0,
        method: "failed-safe".into(),
        latency_ms,
        stages: Stages::default(),
        warnings: Vec::new(),
        error: Some(Failure {
            code: code.into(),
            message: message.into(),
            retryable,
        }),
    }
}

fn json_response<T: Serialize>(status: u16, value: &T) -> Result<Response<ResponseBody>, Error> {
    let status = http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
    let bytes = serde_json::to_vec(value)?;
    Ok(Response::builder()
        .status(status)
        .header("access-control-allow-origin", "*")
        .header("access-control-allow-methods", "POST, OPTIONS")
        .header("access-control-allow-headers", "content-type, authorization, x-arix-crawler-token")
        .header("content-type", "application/json; charset=utf-8")
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .body(ResponseBody::from(bytes))?)
}

async fn crawl(raw: &str, max_text: Option<usize>, include_ai_context: bool) -> Result<CrawlResponse> {
    let total = Instant::now();
    let mut stages = Stages::default();
    let mut warnings = Vec::new();

    if raw.len() > MAX_URL_LEN {
        return Err(anyhow!("URL_TOO_LONG"));
    }

    let validation = Instant::now();
    let initial = validate_target(raw).await?;
    let original_url = initial.url.to_string();
    stages.validation_ms = validation.elapsed().as_millis();

    let fetch = Instant::now();
    let mut fetched = fetch_with_safe_redirects(initial).await?;
    if matches!(fetched.response.status(), StatusCode::FORBIDDEN | StatusCode::NOT_FOUND)
        && !fetched.final_target.url.host_str().unwrap_or_default().ends_with("web.archive.org")
    {
        let archive = timeout(Duration::from_secs(4), fetch_archive_snapshot(&original_url)).await;
        if let Ok(Ok(archive_fetch)) = archive {
            fetched = archive_fetch;
            warnings.push("archive_snapshot_fallback_used".into());
        }
    }
    stages.fetch_ms = fetch.elapsed().as_millis();
    stages.dns_ms = fetched.dns_ms;
    stages.redirect_ms = fetched.redirect_ms;

    let status = fetched.response.status();
    let final_url = fetched.final_target.url.to_string();
    let content_type = fetched
        .response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string();

    if status == StatusCode::TOO_MANY_REQUESTS {
        return Err(anyhow!("RATE_LIMITED_429"));
    }
    if status == StatusCode::UNAUTHORIZED {
        return Err(anyhow!("AUTHENTICATION_REQUIRED"));
    }
    if status == StatusCode::FORBIDDEN {
        return Err(anyhow!("FORBIDDEN_OR_BOT_PROTECTION"));
    }
    if status.is_client_error() {
        return Err(anyhow!("HTTP_{}", status.as_u16()));
    }
    if status.is_server_error() {
        return Err(anyhow!("UPSTREAM_{}", status.as_u16()));
    }

    let is_html = content_type.contains("text/html")
        || content_type.contains("application/xhtml+xml")
        || content_type.is_empty();
    if !is_html {
        return Err(anyhow!("UNSUPPORTED_CONTENT_TYPE:{}", content_type));
    }

    let read = Instant::now();
    let mut sanitizer = StreamingHtmlSanitizer::default();
    let mut source_bytes = 0usize;
    let mut truncated = false;
    let mut body_stream = fetched.response.bytes_stream();

    while let Some(chunk) = body_stream.next().await {
        let chunk = chunk.context("BODY_READ_FAILED")?;
        let remaining = MAX_HTML_BYTES.saturating_sub(source_bytes);
        if remaining == 0 {
            truncated = true;
            break;
        }
        let take = chunk.len().min(remaining);
        sanitizer.push(&chunk[..take]);
        source_bytes = source_bytes.saturating_add(take);
        if take < chunk.len() || source_bytes >= MAX_HTML_BYTES {
            truncated = true;
            break;
        }
    }
    sanitizer.finish();
    stages.read_ms = read.elapsed().as_millis();
    if truncated {
        warnings.push("source_html_early_bailout_at_2mb".into());
    }

    let clean_bytes = sanitizer.into_output();
    let parse = Instant::now();
    let html = String::from_utf8_lossy(&clean_bytes).into_owned();
    let document = Html::parse_document(&html);
    stages.parse_ms = parse.elapsed().as_millis();

    let extract = Instant::now();
    let (title, description, language, mut text, stats, extraction_warnings) = extract_full_document(&document);
    let structured_text = extract_structured_json_text(&document);
    let structured_added = !structured_text.is_empty()
        && (text.split_whitespace().count() < 100 || text.len() < structured_text.len() / 2);
    if structured_added {
        text = normalize_document_text(&format!("{}\n\n{}", text, structured_text));
        warnings.push("embedded_json_or_hydration_content_extracted".into());
    }
    stages.extraction_ms = extract.elapsed().as_millis();
    warnings.extend(extraction_warnings);
    if fetched.archive_fallback {
        warnings.push("content_is_from_public_wayback_snapshot".into());
    }

    if let Some(cap) = max_text {
        let cap = cap.clamp(1000, 500_000);
        if text.len() > cap {
            text = truncate_utf8_safely(&text, cap);
            warnings.push("explicit_max_text_cap_applied".into());
        }
    }

    let audit = Instant::now();
    let words = text.split_whitespace().count();
    let lower = text.to_ascii_lowercase();
    let mut quality = quality_score(words, &stats, text.len());

    if structured_added && words >= 40 {
        quality = quality.max(62);
    }
    if words < 30 {
        quality = quality.min(35);
        warnings.push("very_little_meaningful_text".into());
    }
    if lower.contains("enable javascript")
        || lower.contains("checking your browser")
        || lower.contains("verify you are human")
        || lower.contains("just a moment")
    {
        warnings.push("possible_js_or_bot_challenge".into());
        quality = quality.min(25);
    }
    if lower.contains("sign in") && words < 120 {
        warnings.push("possible_auth_wall".into());
        quality = quality.min(45);
    }
    if html_indicates_dynamic_shell(&document, words) && !structured_added {
        warnings.push("dynamic_shell_detected_static_content_only".into());
    }
    if stats.density_blocks_skipped > 0 {
        warnings.push(format!("filtered_{}_low_text_density_blocks", stats.density_blocks_skipped));
    }
    if quality < 40 {
        warnings.push("low_confidence_but_content_preserved".into());
    }
    stages.audit_ms = audit.elapsed().as_millis();

    let ai_context = include_ai_context.then(|| {
        format!(
            "SOURCE: {}\nTITLE: {}\nQUALITY: {}/100\n\n{}",
            final_url,
            title.as_deref().unwrap_or("Untitled"),
            quality,
            text
        )
    });

    Ok(CrawlResponse {
        ok: true,
        url: raw.to_string(),
        final_url: Some(final_url),
        title,
        description,
        language,
        content_type: Some(content_type),
        character_count: text.chars().count(),
        word_count: words,
        source_html_bytes: source_bytes,
        quality,
        method: if fetched.archive_fallback {
            "archive-static-streaming-dom".into()
        } else if structured_added {
            "static-streaming-dom+structured-json".into()
        } else {
            "static-streaming-dom-density".into()
        },
        latency_ms: total.elapsed().as_millis(),
        stages,
        warnings,
        text: Some(text),
        ai_context,
        error: None,
    })
}

async fn fetch_with_safe_redirects(mut target: SafeTarget) -> Result<FetchResult> {
    let mut visited = HashSet::new();
    let mut redirect_count = 0usize;
    let mut redirect_ms = 0u128;
    let mut dns_ms = 0u128;

    loop {
        let current = target.url.to_string();
        if !visited.insert(current) {
            return Err(anyhow!("REDIRECT_LOOP"));
        }

        let client = client_for_target(&target)?;
        let request = client
            .get(target.url.clone())
            .header(header::ACCEPT, "text/html,application/xhtml+xml;q=0.9,text/plain;q=0.7,*/*;q=0.2")
            .header(header::ACCEPT_LANGUAGE, "en-IN,en;q=0.9")
            .header("cache-control", "no-cache");

        let timer = Instant::now();
        let response = request.send().await.context("FETCH_FAILED")?;
        redirect_ms += timer.elapsed().as_millis();

        if !response.status().is_redirection() {
            return Ok(FetchResult {
                response,
                final_target: target,
                redirect_ms,
                dns_ms,
                archive_fallback: false,
            });
        }

        if redirect_count >= MAX_REDIRECTS {
            return Err(anyhow!("REDIRECT_LIMIT"));
        }
        let location = response
            .headers()
            .get(header::LOCATION)
            .ok_or_else(|| anyhow!("REDIRECT_WITHOUT_LOCATION"))?
            .to_str()
            .context("BAD_LOCATION")?;
        let next = target.url.join(location).context("INVALID_REDIRECT")?;

        let dns_timer = Instant::now();
        target = validate_target(next.as_str()).await?;
        dns_ms += dns_timer.elapsed().as_millis();
        redirect_count += 1;
    }
}

async fn fetch_archive_snapshot(original_url: &str) -> Result<FetchResult> {
    let mut cdx = Url::parse("https://web.archive.org/cdx/search/cdx")?;
    cdx.query_pairs_mut()
        .append_pair("url", original_url)
        .append_pair("output", "json")
        .append_pair("fl", "timestamp,original,statuscode")
        .append_pair("filter", "statuscode:200")
        .append_pair("collapse", "digest")
        .append_pair("limit", "1");

    let cdx_target = validate_target(cdx.as_str()).await?;
    let cdx_fetch = fetch_with_safe_redirects(cdx_target).await?;
    if !cdx_fetch.response.status().is_success() {
        return Err(anyhow!("ARCHIVE_INDEX_UNAVAILABLE"));
    }
    let body = read_response_limited(cdx_fetch.response, 128 * 1024).await?;
    let rows: Vec<Vec<String>> = serde_json::from_slice(&body).context("ARCHIVE_INDEX_INVALID")?;
    let row = rows
        .iter()
        .skip(1)
        .find(|row| row.len() >= 3 && row[0].chars().all(|c| c.is_ascii_digit()) && row[2] == "200")
        .ok_or_else(|| anyhow!("ARCHIVE_SNAPSHOT_NOT_FOUND"))?;

    let snapshot = format!("https://web.archive.org/web/{}id_/{}", row[0], row[1]);
    let snapshot_target = validate_target(&snapshot).await?;
    let mut fetched = fetch_with_safe_redirects(snapshot_target).await?;
    if !fetched.response.status().is_success() {
        return Err(anyhow!("ARCHIVE_SNAPSHOT_UNAVAILABLE"));
    }
    fetched.archive_fallback = true;
    Ok(fetched)
}

async fn read_response_limited(response: reqwest::Response, maximum: usize) -> Result<Vec<u8>> {
    let mut stream = response.bytes_stream();
    let mut out = Vec::with_capacity(maximum.min(32 * 1024));
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("BODY_READ_FAILED")?;
        let remaining = maximum.saturating_sub(out.len());
        if remaining == 0 {
            break;
        }
        let take = chunk.len().min(remaining);
        out.extend_from_slice(&chunk[..take]);
        if take < chunk.len() || out.len() >= maximum {
            break;
        }
    }
    Ok(out)
}

fn client_for_target(target: &SafeTarget) -> Result<Client> {
    let host = target.url.host_str().ok_or_else(|| anyhow!("MISSING_HOST"))?;
    let port = target.url.port_or_known_default().unwrap_or(443);
    let key = format!("{}:{}:{}", host, port, target.ip);
    let pool = CLIENT_POOL.get_or_init(|| Mutex::new(ClientPool::default()));

    {
        let mut guard = pool.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(client) = guard.clients.get(&key).cloned() {
            guard.touch(&key);
            return Ok(client);
        }
    }

    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .timeout(Duration::from_secs(FETCH_TIMEOUT_SECS))
        .pool_max_idle_per_host(16)
        .pool_idle_timeout(Duration::from_secs(60))
        .http2_adaptive_window(true)
        .http2_initial_stream_window_size(1024 * 1024)
        .http2_initial_connection_window_size(4 * 1024 * 1024)
        .gzip(true)
        .brotli(true)
        .deflate(true)
        .zstd(true)
        .user_agent(USER_AGENT)
        .resolve(host, SocketAddr::new(target.ip, port))
        .build()?;

    let mut guard = pool.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = guard.clients.get(&key).cloned() {
        guard.touch(&key);
        return Ok(existing);
    }
    guard.insert(key, client.clone());
    Ok(client)
}

async fn validate_target(raw: &str) -> Result<SafeTarget> {
    let mut url = Url::parse(raw).context("INVALID_URL")?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(anyhow!("UNSUPPORTED_SCHEME"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(anyhow!("USERINFO_NOT_ALLOWED"));
    }
    url.set_fragment(None);

    let host = url.host_str().ok_or_else(|| anyhow!("MISSING_HOST"))?.to_ascii_lowercase();
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".home.arpa")
    {
        return Err(anyhow!("PRIVATE_HOST"));
    }

    let port = url.port_or_known_default().ok_or_else(|| anyhow!("BAD_PORT"))?;
    if !matches!(port, 80 | 443) {
        return Err(anyhow!("PORT_NOT_ALLOWED"));
    }

    let ip = match url.host() {
        Some(url::Host::Ipv4(address)) => IpAddr::V4(address),
        Some(url::Host::Ipv6(address)) => IpAddr::V6(address),
        _ => {
            let mut addresses = timeout(
                Duration::from_secs(CONNECT_TIMEOUT_SECS),
                lookup_host((host.as_str(), port)),
            )
            .await
            .context("DNS_TIMEOUT")?
            .context("DNS_FAILED")?;
            let mut selected = None;
            while let Some(address) = addresses.next() {
                if is_public_ip(address.ip()) {
                    selected = Some(address.ip());
                    break;
                }
            }
            selected.ok_or_else(|| anyhow!("NO_PUBLIC_IP"))?
        }
    };

    if !is_public_ip(ip) {
        return Err(anyhow!("PRIVATE_OR_RESERVED_IP"));
    }
    Ok(SafeTarget { url, ip })
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => {
            let octets = address.octets();
            let in_192_0_0_0_24 = octets[0] == 192 && octets[1] == 0 && octets[2] == 0;
            !(address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || in_192_0_0_0_24
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 198 && (18..=19).contains(&octets[1]))
                || octets[0] >= 224)
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(mapped));
            }
            let octets = address.octets();
            let global_unicast = octets[0] & 0xe0 == 0x20;
            let documentation_range = octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x0d && octets[3] == 0xb8;
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                || address.is_multicast()
                || !global_unicast
                || documentation_range)
        }
    }
}

fn split_url_field(value: &str, output: &mut Vec<String>) {
    for token in value.split(|c: char| c == ',' || c == '\n' || c == '\r' || c.is_whitespace()) {
        let token = token.trim();
        if !token.is_empty() {
            output.push(token.to_string());
        }
    }
}

#[derive(Default)]
struct StreamingHtmlSanitizer {
    pending: Vec<u8>,
    output: Vec<u8>,
    ignored_tag: Option<String>,
}

impl StreamingHtmlSanitizer {
    fn push(&mut self, chunk: &[u8]) {
        self.pending.extend_from_slice(chunk);
        self.process(false);
    }

    fn finish(&mut self) {
        self.process(true);
    }

    fn into_output(self) -> Vec<u8> {
        self.output
    }

    fn process(&mut self, final_chunk: bool) {
        loop {
            if let Some(ignored) = self.ignored_tag.clone() {
                let closing = format!("</{}", ignored);
                if let Some(position) = find_ascii_case_insensitive(&self.pending, closing.as_bytes()) {
                    if let Some(end_offset) = self.pending[position..].iter().position(|byte| *byte == b'>') {
                        self.pending.drain(..position + end_offset + 1);
                        self.ignored_tag = None;
                        continue;
                    }
                    if position > 0 {
                        self.pending.drain(..position);
                    }
                    break;
                }
                if final_chunk {
                    self.pending.clear();
                    break;
                }
                let keep = closing.len() + 4;
                if self.pending.len() > keep {
                    let remove = self.pending.len() - keep;
                    self.pending.drain(..remove);
                }
                break;
            }

            if self.pending.starts_with(b"<!--") {
                if let Some(position) = find_bytes(&self.pending, b"-->") {
                    self.pending.drain(..position + 3);
                    continue;
                }
                if final_chunk || self.pending.len() > MAX_TAG_BUFFER_BYTES {
                    self.pending.clear();
                }
                break;
            }

            let Some(open_position) = self.pending.iter().position(|byte| *byte == b'<') else {
                self.output.extend(self.pending.drain(..));
                break;
            };
            if open_position > 0 {
                self.output.extend(self.pending.drain(..open_position));
                continue;
            }

            if self.pending.len() < 2 {
                break;
            }
            let next = self.pending[1];
            if !(next.is_ascii_alphabetic() || next == b'/' || next == b'!' || next == b'?') {
                self.output.push(self.pending.remove(0));
                continue;
            }
            let Some(end_position) = self.pending.iter().position(|byte| *byte == b'>') else {
                if self.pending.len() > MAX_TAG_BUFFER_BYTES {
                    self.pending.clear();
                }
                break;
            };

            let tag_token: Vec<u8> = self.pending.drain(..=end_position).collect();
            let (tag_name, closing, self_closing) = parse_tag_name(&tag_token);
            if tag_name.is_empty() {
                self.output.extend_from_slice(&tag_token);
                continue;
            }

            let lower_token = String::from_utf8_lossy(&tag_token).to_ascii_lowercase();
            if !closing && !self_closing && should_strip_tag(&tag_name, &lower_token) {
                self.ignored_tag = Some(tag_name);
                continue;
            }
            if !closing && tag_name == "script" && !should_keep_json_script(&lower_token) {
                self.ignored_tag = Some(tag_name);
                continue;
            }
            self.output.extend_from_slice(&tag_token);
        }

        if final_chunk && self.ignored_tag.is_none() && !self.pending.is_empty() {
            if !self.pending.starts_with(b"<") {
                self.output.extend(self.pending.drain(..));
            } else {
                self.pending.clear();
            }
        }
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn find_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window.eq_ignore_ascii_case(needle))
}

fn parse_tag_name(token: &[u8]) -> (String, bool, bool) {
    if token.len() < 3 {
        return (String::new(), false, false);
    }
    let mut index = 1usize;
    let closing = token.get(index) == Some(&b'/');
    if closing {
        index += 1;
    }
    while token.get(index).is_some_and(|byte| byte.is_ascii_whitespace()) {
        index += 1;
    }
    let start = index;
    while token.get(index).is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b':') {
        index += 1;
    }
    let name = String::from_utf8_lossy(&token[start..index]).to_ascii_lowercase();
    let self_closing = token[..token.len().saturating_sub(1)].iter().rev().find(|byte| !byte.is_ascii_whitespace()).is_some_and(|byte| **byte == b'/');
    (name, closing, self_closing)
}

fn should_strip_tag(name: &str, token: &str) -> bool {
    matches!(name, "style" | "svg" | "nav" | "noscript" | "template" | "iframe" | "object" | "embed" | "form")
        || (name == "script" && !should_keep_json_script(token))
}

fn should_keep_json_script(token: &str) -> bool {
    token.contains("application/ld+json")
        || token.contains("__next_data__")
        || token.contains("__nuxt_data__")
        || token.contains("data-hydration")
        || token.contains("application/json")
}

fn extract_full_document(
    doc: &Html,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    ExtractionStats,
    Vec<String>,
) {
    let mut warnings = Vec::new();
    let title = select_first_text(doc, "title");
    let description = Selector::parse("meta[name='description'],meta[property='og:description']")
        .ok()
        .and_then(|selector| doc.select(&selector).next())
        .and_then(|node| node.value().attr("content"))
        .map(|value| clean(value.to_string()))
        .filter(|value| !value.is_empty());
    let language = Selector::parse("html")
        .ok()
        .and_then(|selector| doc.select(&selector).next())
        .and_then(|node| node.value().attr("lang"))
        .map(str::to_string);

    let root = Selector::parse("body")
        .ok()
        .and_then(|selector| doc.select(&selector).next())
        .or_else(|| Some(doc.root_element()));
    let mut output = String::new();
    let mut stats = ExtractionStats::default();
    if let Some(root) = root {
        walk_complete(root, &mut output, &mut stats);
    }
    let text = normalize_document_text(&output);
    if text.is_empty() {
        warnings.push("no_visible_text_found".into());
    }
    if stats.skipped_noise_nodes > 0 {
        warnings.push(format!("filtered_{}_obvious_noise_nodes", stats.skipped_noise_nodes));
    }
    if stats.hidden_nodes > 0 {
        warnings.push(format!("ignored_{}_hidden_or_aria_hidden_nodes", stats.hidden_nodes));
    }
    (title, description, language, text, stats, warnings)
}

fn walk_complete(node: ElementRef<'_>, output: &mut String, stats: &mut ExtractionStats) {
    let value = node.value();
    let tag = value.name();
    if should_skip_entire_node(&node) {
        stats.skipped_noise_nodes = stats.skipped_noise_nodes.saturating_add(1);
        return;
    }
    if is_hidden_element(&node) {
        stats.hidden_nodes = stats.hidden_nodes.saturating_add(1);
        return;
    }
    if should_skip_low_density_block(&node) {
        stats.density_blocks_skipped = stats.density_blocks_skipped.saturating_add(1);
        return;
    }

    let is_block = is_block_tag(tag);
    if is_block && !output.is_empty() {
        output.push_str("\n\n");
    }
    match tag {
        "p" => stats.paragraphs = stats.paragraphs.saturating_add(1),
        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => stats.headings = stats.headings.saturating_add(1),
        "a" => stats.links = stats.links.saturating_add(1),
        _ => {}
    }

    let mut had_text = false;
    for child in node.children() {
        if let Some(element) = ElementRef::wrap(child) {
            walk_complete(element, output, stats);
        } else if let Some(text) = child.value().as_text() {
            let value = text.trim();
            if !value.is_empty() {
                if !output.is_empty() && !ends_with_separator(output) {
                    output.push(' ');
                }
                output.push_str(value);
                stats.emitted_words = stats.emitted_words.saturating_add(value.split_whitespace().count());
                had_text = true;
            }
        }
    }
    if is_block && (had_text || ends_with_non_separator(output)) {
        output.push_str("\n\n");
        stats.emitted_blocks = stats.emitted_blocks.saturating_add(1);
    }
}

fn should_skip_entire_node(node: &ElementRef<'_>) -> bool {
    let tag = node.value().name();
    if matches!(tag, "script" | "style" | "template" | "svg" | "canvas" | "iframe" | "object" | "embed" | "form" | "nav" | "footer") {
        return true;
    }
    let attributes = format!("{} {}", node.value().id().unwrap_or(""), node.value().attr("class").unwrap_or("")).to_ascii_lowercase();
    const NOISE: [&str; 28] = [
        "cookie-banner", "cookie-consent", "consent-banner", "consent-manager", "advertisement", "ad-container",
        "ad-slot", "adsbygoogle", "sponsored-content", "newsletter-signup", "newsletter-form", "social-share",
        "share-tools", "breadcrumb", "login-modal", "signup-modal", "paywall", "modal-overlay", "sidebar",
        "related-articles", "related-posts", "recommended-content", "popular-posts", "read-next", "pagination",
        "post-navigation", "widget-area", "cookie-settings",
    ];
    NOISE.iter().any(|marker| attributes.contains(marker))
}

fn should_skip_low_density_block(node: &ElementRef<'_>) -> bool {
    let tag = node.value().name();
    let attributes = format!("{} {}", node.value().id().unwrap_or(""), node.value().attr("class").unwrap_or("")).to_ascii_lowercase();
    let tagged_candidate = matches!(tag, "aside" | "ul" | "ol" | "li")
        || ((tag == "div" || tag == "section")
            && ["sidebar", "related", "recommend", "popular", "read-next", "trending", "widget", "more-stories"]
                .iter()
                .any(|marker| attributes.contains(marker)));
    if !tagged_candidate {
        return false;
    }
    let mut metrics = DensityMetrics::default();
    collect_density(node, false, &mut metrics);
    if metrics.links < 3 || metrics.words < 8 {
        return false;
    }
    let score = (metrics.words + metrics.punctuation) as f64 / (metrics.links + 1) as f64;
    let linked_ratio = metrics.linked_words as f64 / metrics.words.max(1) as f64;
    score < 3.0 || (linked_ratio > 0.60 && score < 12.0)
}

fn collect_density(node: &ElementRef<'_>, inside_link: bool, metrics: &mut DensityMetrics) {
    for child in node.children() {
        if let Some(element) = ElementRef::wrap(child) {
            let tag = element.value().name();
            if matches!(tag, "script" | "style" | "svg" | "nav" | "footer") || is_hidden_element(&element) {
                continue;
            }
            if tag == "a" {
                metrics.links = metrics.links.saturating_add(1);
                collect_density(&element, true, metrics);
            } else {
                collect_density(&element, inside_link, metrics);
            }
        } else if let Some(text) = child.value().as_text() {
            let word_count = text.split_whitespace().count();
            metrics.words = metrics.words.saturating_add(word_count);
            if inside_link {
                metrics.linked_words = metrics.linked_words.saturating_add(word_count);
            }
            metrics.punctuation = metrics.punctuation.saturating_add(
                text.chars().filter(|character| matches!(character, '.' | ',' | ';' | ':' | '!' | '?')).count(),
            );
        }
    }
}

fn extract_structured_json_text(doc: &Html) -> String {
    let Ok(selector) = Selector::parse(
        "script[type='application/ld+json'],script#__NEXT_DATA__,script#__NUXT_DATA__,script[data-hydration],script[type='application/json']",
    ) else {
        return String::new();
    };
    let mut fragments = Vec::new();
    let mut seen = HashSet::new();
    let mut budget = MAX_JSON_TEXT_BYTES;

    for script in doc.select(&selector) {
        if budget == 0 {
            break;
        }
        let raw = script.text().collect::<String>();
        let Ok(value) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        collect_json_strings(&value, None, &mut fragments, &mut seen, &mut budget);
    }
    normalize_document_text(&fragments.join("\n\n"))
}

fn collect_json_strings(
    value: &Value,
    parent_key: Option<&str>,
    output: &mut Vec<String>,
    seen: &mut HashSet<String>,
    budget: &mut usize,
) {
    if *budget == 0 {
        return;
    }
    match value {
        Value::String(text) => {
            let normalized = clean(text.to_string());
            let key = parent_key.unwrap_or("").to_ascii_lowercase();
            let content_key = matches!(key.as_str(), "articlebody" | "description" | "abstract" | "text" | "content" | "headline" | "name" | "title" | "summary" | "caption" | "rendered");
            let looks_like_content = normalized.split_whitespace().count() >= 8
                && normalized.len() >= 48
                && !normalized.starts_with("http://")
                && !normalized.starts_with("https://")
                && !normalized.contains("data:image/");
            if (content_key || normalized.len() >= 120) && looks_like_content && seen.insert(normalized.clone()) {
                let take = normalized.len().min(*budget);
                let fragment = truncate_utf8_safely(&normalized, take);
                *budget = (*budget).saturating_sub(fragment.len());
                output.push(fragment);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_json_strings(item, parent_key, output, seen, budget);
                if *budget == 0 {
                    break;
                }
            }
        }
        Value::Object(map) => {
            for (key, child) in map {
                let lower_key = key.to_ascii_lowercase();
                if matches!(lower_key.as_str(), "url" | "@id" | "image" | "images" | "src" | "href" | "id" | "thumbnail" | "logo") {
                    continue;
                }
                collect_json_strings(child, Some(key), output, seen, budget);
                if *budget == 0 {
                    break;
                }
            }
        }
        _ => {}
    }
}

fn is_hidden_element(node: &ElementRef<'_>) -> bool {
    let value = node.value();
    if value.attr("aria-hidden") == Some("true") {
        return true;
    }
    let style = value.attr("style").unwrap_or("").to_ascii_lowercase();
    style.contains("display:none")
        || style.contains("display: none")
        || style.contains("visibility:hidden")
        || style.contains("visibility: hidden")
        || style.contains("content-visibility:hidden")
        || style.contains("content-visibility: hidden")
}

fn is_block_tag(tag: &str) -> bool {
    matches!(
        tag,
        "address" | "article" | "aside" | "blockquote" | "caption" | "dd" | "div" | "dl" | "dt" |
        "fieldset" | "figcaption" | "figure" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "header" |
        "hr" | "li" | "main" | "ol" | "p" | "pre" | "section" | "table" | "tbody" | "td" |
        "tfoot" | "th" | "thead" | "tr" | "ul" | "details" | "summary"
    )
}

fn select_first_text(doc: &Html, selector_text: &str) -> Option<String> {
    Selector::parse(selector_text)
        .ok()
        .and_then(|selector| doc.select(&selector).next())
        .map(|node| clean(node.text().collect::<Vec<_>>().join(" ")))
        .filter(|value| !value.is_empty())
}

fn quality_score(words: usize, stats: &ExtractionStats, characters: usize) -> u8 {
    if words == 0 {
        return 0;
    }
    let mut score = 45i64;
    score += (words.min(12_000) / 120) as i64;
    score += (stats.paragraphs.min(80) / 4) as i64;
    score += stats.headings.min(12) as i64 * 2;
    if characters > 1000 {
        score += 10;
    }
    if characters > 10_000 {
        score += 10;
    }
    score.clamp(0, 100) as u8
}

fn html_indicates_dynamic_shell(doc: &Html, words: usize) -> bool {
    if words > 80 {
        return false;
    }
    ["[id*='root']", "[id*='app']", "[id*='__next']", "[id*='svelte']"]
        .iter()
        .any(|selector_text| {
            Selector::parse(selector_text)
                .ok()
                .is_some_and(|selector| doc.select(&selector).next().is_some())
        })
}

fn normalize_document_text(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut pending_space = false;
    let mut pending_breaks = 0usize;
    for character in input.chars() {
        if character == '\n' || character == '\r' {
            pending_breaks = (pending_breaks + 1).min(2);
            pending_space = false;
            continue;
        }
        if character.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_breaks > 0 {
            while output.ends_with(' ') {
                output.pop();
            }
            if !output.is_empty() {
                output.push_str("\n\n");
            }
            pending_breaks = 0;
            pending_space = false;
        } else if pending_space && !output.is_empty() && !output.ends_with(' ') && !output.ends_with('\n') {
            output.push(' ');
            pending_space = false;
        }
        output.push(character);
    }
    output.trim().to_string()
}

fn truncate_utf8_safely(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    input[..end].to_string()
}

fn clean(input: String) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn ends_with_separator(value: &str) -> bool {
    value.as_bytes().last().is_some_and(|byte| matches!(*byte, b' ' | b'\n' | b'\r' | b'\t'))
}

fn ends_with_non_separator(value: &str) -> bool {
    !value.is_empty() && !ends_with_separator(value)
}

fn is_retryable_error(error: &anyhow::Error) -> bool {
    let text = error.to_string();
    text.contains("FETCH_FAILED")
        || text.contains("DNS_FAILED")
        || text.contains("BODY_READ_FAILED")
        || text.contains("UPSTREAM_")
        || text.contains("RATE_LIMITED")
        || text.contains("ARCHIVE_")
}

fn safe_error(error: &anyhow::Error) -> String {
    error.to_string().chars().take(180).collect()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_stream_sanitizer_removes_script_but_preserves_structured_json() {
        let mut sanitizer = StreamingHtmlSanitizer::default();
        sanitizer.push(b"<html><body><script>const secret = 'noise';</script><p>Article text.</p>");
        sanitizer.push(b"<script type=\"application/ld+json\">{\"articleBody\":\"Useful article body content.\"}</script></body></html>");
        sanitizer.finish();
        let output = String::from_utf8(sanitizer.into_output()).expect("sanitized HTML should remain UTF-8");
        assert!(!output.contains("const secret"));
        assert!(output.contains("application/ld+json"));
        assert!(output.contains("Article text"));
    }

    #[test]
    fn tokenizer_recognizes_self_closing_and_closing_tags() {
        assert_eq!(parse_tag_name(b"<img src='x' />"), ("img".to_string(), false, true));
        assert_eq!(parse_tag_name(b"</article>"), ("article".to_string(), true, false));
    }

    #[test]
    fn private_and_documentation_addresses_are_rejected() {
        assert!(!is_public_ip("127.0.0.1".parse().expect("valid IPv4")));
        assert!(!is_public_ip("10.1.2.3".parse().expect("valid IPv4")));
        assert!(!is_public_ip("192.0.2.10".parse().expect("valid IPv4")));
        assert!(!is_public_ip("2001:db8::1".parse().expect("valid IPv6")));
        assert!(is_public_ip("8.8.8.8".parse().expect("valid IPv4")));
    }

    #[test]
    fn extraction_drops_link_dense_related_lists_but_keeps_article_paragraphs() {
        let document = Html::parse_document(
            r#"<html><head><title>Test Article</title></head><body>
            <main><article><h1>Primary heading</h1><p>This is the actual article paragraph with enough useful words and punctuation. It explains the main topic clearly for a reader.</p></article>
            <aside class="related-articles"><ul>
            <li><a href="/a">Related one</a></li><li><a href="/b">Related two</a></li>
            <li><a href="/c">Related three</a></li><li><a href="/d">Related four</a></li>
            </ul></aside></main></body></html>"#,
        );
        let (_, _, _, text, stats, _) = extract_full_document(&document);
        assert!(text.contains("actual article paragraph"));
        assert!(!text.contains("Related one"));
        assert!(stats.density_blocks_skipped > 0);
    }
}
