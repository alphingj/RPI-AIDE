//! A minimal HTTP/1.1 client for the CLI to talk to a running service on
//! the same host: `rpi-aide --unban 1.2.3.4` and friends go through this.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

pub struct Request<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
    pub bearer: Option<&'a str>,
    pub action: bool,
    pub body: Option<&'a str>,
}

const TIMEOUT: Duration = Duration::from_secs(5);

pub fn request(request: &Request<'_>) -> Result<HttpResponse, String> {
    let address = resolve(request.host, request.port)?;
    let mut stream = TcpStream::connect_timeout(&address, TIMEOUT)
        .map_err(|error| format!("cannot reach the service at {address}: {error}"))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|error| format!("cannot set the socket timeout: {error}"))?;

    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\nUser-Agent: rpi-aide\r\n",
        request.method, request.path, request.host, request.port
    );
    if request.action {
        head.push_str("x-rpi-aide-scan: 1\r\n");
    }
    if let Some(token) = request.bearer {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    let body = request.body.unwrap_or("");
    if !body.is_empty() || request.method == "POST" {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        head.push_str("Content-Type: application/json\r\n");
    }
    head.push_str("\r\n");

    stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(body.as_bytes()))
        .map_err(|error| format!("request failed: {error}"))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| format!("response was cut off: {error}"))?;

    parse_response(&response)
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, String> {
    if let Ok(address) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(address, port));
    }
    (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("cannot resolve '{host}': {error}"))?
        .next()
        .ok_or_else(|| format!("'{host}' did not resolve to an address"))
}

fn parse_response(raw: &[u8]) -> Result<HttpResponse, String> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = match text.find("\r\n\r\n") {
        Some(split) => text.split_at(split + 4),
        None => (text.as_ref(), ""),
    };
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| "malformed response from the service".to_string())?;
    Ok(HttpResponse {
        status,
        body: body.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_parsing() {
        let parsed = parse_response(b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}")
            .expect("parse");
        assert_eq!(parsed.status, 404);
        assert_eq!(parsed.body, "{}");
        assert!(parse_response(b"garbage").is_err());
    }
}
