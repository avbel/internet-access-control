use tiny_http::{Header, Request, Response, StatusCode};

use crate::config::Config;
use crate::nftables::NftManager;
use crate::types::{
    Action, AliasEntry, AliasesResponse, DeviceStatus, DevicesStatusResponse, ErrorResponse,
    RuleRequest, StatusResponse,
};

pub fn handle_request(
    request: &mut Request,
    config: &Config,
    nft: &mut NftManager,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let path = request.url().split('?').next().unwrap_or("");

    match (request.method().as_str(), path) {
        ("POST", "/rule") => handle_rule(request, config, nft),
        ("GET", "/status") => handle_status(request, config, nft),
        ("GET", "/aliases") => handle_aliases(config),
        ("GET", "/statuses") => handle_statuses(config, nft),
        _ => json_response(
            StatusCode(404),
            &ErrorResponse {
                error: "not found".to_string(),
            },
        ),
    }
}

fn handle_rule(
    request: &mut Request,
    config: &Config,
    nft: &mut NftManager,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut body = String::new();

    if std::io::Read::read_to_string(&mut request.as_reader(), &mut body).is_err() {
        return json_response(
            StatusCode(400),
            &ErrorResponse {
                error: "failed to read body".to_string(),
            },
        );
    }

    let Ok(rule_request) = serde_json::from_str::<RuleRequest>(&body) else {
        return json_response(
            StatusCode(400),
            &ErrorResponse {
                error: "invalid JSON".to_string(),
            },
        );
    };

    let Some(mac) = config.resolve_device(&rule_request.device) else {
        return json_response(
            StatusCode(400),
            &ErrorResponse {
                error: format!("unknown device: {}", rule_request.device),
            },
        );
    };

    let result = match rule_request.action {
        Action::Deny => nft.deny(&mac),
        Action::Allow => nft.allow(&mac),
    };

    match result {
        Ok(()) => json_response(
            StatusCode(200),
            &serde_json::json!({
                "status": "ok",
                "device": rule_request.device,
                "mac": mac,
                "action": rule_request.action,
            }),
        ),
        Err(error) => json_response(StatusCode(500), &ErrorResponse { error }),
    }
}

fn handle_status(
    request: &Request,
    config: &Config,
    nft: &NftManager,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let query = request.url().split('?').nth(1).unwrap_or("");

    let device = query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        if key == "device" {
            Some(url_decode(value))
        } else {
            None
        }
    });

    let Some(device) = device else {
        return json_response(
            StatusCode(400),
            &ErrorResponse {
                error: "missing 'device' query parameter".to_string(),
            },
        );
    };

    let Some(mac) = config.resolve_device(&device) else {
        return json_response(
            StatusCode(400),
            &ErrorResponse {
                error: format!("unknown device: {device}"),
            },
        );
    };

    let response = StatusResponse {
        device,
        mac: mac.clone(),
        allowed: nft.is_allowed(&mac),
    };

    json_response(StatusCode(200), &response)
}

fn handle_aliases(config: &Config) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut aliases: Vec<AliasEntry> = config
        .devices
        .iter()
        .map(|(alias, mac)| AliasEntry {
            alias: alias.clone(),
            mac: mac.to_uppercase(),
        })
        .collect();

    aliases.sort_by(|a, b| a.alias.cmp(&b.alias));

    let response = AliasesResponse { aliases };

    json_response(StatusCode(200), &response)
}

fn handle_statuses(config: &Config, nft: &NftManager) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut devices: Vec<DeviceStatus> = config
        .devices
        .iter()
        .map(|(alias, mac)| {
            let mac_upper = mac.to_uppercase();
            DeviceStatus {
                alias: alias.clone(),
                mac: mac_upper.clone(),
                allowed: nft.is_allowed(&mac_upper),
            }
        })
        .collect();

    devices.sort_by(|a, b| a.alias.cmp(&b.alias));

    json_response(StatusCode(200), &DevicesStatusResponse { devices })
}

fn json_content_type_header() -> Header {
    #[allow(clippy::expect_used)]
    Header::from_bytes(b"Content-Type", b"application/json").expect("valid header")
}

fn json_response<T: serde::Serialize>(
    status: StatusCode,
    body: &T,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let json = serde_json::to_vec(body).unwrap_or_default();
    let cursor = std::io::Cursor::new(json);

    Response::new(status, vec![json_content_type_header()], cursor, None, None)
}

fn url_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars();

    while let Some(character) = chars.next() {
        if character == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                    continue;
                }
            }
            result.push('%');
            result.push_str(&hex);
        } else if character == '+' {
            result.push(' ');
        } else {
            result.push(character);
        }
    }

    result
}
