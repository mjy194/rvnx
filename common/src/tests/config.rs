use super::*;

#[test]
fn validates_dedicated_pools_and_total_connection_budget() {
    let mut config: ClientConfig = toml::from_str(
        r#"
        server = "127.0.0.1:7000"
        server_name = "localhost"
        token = "01234567890123456789012345678901"
        tls_ca = "cert.pem"
        [[proxies]]
        name = "model"
        protocol = "tcp"
        local = "127.0.0.1:8080"
    "#,
    )
    .unwrap();
    assert!(config.validate().is_ok());
    assert!(!config.multiplex_for(&config.proxies[0]));
    config.multiplex = true;
    assert!(config.multiplex_for(&config.proxies[0]));
    config.proxies[0].dedicated_pool_size = Some(0);
    assert!(config.validate().is_err());
    config.proxies[0].dedicated_pool_size = Some(33);
    assert!(config.validate().is_err());
    config.proxies[0].dedicated_pool_size = Some(32);
    let template = config.proxies[0].clone();
    config.proxies = (0..8)
        .map(|i| ClientProxy {
            name: format!("model-{i}"),
            ..template.clone()
        })
        .collect();
    assert!(config.validate().is_ok()); // Exactly 256; unused shared pool not counted.
    config.proxies.push(ClientProxy {
        name: "extra".into(),
        ..template
    });
    assert!(config.validate().is_err());
    // Explicit per-mapping opt-out takes precedence and consumes no pool slots.
    config.proxies.last_mut().unwrap().multiplex = Some(false);
    assert!(config.validate().is_ok());
    config.multiplex = false;
    config.proxies[0].multiplex = Some(true);
    assert!(config.multiplex_for(&config.proxies[0]));
    assert!(!config.multiplex_for(&config.proxies[1]));
}

#[test]
fn rejects_duplicate_names_and_weak_tokens() {
    let mut config: ServerConfig = toml::from_str(
        r#"
        bind = "127.0.0.1:7000"
        token = "01234567890123456789012345678901"
        tls_cert = "cert.pem"
        tls_key = "key.pem"
        [[proxies]]
        name = "web"
        protocol = "tcp"
        bind = "127.0.0.1:8080"
    "#,
    )
    .unwrap();
    assert!(config.validate().is_ok());
    config.proxies.push(config.proxies[0].clone());
    assert!(config.validate().is_err());
    config.proxies.pop();
    config.token = Some("short".into());
    assert!(config.validate().is_err());
}

#[test]
fn cloudflare_requires_consistent_identity_and_explicit_transport_choice() {
    let text = include_str!("../../../examples/clnt.cloudflare.toml").replace(
        "REPLACE_WITH_A_RANDOM_SECRET_AT_LEAST_32_BYTES",
        "01234567890123456789012345678901",
    );
    let mut config: ClientConfig = toml::from_str(&text).unwrap();
    assert!(config.validate().is_ok());
    config.server = "other.example.com:443".into();
    assert!(config.validate().is_err());
    config.server = "tunnel.example.com:443".into();
    config.proxies[0].multiplex = Some(false);
    assert!(config.validate().is_err());
    config.proxies[0].multiplex = None;
    config.cloudflare.as_mut().unwrap().candidates.clear();
    assert!(config.validate().is_err());
}

#[test]
fn rejects_unknown_fields() {
    assert!(
        toml::from_str::<ClientProxy>(
            r#"
        name = "dns"
        protocol = "udp"
        local = "127.0.0.1:53"
        typo = true
    "#
        )
        .is_err()
    );
}

fn client_fixture() -> ClientConfig {
    toml::from_str(
        &include_str!("../../../examples/clnt.cloudflare.toml").replace(
            "REPLACE_WITH_A_RANDOM_SECRET_AT_LEAST_32_BYTES",
            &"a".repeat(32),
        ),
    )
    .unwrap()
}
fn server_fixture() -> ServerConfig {
    toml::from_str(
        &include_str!("../../../examples/srv.cloudflare.toml").replace(
            "REPLACE_WITH_A_RANDOM_SECRET_AT_LEAST_32_BYTES",
            &"a".repeat(32),
        ),
    )
    .unwrap()
}
#[test]
fn token_and_proxy_identity_boundaries() {
    for (token, accepted) in [
        ("a".repeat(31), false),
        ("a".repeat(32), true),
        ("a".repeat(4096), true),
        ("a".repeat(4097), false),
        (format!("{} ", "a".repeat(32)), false),
        ("密钥".repeat(32), false),
        (
            "REPLACE_WITH_A_RANDOM_SECRET_AT_LEAST_32_BYTES".into(),
            false,
        ),
    ] {
        let mut client = client_fixture();
        client.token = token.clone();
        let mut server = server_fixture();
        server.token = Some(token);
        assert_eq!(client.validate().is_ok(), accepted);
        assert_eq!(server.validate().is_ok(), accepted);
    }
    for (name, accepted) in [
        ("".into(), false),
        ("a".repeat(64), true),
        ("a".repeat(65), false),
        ("valid_123-name".into(), true),
        ("name.with.dot".into(), false),
        ("服务".into(), false),
    ] {
        let mut client = client_fixture();
        client.proxies[0].name = name.clone();
        let mut server = server_fixture();
        server.proxies[0].name = name;
        assert_eq!(client.validate().is_ok(), accepted);
        assert_eq!(server.validate().is_ok(), accepted);
    }
    let mut client = client_fixture();
    client.proxies.push(client.proxies[0].clone());
    assert!(client.validate().is_err());
}
#[test]
fn client_and_server_numeric_limits_and_required_fields() {
    for (value, accepted) in [(0, false), (1, true), (4096, true), (4097, false)] {
        let mut c = client_fixture();
        c.proxies[0].max_connections = value;
        assert_eq!(c.validate().is_ok(), accepted);
        let mut s = server_fixture();
        s.proxies[0].max_connections = value;
        assert_eq!(s.validate().is_ok(), accepted);
    }
    for (value, accepted) in [(0, false), (1, true), (86400, true), (86401, false)] {
        let mut c = client_fixture();
        c.proxies[0].udp_timeout_secs = value;
        assert_eq!(c.validate().is_ok(), accepted);
        let mut s = server_fixture();
        s.proxies[0].udp_timeout_secs = value;
        assert_eq!(s.validate().is_ok(), accepted);
    }
    for (value, accepted) in [(0, false), (1, true), (300, true), (301, false)] {
        let mut c = client_fixture();
        c.reconnect_secs = value;
        assert_eq!(c.validate().is_ok(), accepted);
    }
    for (value, accepted) in [(0, false), (1, true), (600, true), (601, false)] {
        let mut s = server_fixture();
        s.proxies[0].connection_wait_secs = value;
        assert_eq!(s.validate().is_ok(), accepted);
    }
    for (value, accepted) in [(0, false), (1, true), (32, true), (33, false)] {
        let mut c = client_fixture();
        c.pool_size = value;
        assert_eq!(c.validate().is_ok(), accepted);
    }
    let mut c = client_fixture();
    c.proxies.clear();
    assert!(c.validate().is_err());
    let mut c = client_fixture();
    c.proxies[0].local.clear();
    assert!(c.validate().is_err());
    let mut c = client_fixture();
    c.server.clear();
    assert!(c.validate().is_err());
    let mut c = client_fixture();
    c.server_name.clear();
    assert!(c.validate().is_err());
    let mut s = server_fixture();
    s.proxies.clear();
    assert!(s.validate().is_err());
    let mut s = server_fixture();
    s.bind.set_port(0);
    assert!(s.validate().is_err());
    let mut s = server_fixture();
    s.proxies[0].bind.set_port(0);
    assert!(s.validate().is_err());
}
#[test]
fn server_bind_collisions_and_mixed_protocols() {
    let mut s = server_fixture();
    s.proxies[1].bind = s.proxies[0].bind;
    assert!(s.validate().is_err());
    s.proxies[1].protocol = Protocol::Udp;
    assert!(s.validate().is_ok());
    s.proxies[0].bind = s.bind;
    assert!(s.validate().is_err());
    s.proxies[0].protocol = Protocol::Udp;
    assert!(s.validate().is_ok());
}
#[test]
fn cloudflare_conflicting_modes_and_authorities_are_rejected() {
    let mut c = client_fixture();
    c.multiplex = true;
    assert!(c.validate().is_err());
    let mut c = client_fixture();
    c.proxies[0].dedicated_pool_size = Some(1);
    assert!(c.validate().is_err());
    let mut c = client_fixture();
    c.server = "not a valid authority".into();
    assert!(c.validate().is_err());
    let mut c = client_fixture();
    c.cloudflare.as_mut().unwrap().candidate_count = 0;
    assert!(c.validate().is_err());
    let mut c = client_fixture();
    c.cloudflare = None;
    c.multiplex = true;
    c.pool_size = 1;
    let template = c.proxies[0].clone();
    c.proxies = (0..8)
        .map(|i| ClientProxy {
            name: format!("p{i}"),
            dedicated_pool_size: Some(32),
            ..template.clone()
        })
        .collect();
    c.proxies.push(ClientProxy {
        name: "shared".into(),
        dedicated_pool_size: None,
        ..template
    });
    assert!(c.validate().is_err()); // 256 dedicated + 1 shared is over the global pool budget.
    c.proxies[0].dedicated_pool_size = Some(31);
    assert!(c.validate().is_ok());
}

#[test]
fn load_reports_io_and_toml_errors_and_preserves_defaults() {
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let file = Cleanup(std::env::temp_dir().join(format!(
        "rvnx-config-test-{}-{}.toml",
        std::process::id(),
        rand::random::<u64>()
    )));
    assert!(
        load::<ClientConfig>(&file.0)
            .err()
            .unwrap()
            .to_string()
            .contains("cannot read config")
    );
    std::fs::write(&file.0, "[[invalid").unwrap();
    assert!(
        load::<ClientConfig>(&file.0)
            .err()
            .unwrap()
            .to_string()
            .contains("invalid config")
    );
    let text = include_str!("../../../examples/clnt.cloudflare.toml").replace(
        "REPLACE_WITH_A_RANDOM_SECRET_AT_LEAST_32_BYTES",
        &"x".repeat(32),
    );
    std::fs::write(&file.0, text).unwrap();
    let config: ClientConfig = load(&file.0).unwrap();
    assert!(config.validate().is_ok());
    assert!(!config.multiplex);
    let mut config = client_fixture();
    config.cloudflare = None;
    config.multiplex = false;
    config.pool_size = 32;
    assert!(config.validate().is_ok());
    assert!(!config.multiplex_for(&config.proxies[0]));
}

#[test]
fn server_accepts_legacy_token_or_multiple_tokens_but_not_both() {
    let template = include_str!("../../../examples/srv.toml");
    let legacy = "token = \"REPLACE_WITH_A_RANDOM_SECRET_AT_LEAST_32_BYTES\"";
    let a = "a".repeat(32);
    let b = "b".repeat(32);
    for (credentials, accepted) in [
        (format!("token = {a:?}"), true),
        (format!("tokens = [{a:?}, {b:?}]"), true),
        (format!("tokens = [{a:?}]"), true),
        (String::new(), false),
        ("tokens = []".into(), false),
        (format!("token = {a:?}\ntokens = []"), false),
        (format!("token = {a:?}\ntokens = [{b:?}]"), false),
        (format!("tokens = [{a:?}, {a:?}]"), false),
        (format!("tokens = [{a:?}, \"\"]"), false),
        (format!("tokens = [{a:?}, \"short\"]"), false),
        (format!("tokens = [{a:?}, {:?}]", "x".repeat(4097)), false),
        (
            format!("tokens = [{a:?}, {:?}]", "with spaces".repeat(4)),
            false,
        ),
        (format!("tokens = [{a:?}, {:?}]", "密钥".repeat(32)), false),
        (
            format!("tokens = [{a:?}, \"REPLACE_WITH_A_RANDOM_SECRET_AT_LEAST_32_BYTES\"]"),
            false,
        ),
    ] {
        let config: ServerConfig = toml::from_str(&template.replace(legacy, &credentials)).unwrap();
        assert_eq!(config.validate().is_ok(), accepted);
        if accepted {
            assert!(!config.auth_tokens().is_empty());
        }
    }
}

fn policy_fixture() -> Policy {
    Policy {
        bind_ip: "127.0.0.1".parse().unwrap(),
        allowed_ports: vec![PortRange {
            start: 8000,
            end: 8010,
        }],
        protocols: vec![Protocol::Tcp, Protocol::Udp],
        max_mappings: 2,
    }
}

#[test]
fn policy_config_is_explicit_and_exclusive_with_legacy_mode() {
    let mut server = server_fixture();
    assert!(!server.is_policy_mode());
    server.policies = Some(vec![TokenPolicy {
        token: "b".repeat(32),
        policy: policy_fixture(),
    }]);
    assert!(server.is_policy_mode());
    assert!(server.validate().is_err());
    server.token = None;
    assert!(server.validate().is_err()); // Static proxies are not a fallback.
    server.proxies.clear();
    assert!(server.validate().is_ok());
    assert_eq!(server.auth_tokens(), vec!["b".repeat(32)]);
    server.tokens = Some(vec![]);
    assert!(server.validate().is_err());
    server.tokens = None;
    let entry = server.policies.as_ref().unwrap()[0].clone();
    server.policies.as_mut().unwrap().push(entry);
    assert!(server.validate().is_err());
    server.policies.as_mut().unwrap()[1].token = "c".repeat(32);
    assert!(server.validate().is_ok());
    server.policies.as_mut().unwrap()[1].token = "short".into();
    assert!(server.validate().is_err());
    server.policies = Some(vec![]);
    assert!(server.validate().is_err());
    server.token = Some("a".repeat(32));
    assert!(server.validate().is_err()); // Even an explicit empty list selects policy mode.
}

#[test]
fn policy_toml_requires_a_complete_policy_and_hides_credentials_on_wire() {
    let text = format!(
        r#"
        bind = "127.0.0.1:7000"
        tls_cert = "cert.pem"
        tls_key = "key.pem"
        [[policies]]
        token = "{}"
        [policies.policy]
        bind_ip = "127.0.0.1"
        allowed_ports = [{{ start = 8000, end = 8010 }}]
        protocols = ["tcp", "udp"]
        max_mappings = 2
    "#,
        "a".repeat(32)
    );
    let server: ServerConfig = toml::from_str(&text).unwrap();
    assert!(server.validate().is_ok());
    assert!(server.proxies.is_empty());
    let policy = &server.policies.as_ref().unwrap()[0].policy;
    let wire = serde_json::to_string(policy).unwrap();
    assert!(!wire.contains("token"));
    assert!(!wire.contains(&"a".repeat(32)));
    assert_eq!(serde_json::from_str::<Policy>(&wire).unwrap(), *policy);
    for missing in [
        "bind_ip = \"127.0.0.1\"",
        "allowed_ports = [{ start = 8000, end = 8010 }]",
        "protocols = [\"tcp\", \"udp\"]",
        "max_mappings = 2",
    ] {
        assert!(toml::from_str::<ServerConfig>(&text.replace(missing, "")).is_err());
    }
    assert!(
        toml::from_str::<ServerConfig>(
            &text.replace("max_mappings = 2", "max_mappings = 2\nextra = 1")
        )
        .is_err()
    );
}

#[test]
fn policy_limits_ranges_and_shared_mapping_validation() {
    let policy = policy_fixture();
    assert!(policy.validate().is_ok());
    for (name, protocol, port, valid) in [
        ("web", Protocol::Tcp, 8000, true),
        ("web", Protocol::Udp, 8010, true),
        ("web", Protocol::Tcp, 7999, false),
        ("web", Protocol::Tcp, 8011, false),
        ("web", Protocol::Tcp, 0, false),
        ("", Protocol::Tcp, 8000, false),
        ("bad.name", Protocol::Tcp, 8000, false),
    ] {
        assert_eq!(
            policy.validate_mapping(name, &protocol, port).is_ok(),
            valid
        );
    }
    let mut tcp_only = policy.clone();
    tcp_only.protocols = vec![Protocol::Tcp];
    assert!(
        tcp_only
            .validate_mapping("web", &Protocol::Udp, 8000)
            .is_err()
    );
    for limit in [0, 4097] {
        let mut invalid = policy.clone();
        invalid.max_mappings = limit;
        assert!(invalid.validate().is_err());
    }
    for protocols in [vec![], vec![Protocol::Tcp, Protocol::Tcp]] {
        let mut invalid = policy.clone();
        invalid.protocols = protocols;
        assert!(invalid.validate().is_err());
    }
    for ranges in [
        vec![],
        vec![PortRange { start: 0, end: 10 }],
        vec![PortRange { start: 10, end: 9 }],
        vec![
            PortRange { start: 10, end: 20 },
            PortRange { start: 20, end: 30 },
        ],
        (1..=129)
            .map(|port| PortRange {
                start: port,
                end: port,
            })
            .collect(),
    ] {
        let mut invalid = policy.clone();
        invalid.allowed_ports = ranges;
        assert!(invalid.validate().is_err());
    }
    let mut boundaries = policy;
    boundaries.max_mappings = 4096;
    boundaries.allowed_ports = vec![PortRange {
        start: 1,
        end: 65535,
    }];
    assert!(boundaries.validate().is_ok());
    assert!(
        boundaries
            .validate_mapping("web", &Protocol::Tcp, 65535)
            .is_ok()
    );
}

#[test]
fn policy_client_requires_explicit_mode_and_exact_nonzero_remote_ports() {
    let mut client = client_fixture();
    assert!(!client.policy_mode);
    assert!(
        client
            .proxies
            .iter()
            .all(|proxy| proxy.remote_port.is_none())
    );
    client.policy_mode = true;
    assert!(client.validate().is_err());
    for proxy in &mut client.proxies {
        proxy.remote_port = Some(8000);
    }
    assert!(client.validate().is_ok());
    client.proxies[0].remote_port = Some(0);
    assert!(client.validate().is_err());
    client.proxies[0].remote_port = Some(65535);
    assert!(client.validate().is_ok());
    client.policy_mode = false;
    assert!(client.validate().is_err());
}
