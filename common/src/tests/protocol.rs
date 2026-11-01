use super::*;

#[tokio::test]
async fn round_trip_empty_and_maximum_datagrams() {
    for data in [vec![], vec![42; MAX_DATAGRAM]] {
        let mut bytes = Vec::new();
        write_frame(
            &mut bytes,
            &Frame::Datagram {
                peer: 7,
                data: data.clone(),
            },
        )
        .await
        .unwrap();
        let Frame::Datagram { peer, data: actual } =
            read_frame(&mut bytes.as_slice()).await.unwrap()
        else {
            panic!()
        };
        assert_eq!(peer, 7);
        assert_eq!(actual, data);
    }
}

#[tokio::test]
async fn rejects_oversized_and_truncated_frames() {
    let bytes = u32::MAX.to_be_bytes();
    assert!(read_frame(&mut bytes.as_slice()).await.is_err());
    assert!(read_frame(&mut [0, 0, 0, 1, 2].as_slice()).await.is_err());
    assert!(read_frame(&mut [0, 0, 0, 1, 99].as_slice()).await.is_err());
}

#[tokio::test]
async fn control_parser_rejects_datagrams_and_invalid_control_payloads() {
    let mut data = Vec::new();
    write_frame(
        &mut data,
        &Frame::Datagram {
            peer: 1,
            data: vec![],
        },
    )
    .await
    .unwrap();
    assert!(
        read_control(&mut data.as_slice())
            .await
            .unwrap_err()
            .to_string()
            .contains("expected a control")
    );
    for json in [b"{".as_slice(), br#"{"type":"attach","extra":true}"#] {
        let mut bytes = ((json.len() + 1) as u32).to_be_bytes().to_vec();
        bytes.push(1);
        bytes.extend_from_slice(json);
        assert!(read_control(&mut bytes.as_slice()).await.is_err());
    }
}

#[tokio::test]
async fn control_and_datagram_write_limits_reject_without_partial_output() {
    for frame in [
        Frame::Control(Control::Error {
            message: "x".repeat(MAX_CONTROL),
        }),
        Frame::Datagram {
            peer: 1,
            data: vec![0; MAX_DATAGRAM + 1],
        },
    ] {
        let mut output = Vec::new();
        assert!(write_frame(&mut output, &frame).await.is_err());
        assert!(output.is_empty());
    }
    let mut bytes = ((MAX_CONTROL + 2) as u32).to_be_bytes().to_vec();
    bytes.push(1);
    assert!(
        read_frame(&mut bytes.as_slice())
            .await
            .unwrap_err()
            .to_string()
            .contains("control frame too large")
    );
}

#[tokio::test]
async fn truncated_frame_fields_report_eof_instead_of_accepting_partial_data() {
    for bytes in [
        vec![0, 0, 0, 1],                             // missing kind
        vec![0, 0, 0, 3, 1, b'{'],                    // incomplete control body
        vec![0, 0, 0, 9, 2, 0],                       // incomplete UDP peer ID
        vec![0, 0, 0, 10, 2, 0, 0, 0, 0, 0, 0, 0, 1], // missing UDP payload
    ] {
        let error = read_frame(&mut bytes.as_slice()).await.unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
}

struct FlushFailure(Vec<u8>);
impl AsyncWrite for FlushFailure {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.0.extend_from_slice(data);
        std::task::Poll::Ready(Ok(data.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}
#[tokio::test]
async fn a_frame_flush_failure_is_reported_even_after_its_bytes_were_written() {
    let mut writer = FlushFailure(Vec::new());
    let error = send_control(&mut writer, Control::Ping).await.unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::BrokenPipe
    );
    assert!(matches!(
        read_control(&mut writer.0.as_slice()).await.unwrap(),
        Control::Ping
    ));
}

#[tokio::test]
async fn policy_control_roundtrips_are_explicit_and_preserve_legacy_wire_format() {
    use crate::config::{Policy, PortRange, Protocol};
    let policy = Policy {
        bind_ip: "127.0.0.1".parse().unwrap(),
        allowed_ports: vec![PortRange {
            start: 8000,
            end: 8001,
        }],
        protocols: vec![Protocol::Tcp],
        max_mappings: 2,
    };
    for control in [
        Control::GetPolicy {
            version: POLICY_VERSION,
        },
        Control::Policy {
            version: POLICY_VERSION,
            policy,
        },
        Control::RegisterPolicy {
            version: POLICY_VERSION,
            proxy: "web".into(),
            protocol: Protocol::Tcp,
            remote_port: 8000,
        },
        Control::Registered {
            proxy: "web".into(),
            protocol: Protocol::Tcp,
            remote_port: 8000,
        },
        Control::MappingError {
            proxy: "web".into(),
            protocol: Protocol::Tcp,
            remote_port: 8000,
            code: "port_in_use".into(),
            reason: "requested port is occupied".into(),
        },
    ] {
        let expected = serde_json::to_value(&control).unwrap();
        let mut bytes = Vec::new();
        send_control(&mut bytes, control).await.unwrap();
        let actual = read_control(&mut bytes.as_slice()).await.unwrap();
        assert_eq!(serde_json::to_value(actual).unwrap(), expected);
    }
    assert_eq!(VERSION, 2);
    let legacy = Control::Register {
        version: VERSION,
        proxy: "web".into(),
        protocol: "tcp".into(),
    };
    assert_eq!(
        serde_json::to_string(&legacy).unwrap(),
        r#"{"type":"register","version":2,"proxy":"web","protocol":"tcp"}"#
    );
    for invalid in [
        r#"{"type":"register_policy","version":3,"proxy":"web","protocol":"tcp"}"#,
        r#"{"type":"register_policy","version":3,"proxy":"web","protocol":"icmp","remote_port":8000}"#,
        r#"{"type":"get_policy","version":"3","future":true}"#,
    ] {
        assert!(serde_json::from_str::<Control>(invalid).is_err());
    }
}

#[tokio::test]
async fn open_budget_is_optional_and_legacy_encoding_is_unchanged() {
    let legacy_json = r#"{"type":"open","ticket":"ticket"}"#;
    let legacy: Control = serde_json::from_str(legacy_json).unwrap();
    assert!(matches!(&legacy, Control::Open { ticket, timeout_ms: None } if ticket == "ticket"));
    assert_eq!(serde_json::to_string(&legacy).unwrap(), legacy_json);
    let mut bytes = Vec::new();
    send_control(&mut bytes, legacy).await.unwrap();
    assert_eq!(&bytes[5..], legacy_json.as_bytes());
    assert!(matches!(
        read_control(&mut bytes.as_slice()).await.unwrap(),
        Control::Open {
            timeout_ms: None,
            ..
        }
    ));

    for timeout_ms in [0, 1, 10000, 600000, u64::MAX] {
        // The wire parser handles unsigned budgets; mode-specific bounds belong to the client.
        let control = Control::Open {
            ticket: "ticket".into(),
            timeout_ms: Some(timeout_ms),
        };
        let json = serde_json::to_string(&control).unwrap();
        assert!(json.contains(&format!("\"timeout_ms\":{timeout_ms}")));
        let mut bytes = Vec::new();
        send_control(&mut bytes, control).await.unwrap();
        assert!(
            matches!(read_control(&mut bytes.as_slice()).await.unwrap(), Control::Open { timeout_ms: Some(actual), .. } if actual == timeout_ms)
        );
    }
    for invalid in [
        r#"{"type":"open","ticket":"ticket","timeout_ms":-1}"#,
        r#"{"type":"open","ticket":"ticket","timeout_ms":1.5}"#,
        r#"{"type":"open","ticket":"ticket","timeout_ms":"1000"}"#,
        r#"{"type":"open","ticket":"ticket","timeout_ms":18446744073709551616}"#,
    ] {
        assert!(serde_json::from_str::<Control>(invalid).is_err());
    }
}

#[tokio::test]
async fn known_wire_messages_ignore_additive_fields_at_every_object_level() {
    let messages = [
        r#"{"type":"get_policy","version":3}"#,
        r#"{"type":"policy","version":3,"policy":{"bind_ip":"127.0.0.1","allowed_ports":[{"start":8000,"end":8010}],"protocols":["tcp"],"max_mappings":2}}"#,
        r#"{"type":"register_policy","version":3,"proxy":"web","protocol":"tcp","remote_port":8000}"#,
        r#"{"type":"registered","proxy":"web","protocol":"tcp","remote_port":8000}"#,
        r#"{"type":"mapping_error","proxy":"web","protocol":"tcp","remote_port":8000,"code":"denied","reason":"not allowed"}"#,
        r#"{"type":"register","version":2,"proxy":"web","protocol":"tcp"}"#,
        r#"{"type":"attach","ticket":"ticket"}"#,
        r#"{"type":"ready"}"#,
        r#"{"type":"error","message":"rejected"}"#,
        r#"{"type":"open","ticket":"ticket"}"#,
        r#"{"type":"cancel","ticket":"ticket"}"#,
        r#"{"type":"ping"}"#,
        r#"{"type":"pong"}"#,
    ];
    for json in messages {
        let original: Control = serde_json::from_str(json).unwrap();
        let expected = serde_json::to_value(original).unwrap();
        let mut extended: serde_json::Value = serde_json::from_str(json).unwrap();
        extended["future"] = serde_json::json!({"nested": [true, 17, null]});
        if let Some(policy) = extended.get_mut("policy") {
            policy["future_permission"] = serde_json::json!({"mode": "additive"});
            policy["allowed_ports"][0]["future_range_label"] = serde_json::json!("web");
        }
        let json = serde_json::to_vec(&extended).unwrap();
        let mut bytes = ((json.len() + 1) as u32).to_be_bytes().to_vec();
        bytes.push(1);
        bytes.extend_from_slice(&json);
        let parsed = read_control(&mut bytes.as_slice()).await.unwrap();
        if let Control::Policy { policy, .. } = &parsed {
            policy.validate().unwrap();
            assert!(
                policy
                    .validate_mapping("web", &crate::config::Protocol::Tcp, 8000)
                    .is_ok()
            );
            assert!(
                policy
                    .validate_mapping("web", &crate::config::Protocol::Tcp, 9000)
                    .is_err()
            );
        }
        assert_eq!(serde_json::to_value(parsed).unwrap(), expected);
    }
}

#[test]
fn tolerant_wire_policy_still_requires_known_fields_types_and_validation() {
    let valid = serde_json::json!({
        "type": "policy", "version": 3,
        "policy": {"bind_ip": "127.0.0.1", "allowed_ports": [{"start": 8000, "end": 8010}], "protocols": ["tcp"], "max_mappings": 2}
    });
    for field in ["bind_ip", "allowed_ports", "protocols", "max_mappings"] {
        let mut value = valid.clone();
        value["policy"].as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<Control>(value).is_err());
    }
    for field in ["start", "end"] {
        let mut value = valid.clone();
        value["policy"]["allowed_ports"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(serde_json::from_value::<Control>(value).is_err());
        let mut value = valid.clone();
        value["policy"]["allowed_ports"][0][field] = serde_json::json!("8000");
        assert!(serde_json::from_value::<Control>(value).is_err());
    }
    for (field, wrong) in [
        ("bind_ip", serde_json::json!("invalid address")),
        (
            "allowed_ports",
            serde_json::json!({"start": 8000, "end": 8010}),
        ),
        ("protocols", serde_json::json!(["icmp"])),
        ("max_mappings", serde_json::json!("2")),
    ] {
        let mut value = valid.clone();
        value["policy"][field] = wrong;
        assert!(serde_json::from_value::<Control>(value).is_err());
    }
    let mut invalid_known = valid.clone();
    invalid_known["policy"]["max_mappings"] = serde_json::json!(0);
    invalid_known["policy"]["future"] = serde_json::json!(true);
    let Control::Policy { policy, .. } = serde_json::from_value::<Control>(invalid_known).unwrap()
    else {
        panic!()
    };
    assert!(policy.validate().is_err());
    for invalid in [
        r#"{"type":"future_message","version":3}"#,
        r#"{"type":"get_policy","future":true}"#,
        r#"{"type":"attach","ticket":42,"future":true}"#,
        r#"{"type":"register_policy","version":3,"proxy":"web","protocol":"tcp","remote_port":"8000"}"#,
    ] {
        assert!(serde_json::from_str::<Control>(invalid).is_err());
    }
}
