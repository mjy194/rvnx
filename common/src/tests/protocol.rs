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
    for json in [
        b"{".as_slice(),
        br#"{"type":"attach","ticket":"t","extra":true}"#,
    ] {
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
