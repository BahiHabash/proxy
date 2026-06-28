use proxy::socks5::{
    HandshakeError, REP_ADDRESS_TYPE_NOT_SUPPORTED, REP_COMMAND_NOT_SUPPORTED,
    REP_CONNECTION_REFUSED, TargetAddr, handshake, send_reply,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const USER: &str = "user";
const PASS: &str = "pass";

async fn connected_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client = TcpStream::connect(addr);
    let server = async {
        let (stream, _) = listener.accept().await.unwrap();
        stream
    };

    let (client, server) = tokio::join!(client, server);
    (client.unwrap(), server)
}

async fn negotiate_and_auth(client: &mut TcpStream, username: &str, password: &str) {
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();

    let mut method_response = [0_u8; 2];
    client.read_exact(&mut method_response).await.unwrap();
    assert_eq!(method_response, [0x05, 0x02]);

    let mut auth = vec![0x01, username.len() as u8];
    auth.extend_from_slice(username.as_bytes());
    auth.push(password.len() as u8);
    auth.extend_from_slice(password.as_bytes());
    client.write_all(&auth).await.unwrap();

    let mut auth_response = [0_u8; 2];
    client.read_exact(&mut auth_response).await.unwrap();
    assert_eq!(auth_response, [0x01, 0x00]);
}

#[tokio::test]
async fn parses_ipv4_connect_request() {
    let (mut client, mut server) = connected_pair().await;
    let server_task = tokio::spawn(async move { handshake(&mut server, USER, PASS).await });

    negotiate_and_auth(&mut client, USER, PASS).await;
    client
        .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb])
        .await
        .unwrap();

    let target = server_task.await.unwrap().unwrap();
    assert_eq!(target, TargetAddr::Ip4(Ipv4Addr::new(127, 0, 0, 1), 443));
}

#[tokio::test]
async fn parses_domain_connect_request() {
    let (mut client, mut server) = connected_pair().await;
    let server_task = tokio::spawn(async move { handshake(&mut server, USER, PASS).await });

    negotiate_and_auth(&mut client, USER, PASS).await;

    let host = b"example.com";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&443_u16.to_be_bytes());
    client.write_all(&request).await.unwrap();

    let target = server_task.await.unwrap().unwrap();
    assert_eq!(target, TargetAddr::Domain("example.com".into(), 443));
}

#[tokio::test]
async fn parses_ipv6_connect_request() {
    let (mut client, mut server) = connected_pair().await;
    let server_task = tokio::spawn(async move { handshake(&mut server, USER, PASS).await });

    negotiate_and_auth(&mut client, USER, PASS).await;

    let ip = Ipv6Addr::LOCALHOST;
    let mut request = vec![0x05, 0x01, 0x00, 0x04];
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(&443_u16.to_be_bytes());
    client.write_all(&request).await.unwrap();

    let target = server_task.await.unwrap().unwrap();
    assert_eq!(target, TargetAddr::Ip6(ip, 443));
}

#[tokio::test]
async fn rejects_clients_without_username_password_auth() {
    let (mut client, mut server) = connected_pair().await;
    let server_task = tokio::spawn(async move { handshake(&mut server, USER, PASS).await });

    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

    let mut response = [0_u8; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [0x05, 0xff]);

    assert!(matches!(
        server_task.await.unwrap(),
        Err(HandshakeError::NoAcceptableAuth)
    ));
}

#[tokio::test]
async fn rejects_bad_socks_version() {
    let (mut client, mut server) = connected_pair().await;
    let server_task = tokio::spawn(async move { handshake(&mut server, USER, PASS).await });

    client.write_all(&[0x04]).await.unwrap();

    assert!(matches!(
        server_task.await.unwrap(),
        Err(HandshakeError::BadVersion(0x04))
    ));
}

#[tokio::test]
async fn rejects_bad_auth_version() {
    let (mut client, mut server) = connected_pair().await;
    let server_task = tokio::spawn(async move { handshake(&mut server, USER, PASS).await });

    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut method_response = [0_u8; 2];
    client.read_exact(&mut method_response).await.unwrap();
    client.write_all(&[0x02]).await.unwrap();

    assert!(matches!(
        server_task.await.unwrap(),
        Err(HandshakeError::BadAuthVersion(0x02))
    ));
}

#[tokio::test]
async fn rejects_invalid_credentials_without_exposing_username() {
    let (mut client, mut server) = connected_pair().await;
    let server_task = tokio::spawn(async move { handshake(&mut server, USER, PASS).await });

    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut method_response = [0_u8; 2];
    client.read_exact(&mut method_response).await.unwrap();

    client
        .write_all(&[
            0x01, 0x07, b'a', b't', b't', b'a', b'c', b'k', b'e', 0x03, b'b', b'a', b'd',
        ])
        .await
        .unwrap();

    let mut auth_response = [0_u8; 2];
    client.read_exact(&mut auth_response).await.unwrap();
    assert_eq!(auth_response, [0x01, 0x01]);

    assert!(matches!(
        server_task.await.unwrap(),
        Err(HandshakeError::AuthFailed)
    ));
}

#[tokio::test]
async fn rejects_unsupported_command_with_reply() {
    let (mut client, mut server) = connected_pair().await;
    let server_task = tokio::spawn(async move { handshake(&mut server, USER, PASS).await });

    negotiate_and_auth(&mut client, USER, PASS).await;
    client
        .write_all(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
        .await
        .unwrap();

    let mut reply = [0_u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(
        reply,
        [0x05, REP_COMMAND_NOT_SUPPORTED, 0, 1, 0, 0, 0, 0, 0, 0]
    );

    assert!(matches!(
        server_task.await.unwrap(),
        Err(HandshakeError::UnsupportedCommand(0x02))
    ));
}

#[tokio::test]
async fn rejects_unsupported_address_type_with_reply() {
    let (mut client, mut server) = connected_pair().await;
    let server_task = tokio::spawn(async move { handshake(&mut server, USER, PASS).await });

    negotiate_and_auth(&mut client, USER, PASS).await;
    client.write_all(&[0x05, 0x01, 0x00, 0x09]).await.unwrap();

    let mut reply = [0_u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(
        reply,
        [0x05, REP_ADDRESS_TYPE_NOT_SUPPORTED, 0, 1, 0, 0, 0, 0, 0, 0]
    );

    assert!(matches!(
        server_task.await.unwrap(),
        Err(HandshakeError::UnsupportedAddrType(0x09))
    ));
}

#[tokio::test]
async fn send_reply_uses_zero_bound_address() {
    let (mut client, mut server) = connected_pair().await;

    let server_task = tokio::spawn(async move {
        send_reply(&mut server, REP_CONNECTION_REFUSED)
            .await
            .unwrap();
    });

    let mut response = [0_u8; 10];
    client.read_exact(&mut response).await.unwrap();
    server_task.await.unwrap();

    assert_eq!(
        response,
        [0x05, REP_CONNECTION_REFUSED, 0, 1, 0, 0, 0, 0, 0, 0]
    );
}
