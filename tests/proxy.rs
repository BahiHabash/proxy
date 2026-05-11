use socks5_proxy::{config::Config, socks5::REP_SUCCESS};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Duration, timeout};

const USER: &str = "user";
const PASS: &str = "pass";

fn test_config() -> Config {
    Config {
        bind_host: "127.0.0.1".into(),
        bind_port: 0,
        auth_username: USER.into(),
        auth_password: PASS.into(),
        idle_timeout_secs: 1,
        log_format: "pretty".into(),
        upstream_connection_timeout_sec: 1,
    }
}

async fn start_one_shot_proxy(config: Config) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        socks5_proxy::proxy::handle_client(client, &config)
            .await
            .unwrap();
    });

    addr
}

async fn start_proxy_accepting(config: Config, connection_count: usize) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        for _ in 0..connection_count {
            let (client, _) = listener.accept().await.unwrap();
            let config = config.clone();
            tokio::spawn(async move {
                socks5_proxy::proxy::handle_client(client, &config)
                    .await
                    .unwrap();
            });
        }
    });

    addr
}

async fn write_method_and_auth(client: &mut TcpStream, username: &str, password: &str) {
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();

    let mut method_response = [0_u8; 2];
    client.read_exact(&mut method_response).await.unwrap();
    assert_eq!(method_response, [0x05, 0x02]);

    let mut auth = vec![0x01, username.len() as u8];
    auth.extend_from_slice(username.as_bytes());
    auth.push(password.len() as u8);
    auth.extend_from_slice(password.as_bytes());
    client.write_all(&auth).await.unwrap();
}

async fn assert_auth_success(client: &mut TcpStream) {
    let mut auth_response = [0_u8; 2];
    client.read_exact(&mut auth_response).await.unwrap();
    assert_eq!(auth_response, [0x01, 0x00]);
}

async fn read_socks_reply(client: &mut TcpStream) -> [u8; 10] {
    let mut reply = [0_u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    reply
}

#[tokio::test]
async fn proxies_bidirectional_tcp_after_successful_handshake() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });

    let proxy_addr = start_one_shot_proxy(test_config()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    write_method_and_auth(&mut client, USER, PASS).await;
    assert_auth_success(&mut client).await;

    let ip = match upstream_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => unreachable!("test binds IPv4"),
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(&upstream_addr.port().to_be_bytes());
    client.write_all(&request).await.unwrap();

    let reply = read_socks_reply(&mut client).await;
    assert_eq!(reply, [0x05, REP_SUCCESS, 0, 1, 0, 0, 0, 0, 0, 0]);

    client.write_all(b"ping").await.unwrap();
    let mut response = [0_u8; 4];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
}

#[tokio::test]
async fn supports_domain_targets_with_remote_resolution() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut request = [0_u8; 5];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"hello");
        stream.write_all(b"world").await.unwrap();
    });

    let proxy_addr = start_one_shot_proxy(test_config()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    write_method_and_auth(&mut client, USER, PASS).await;
    assert_auth_success(&mut client).await;

    let host = b"127.0.0.1";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&upstream_addr.port().to_be_bytes());
    client.write_all(&request).await.unwrap();

    let reply = read_socks_reply(&mut client).await;
    assert_eq!(reply, [0x05, REP_SUCCESS, 0, 1, 0, 0, 0, 0, 0, 0]);

    client.write_all(b"hello").await.unwrap();
    let mut response = [0_u8; 5];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"world");
}

#[tokio::test]
async fn sends_failure_reply_when_upstream_refuses_connection() {
    let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_addr = closed_listener.local_addr().unwrap();
    drop(closed_listener);

    let proxy_addr = start_one_shot_proxy(test_config()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    write_method_and_auth(&mut client, USER, PASS).await;
    assert_auth_success(&mut client).await;

    let ip = match closed_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => unreachable!("test binds IPv4"),
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(&closed_addr.port().to_be_bytes());
    client.write_all(&request).await.unwrap();

    let reply = read_socks_reply(&mut client).await;
    assert_ne!(reply[1], REP_SUCCESS);
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[3], 0x01);
}

#[tokio::test]
async fn returns_after_auth_failure_without_connecting_upstream() {
    let proxy_addr = start_one_shot_proxy(test_config()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    write_method_and_auth(&mut client, USER, "wrong").await;

    let mut auth_response = [0_u8; 2];
    client.read_exact(&mut auth_response).await.unwrap();
    assert_eq!(auth_response, [0x01, 0x01]);

    let mut buf = [0_u8; 1];
    let read = client.read(&mut buf).await.unwrap();
    assert_eq!(read, 0);
}

#[tokio::test]
async fn closes_idle_relay_without_payload() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();

    tokio::spawn(async move {
        let (_stream, _) = upstream.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
    });

    let proxy_addr = start_one_shot_proxy(test_config()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    write_method_and_auth(&mut client, USER, PASS).await;
    assert_auth_success(&mut client).await;

    let ip = match upstream_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => unreachable!("test binds IPv4"),
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(&upstream_addr.port().to_be_bytes());
    client.write_all(&request).await.unwrap();

    let reply = read_socks_reply(&mut client).await;
    assert_eq!(reply, [0x05, REP_SUCCESS, 0, 1, 0, 0, 0, 0, 0, 0]);

    let mut buf = [0_u8; 1];
    let read = timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, 0);
}

#[tokio::test]
async fn same_listener_handles_socks5_and_http_connect_clients() {
    let socks_upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_upstream_addr = socks_upstream.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = socks_upstream.accept().await.unwrap();
        let mut request = [0_u8; 5];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"socks");
        stream.write_all(b"ok-s5").await.unwrap();
    });

    let http_upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_upstream_addr = http_upstream.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = http_upstream.accept().await.unwrap();
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"http");
        stream.write_all(b"ok-h").await.unwrap();
    });

    let proxy_addr = start_proxy_accepting(test_config(), 2).await;

    let mut socks_client = TcpStream::connect(proxy_addr).await.unwrap();
    write_method_and_auth(&mut socks_client, USER, PASS).await;
    assert_auth_success(&mut socks_client).await;

    let socks_ip = match socks_upstream_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => unreachable!("test binds IPv4"),
    };
    let mut socks_request = vec![0x05, 0x01, 0x00, 0x01];
    socks_request.extend_from_slice(&socks_ip.octets());
    socks_request.extend_from_slice(&socks_upstream_addr.port().to_be_bytes());
    socks_client.write_all(&socks_request).await.unwrap();
    assert_eq!(
        read_socks_reply(&mut socks_client).await,
        [0x05, REP_SUCCESS, 0, 1, 0, 0, 0, 0, 0, 0]
    );

    socks_client.write_all(b"socks").await.unwrap();
    let mut socks_response = [0_u8; 5];
    socks_client.read_exact(&mut socks_response).await.unwrap();
    assert_eq!(&socks_response, b"ok-s5");

    let mut http_client = TcpStream::connect(proxy_addr).await.unwrap();
    let http_request = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        http_upstream_addr.port(),
        http_upstream_addr.port()
    );
    http_client
        .write_all(http_request.as_bytes())
        .await
        .unwrap();

    let mut http_head = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        http_client.read_exact(&mut byte).await.unwrap();
        http_head.push(byte[0]);
        if http_head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert_eq!(
        String::from_utf8(http_head).unwrap(),
        "HTTP/1.1 200 Connection Established\r\n\r\n"
    );

    http_client.write_all(b"http").await.unwrap();
    let mut http_response = [0_u8; 4];
    http_client.read_exact(&mut http_response).await.unwrap();
    assert_eq!(&http_response, b"ok-h");
}
