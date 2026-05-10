use socks5_proxy::{config::Config, proxy};
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
        proxy::handle_client(client, &config).await.unwrap();
    });

    addr
}

async fn read_http_response_head(client: &mut TcpStream) -> String {
    let mut response = Vec::new();
    let mut byte = [0_u8; 1];

    loop {
        client.read_exact(&mut byte).await.unwrap();
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    String::from_utf8(response).unwrap()
}

#[tokio::test]
async fn http_connect_relays_bidirectional_tcp() {
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

    let request = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        upstream_addr.port(),
        upstream_addr.port()
    );
    client.write_all(request.as_bytes()).await.unwrap();

    let response = read_http_response_head(&mut client).await;
    assert_eq!(response, "HTTP/1.1 200 Connection Established\r\n\r\n");

    client.write_all(b"ping").await.unwrap();
    let mut payload = [0_u8; 4];
    client.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"pong");
}

#[tokio::test]
async fn http_connect_preserves_payload_sent_after_headers() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut request = [0_u8; 5];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"early");
        stream.write_all(b"reply").await.unwrap();
    });

    let proxy_addr = start_one_shot_proxy(test_config()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    let request = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\nearly",
        upstream_addr.port(),
        upstream_addr.port()
    );
    client.write_all(request.as_bytes()).await.unwrap();

    let response = read_http_response_head(&mut client).await;
    assert_eq!(response, "HTTP/1.1 200 Connection Established\r\n\r\n");

    let mut payload = [0_u8; 5];
    client.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"reply");
}

#[tokio::test]
async fn http_connect_rejects_malformed_connect_request() {
    let proxy_addr = start_one_shot_proxy(test_config()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    client
        .write_all(b"CONNECT missing-port HTTP/1.1\r\n\r\n")
        .await
        .unwrap();

    let response = read_http_response_head(&mut client).await;
    assert_eq!(response, "HTTP/1.1 400 Bad Request\r\n\r\n");
}

#[tokio::test]
async fn http_connect_rejects_oversized_headers() {
    let proxy_addr = start_one_shot_proxy(test_config()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    client.write_all(&vec![b'C'; 8193]).await.unwrap();

    let response = read_http_response_head(&mut client).await;
    assert_eq!(
        response,
        "HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n"
    );
}

#[tokio::test]
async fn http_connect_returns_bad_gateway_when_upstream_refuses() {
    let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_addr = closed_listener.local_addr().unwrap();
    drop(closed_listener);

    let proxy_addr = start_one_shot_proxy(test_config()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    let request = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        closed_addr.port(),
        closed_addr.port()
    );
    client.write_all(request.as_bytes()).await.unwrap();

    let response = read_http_response_head(&mut client).await;
    assert!(
        response == "HTTP/1.1 502 Bad Gateway\r\n\r\n"
            || response == "HTTP/1.1 504 Gateway Timeout\r\n\r\n"
    );
}

#[tokio::test]
async fn http_connect_closes_idle_tunnel_without_payload() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();

    tokio::spawn(async move {
        let (_stream, _) = upstream.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
    });

    let proxy_addr = start_one_shot_proxy(test_config()).await;
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    let request = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        upstream_addr.port(),
        upstream_addr.port()
    );
    client.write_all(request.as_bytes()).await.unwrap();

    let response = read_http_response_head(&mut client).await;
    assert_eq!(response, "HTTP/1.1 200 Connection Established\r\n\r\n");

    let mut buf = [0_u8; 1];
    let read = timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, 0);
}
