use oqs_safe::handshake::{HybridClient, HybridServer};

#[test]
fn hybrid_handshake_derives_matching_session_keys() {
    let mut client = HybridClient::new();
    let client_hello = client
        .start_handshake()
        .expect("client hello should be created");

    let mut server = HybridServer::new();
    let server_hello = server
        .respond(client_hello)
        .expect("server should respond to client hello");

    let client_session = client
        .finish(server_hello)
        .expect("client should finish handshake");

    let server_session = server.session().expect("server session should exist");

    let (client_send_key, client_recv_key) = client_session.derive_client_server_keys();
    let (server_send_key, server_recv_key) = server_session.derive_client_server_keys();

    assert_eq!(client_send_key, server_send_key);
    assert_eq!(client_recv_key, server_recv_key);
}

#[test]
fn server_session_is_missing_before_response() {
    let server = HybridServer::new();

    assert!(server.session().is_err());
}

#[test]
fn client_cannot_finish_without_starting_handshake() {
    let mut client = HybridClient::new();

    let result = client.finish(oqs_safe::handshake::ServerHello {
        server_x25519_public: vec![0u8; 32],
        kem_ciphertext: vec![1u8; 32],
    });

    assert!(result.is_err());
}
