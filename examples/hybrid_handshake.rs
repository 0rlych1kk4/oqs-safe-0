use oqs_safe::handshake::{HybridClient, HybridServer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = HybridClient::new();
    let client_hello = client.start_handshake()?;

    let mut server = HybridServer::new();
    let server_hello = server.respond(client_hello)?;

    let client_session = client.finish(server_hello)?;
    let server_session = server.session()?;

    let (client_send_key, client_recv_key) = client_session.derive_client_server_keys();
    let (server_send_key, server_recv_key) = server_session.derive_client_server_keys();

    assert_eq!(client_send_key, server_send_key);
    assert_eq!(client_recv_key, server_recv_key);

    println!("Hybrid handshake completed successfully.");
    println!("Client/server session keys match.");

    Ok(())
}
