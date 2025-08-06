use fibonacci_lib::burn::burn_cmd;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    burn_cmd().await
} 