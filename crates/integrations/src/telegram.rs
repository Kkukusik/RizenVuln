use super::http::{json, Http};
use anyhow::{bail, Result};
use reqwest::Method;
pub async fn send(token: &str, chat: &str, message: &str) -> Result<()> {
    if !token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b":_-".contains(&b))
        || token.is_empty()
    {
        bail!("Invalid Telegram token configuration");
    }
    let http = Http::new("https://api.telegram.org/", false, None)?;
    let request=http.request(Method::POST,http.url(&format!("bot{token}/sendMessage"))?).await?.json(&serde_json::json!({"chat_id":chat,"text":message.chars().take(4000).collect::<String>(),"link_preview_options":{"is_disabled":true}}));
    // Strip reqwest's URL (which contains the bot token) from returned errors.
    let response = request
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("Telegram network request failed"))?;
    let value = json(response)
        .await
        .map_err(|_| anyhow::anyhow!("Telegram API request failed"))?;
    if value["ok"] != true {
        bail!("Telegram rejected message");
    }
    Ok(())
}
