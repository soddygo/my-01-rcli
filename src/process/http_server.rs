use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use anyhow::Result;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Html;
use axum::Router;
use axum::routing::get;
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[derive(Debug)]
struct HttpServeState {
    path: PathBuf,
}


pub async fn process_http_server(path: PathBuf, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving {:?} on {}", path, addr);

    let state = HttpServeState { path: path.clone() };
    // axum router
    // let mut service = ServiceBuilder::new()
    //     // Methods from tower
    //     .timeout(Duration::from_secs(30))
    //     // Methods from tower-http
    //     .trace_for_http()
    //     .propagate_header(HeaderName::from_static("x-request-id"))
    //     .service_fn(handle);

    let router = Router::new()
        .nest_service("/tower", ServeDir::new(path))

        .route("/*path", get(file_handler))
        .route("/dir/*path", get(dir_html_handler))
        .with_state(Arc::new(state));
    // // 将服务和路由器组合在一起
    // let app = router.into_service() // 转换为服务
    //     .and_then(move |req, res| service.call(req).map(move |res| (res, res)));
    //
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

async fn dir_html_handler(State(state): State<Arc<HttpServeState>>, Path(path): Path<String>) -> (StatusCode, Html<String>) {
    let p = std::path::Path::new(&state.path).join(path);
    info!("Reading file {:?}", p);
    if p.is_dir() {
        let mut content = "<html><body><ul>".to_string();
        let mut read_dir = tokio::fs::read_dir(p).await.expect("Failed to read directory");

        while let Some(entry) = read_dir.next_entry().await.expect("Failed to get next entry") {
            let path = entry.path();
            if let Some(name) = path.file_name() {
                let name = name.to_string_lossy();
                content += &format!("<li><a href=\"{}\">{}</a></li>", name, name);
            }
        }

        content += "</ul></body></html>";
        (StatusCode::OK, Html(content))
    } else {
        let content = tokio::fs::read_to_string(p).await.expect("Failed to read file");
        (StatusCode::OK, Html(content))
    }
}


async fn file_handler(
    State(state): State<Arc<HttpServeState>>,
    Path(path): Path<String>,
) -> (StatusCode, String) {
    let p = std::path::Path::new(&state.path).join(path);
    info!("Reading file {:?}", p);
    if !p.exists() {
        (
            StatusCode::NOT_FOUND,
            format!("File {} note found", p.display()),
        )
    } else {
        // TODO: test p is a directory
        // if it is a directory, list all files/subdirectories
        // as <li><a href="/path/to/file">file name</a></li>
        // <html><body><ul>...</ul></body></html>

        if p.is_dir() {
            let mut content = "<html><body><ul>".to_string();
            let mut read_dir = tokio::fs::read_dir(p).await.expect("Failed to read directory");

            while let Some(entry) = read_dir.next_entry().await.expect("Failed to get next entry") {
                let path = entry.path();
                if let Some(name) = path.file_name() {
                    let name = name.to_string_lossy();
                    content += &format!("<li><a href=\"{}\">{}</a></li>", name, name);
                }
            }

            content += "</ul></body></html>";
            (StatusCode::OK, content)
        } else {
            match tokio::fs::read_to_string(p).await {
                Ok(content) => {
                    info!("Read {} bytes", content.len());
                    (StatusCode::OK, content)
                }
                Err(e) => {
                    warn!("Error reading file: {:?}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::extract::State;

    use super::*;

    #[tokio::test]
    async fn test_file_handler() {
        let state = Arc::new(HttpServeState {
            path: PathBuf::from("."),
        });
        let (status, content) = file_handler(State(state), Path("Cargo.toml".to_string())).await;
        assert_eq!(status, StatusCode::OK);
        assert!(content.trim().starts_with("[package]"));
    }
}
