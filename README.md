# Geektime Rust 语言训练营

## 作业

### 目录展示

server start
```shell
 cargo run http server  

```

作业,目录展示
```url

http://127.0.0.1:8080/dir/fixtures

```
### chacha20 加密,解密
作业,生成key,会在fixture下生成: [ChaCha20Poly1305.txt](..%2Ffixtures%2FChaCha20Poly1305.txt)
```shell
cargo run text chip-generate --output-path ./fixtures
```

加密测试,控制台会输出加密后的base64字符,./fixtures/nonce.txt是nonce
```shell
cargo run text encrypt --key ./fixtures/ChaCha20Poly1305.txt --nonce-output-path ./fixtures  --input ./fixtures/chacha20input.text
```

解密测试,控制台会输出解密后的base64字符,./fixtures/nonce.txt是上次加密的nonce
```shell
cargo run text decrypt --key ./fixtures/ChaCha20Poly1305.txt --nonce-input-path ./fixtures/nonce.txt
```


### jwt 加密解密

数据结构定义,输入的内容,自动放到data字段,exp是unix时间戳,标识过期时间
```text
{"data":"hello world","exp":1715677104}
```


加密,参数 --exp  暂时只支持天单位,比如:1d
```shell
cargo run jwt encode --data "hello world"  --secret ./fixtures/jwt_secret.txt --exp 1d
```

解密,其中data 值是前面加密打印的值
```shell
cargo run jwt decode --data eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoiaGVsbG8gd29ybGQiLCJleHAiOjE3MTU2Nzg0MjV9.j9mcf65yIGwkqtTreIr_Km3f-_xB7VWmJdT7yH4YL8s  --secret ./fixtures/jwt_secret.txt
```

验证jwt
```shell
cargo run jwt verify --data eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoiaGVsbG8gd29ybGQiLCJleHAiOjE3MTU3NjMwMjh9.YE-4ZBDj5QnvxwCC7F2i_UkbWvHcMYxSoQ1-Hs3u0is --secret ./fixtures/jwt_secret.txt
```

## 环境设置

### 安装 Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 安装 VSCode 插件

- crates: Rust 包管理
- Even Better TOML: TOML 文件支持
- Better Comments: 优化注释显示
- Error Lens: 错误提示优化
- GitLens: Git 增强
- Github Copilot: 代码提示
- indent-rainbow: 缩进显示优化
- Prettier - Code formatter: 代码格式化
- REST client: REST API 调试
- rust-analyzer: Rust 语言支持
- Rust Test lens: Rust 测试支持
- Rust Test Explorer: Rust 测试概览
- TODO Highlight: TODO 高亮
- vscode-icons: 图标优化
- YAML: YAML 文件支持

### 安装 cargo generate

cargo generate 是一个用于生成项目模板的工具。它可以使用已有的 github repo 作为模版生成新的项目。

```bash
cargo install cargo-generate
```

在我们的课程中，新的项目会使用 `tyr-rust-bootcamp/template` 模版生成基本的代码：

```bash
cargo generate tyr-rust-bootcamp/template
```

### 安装 pre-commit

pre-commit 是一个代码检查工具，可以在提交代码前进行代码检查。

```bash
pipx install pre-commit
```

安装成功后运行 `pre-commit install` 即可。

### 安装 Cargo deny

Cargo deny 是一个 Cargo 插件，可以用于检查依赖的安全性。

```bash
cargo install --locked cargo-deny
```

### 安装 typos

typos 是一个拼写检查工具。

```bash
cargo install typos-cli
```

### 安装 git cliff

git cliff 是一个生成 changelog 的工具。

```bash
cargo install git-cliff
```

### 安装 cargo nextest

cargo nextest 是一个 Rust 增强测试工具。

```bash
cargo install cargo-nextest --locked
```
