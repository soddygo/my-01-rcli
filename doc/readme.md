# 测试命令

## csv

```shell
cargo run csv --input ./assets/juventus.csv --output ./fixtures/result.json
```


## base64

加密
```shell
cargo run base64 decode --input ./fixtures/b64.txt
```
解密
```shell
cargo run base64 decode --input ./fixtures/b64_decode.txt
```

## text

generate
```shell
cargo run text generate --output-path ./fixtures/ 
```

sign
```shell
cargo run text sign --input ./fixtures/b64.txt --key ./fixtures/blake3.txt 
```

verify
```shell
cargo run text verify --input ./fixtures/b64.txt --key ./fixtures/blake3.txt  --sig SlI5fC6LVXrTpiLsMGHWyCgGOH6JdjzHyNrTCevCBi0
```

## http

server start
```shell
 cargo run http server  

```

浏览器 url访问测试:
```url

http://127.0.0.1:8080/tower/fixtures/b64.txt
http://127.0.0.1:8080/fixtures/b64_decode.txt

```
## 作业
### 目录展示
作业,目录展示
```shell

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

加密
```shell
cargo run jwt encode --data "hello world"  --secret ./fixtures/jwt_secret.txt
```

解密,其中data 值是前面加密打印的值
```shell
cargo run jwt decode --data eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoiaGVsbG8gd29ybGQiLCJleHAiOjE3MTU2NzcxMDR9.8g6KRBSNNV2cmFmUusfizdpDarHsu0MmihNfW-08bo0  --secret ./fixtures/jwt_secret.txt
```