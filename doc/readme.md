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

作业,目录展示
```shell

http://127.0.0.1:8080/dir/fixtures

```