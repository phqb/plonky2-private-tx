To run this project, first set rustup nightly:
```shell
rustup override set nightly
```
Then run the main with log info
```shell
RUST_BACKTRACE=1 RUST_LOG="info" cargo run --color=always --example private_tx --release
```
