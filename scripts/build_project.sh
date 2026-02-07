echo "checking code"
cargo check

echo "status of cargo check $?"

cargo update

echo "building code"
cargo build

echo "status of cargo build $?"

echo "running tests"
cargo test
echo "status of cargo test $?"

echo "now you can run ./main"

cargo fmt --check --verbose

cargo fmt