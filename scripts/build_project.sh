echo "checking code"
cargo check

echo "status of cargo check $?"

echo "building code"
cargo build

echo "status of cargo build $?"

echo "now you can run ./main"
