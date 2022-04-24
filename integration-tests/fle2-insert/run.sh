set -o errexit

go run ./setup

outdir=$(pwd)/.out
csfledir=$(pwd)/../../cmake-build

echo "Insert ... begin"
$csfledir/csfle auto_encrypt \
    --db 'db' \
    --kms_providers_file ~/.csfle/kms_providers_zero_local.json \
    --command '{"insert": "test", "documents": [{"ssn": "123"}]}' \
    | python -m json.tool > $outdir/encrypted-insert.json
go run ./run-command $outdir/encrypted-insert.json > /dev/null
echo "Insert ... end"

echo "Find ... begin"
$csfledir/csfle auto_encrypt \
    --db 'db' \
    --kms_providers_file ~/.csfle/kms_providers_zero_local.json \
    --command '{"find": "test", "filter": {"ssn": "123"}}' \
    | python -m json.tool > $outdir/encrypted-find.json
go run ./run-command $outdir/encrypted-find.json > $outdir/encrypted-find-reply.json
echo "Find ... end"

echo "Decrypt reply ... begin"
$csfledir/csfle auto_decrypt \
    --db 'db' \
    --kms_providers_file ~/.csfle/kms_providers_zero_local.json \
    --document_file $outdir/encrypted-find-reply.json \
    | python -m json.tool > $outdir/reply.json
cat $outdir/reply.json
echo "Decrypt reply ... end"
