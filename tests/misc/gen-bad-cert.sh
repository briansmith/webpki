#!/bin/sh --
set -euf
case $0 in
   (/*) dir=${0%/*}/;;
   (*/*) dir=./${0%/*};;
   (*) dir=.;;
esac
cd -- "$dir"
tmpdir=$(mktemp -d)
trap '
set +fe
shred -- "$tmpdir"/*.key
rm -rf -- "$tmpdir"' EXIT
conf=$tmpdir/openssl.cnf ecparams=$tmpdir/params.txt
cakey=$tmpdir/ca.key testkey=$tmpdir/testing.key csr=$tmpdir/testing.csr
cat > "$conf" <<'EOF'
[ req ]
x509_extensions = v3_ca
distinguished_name = req_distinguished_name
default_md = sha256
encrypt_key = no
prompt = no
string_mask = utf8only
utf8 = yes

[ req_distinguished_name ]
CN = dummy

[ v3_ca ]
subjectKeyIdentifier = hash
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,cRLSign,keyCertSign
# webpki does’t understand this
authorityInfoAccess = critical,OCSP;URI:https://example.invalid

[ usr_cert ]
basicConstraints = critical,CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
keyUsage = critical,nonRepudiation,digitalSignature
extendedKeyUsage = critical,serverAuth,clientAuth
subjectAltName = DNS:localhost
# webpki does’t understand this
authorityInfoAccess = critical,OCSP;URI:https://example.invalid
EOF

openssl ecparam -name prime256v1 > "$ecparams"

openssl req \
   -x509 \
   -newkey ed25519 \
   -batch \
   -days 3000 \
   -outform der \
   -subj '/CN=dummy_ca' \
   -multivalue-rdn \
   -out ca.crt \
   -keyout "$cakey" \
   -config "$conf"

openssl req \
   -newkey "ec:$ecparams" \
   -batch \
   -out "$csr" \
   -keyout "$testkey" \
   -keyform der \
   -config "$conf"

openssl x509 \
   -req \
   -sha256 \
   -outform der \
   -inform der \
   -CAkey "$cakey" \
   -CAform der \
   -days 3000 \
   -CA ca.crt \
   -CAcreateserial \
   -CAserial "$tmpdir/ca.srl" \
   -clrext \
   -extfile "$conf" \
   -extensions usr_cert \
   -in "$csr" \
   -out testing.crt

openssl sha256 \
   -sign "$testkey" \
   -out testing.sig \
   "${0##*/}"

cd ../..
cargo +nightly fmt
exec cargo test
