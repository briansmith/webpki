#!/bin/sh --
set -eufx
case $0 in
   (/*) dir=${0%/*}/;;
   (*/*) dir=./${0%/*};;
   (*) dir=.;;
esac
cd -- "$dir"
tmpdir=$(mktemp -d)
trap 'rm -rf -- "$tmpdir"' EXIT
conf=$tmpdir/openssl.cnf
cat > "$conf" <<'EOF'
[ req ]
x509_extensions = v3_ca
req_extensions = v3_req 
distinguished_name = req_distinguished_name
encrypt_key = no
prompt = no
string_mask = utf8only

[ req_distinguished_name ]
CN = dummy

[ v3_req ]
basicConstraints = CA:FALSE

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,cRLSign,keyCertSign
# webpki does’t understand this
authorityInfoAccess = critical,OCSP;URI:https://example.invalid

[ usr_cert ]
basicConstraints = critical,CA:false
keyUsage = critical,nonRepudiation,digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
extendedKeyUsage = critical,serverAuth,clientAuth
subjectAltName = @names
# webpki does’t understand this
authorityInfoAccess = critical,OCSP;URI:https://example.invalid

[ names ]
DNS.1 = localhost
EOF

openssl ecparam -name prime256v1 > "$tmpdir/params.txt"
openssl req \
   -x509 \
   -newkey "ec:$tmpdir/params.txt" \
   -sha256 \
   -batch \
   -days 3000 \
   -outform der \
   -nodes \
   -subj '/CN=dummy_ca' \
   -multivalue-rdn \
   -utf8 \
   -out ca.crt \
   -keyout "$tmpdir/ca.key" \
   -config "$conf"

openssl req \
   -newkey "ec:$tmpdir/params.txt" \
   -sha256 \
   -batch \
   -nodes \
   -utf8 \
   -out "$tmpdir/testing.csr" \
   -keyout "$tmpdir/testing.key" \
   -keyform der \
   -config "$conf"

for i in testing ca; do
   openssl ec \
      -inform pem \
      -outform der \
      -in "$tmpdir/$i.key" \
      -out "$i.key"
   shred -- "$tmpdir/$i.key"
done

file "$tmpdir/testing.csr"
openssl x509 \
   -req \
   -outform der \
   -inform der \
   -CAkeyform der \
   -CAkey ca.key \
   -CAform der \
   -sha256 \
   -days 3000 \
   -CA ca.crt \
   -CAcreateserial \
   -clrext \
   -extfile "$conf" \
   -extensions usr_cert \
   -in "$tmpdir/testing.csr" \
   -out testing.crt

openssl sha256 \
   -sign testing.key \
   -out testing.sig \
   -keyform der \
   "$PWD/$0"
