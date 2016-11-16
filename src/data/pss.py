# Copyright 2016 Joseph Birr-Pixton.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
Generates assorted RSASSA-PSS-params encodings.  See RFC4055.

Requires pyasn1 and python2.
"""

from pyasn1.type import univ, tag
from pyasn1.codec.der import encoder

pkcs1 = [1, 2, 840, 113549, 1, 1]
id_RSASSA_PSS = univ.ObjectIdentifier(pkcs1 + [10])
id_mgf1 = univ.ObjectIdentifier(pkcs1 + [8])

id_SHA1 = univ.ObjectIdentifier([1, 3, 14, 3, 2, 26])
nist_hash_algs = [2, 16, 840, 1, 101, 3, 4, 2]
id_SHA256 = univ.ObjectIdentifier(nist_hash_algs + [1])
id_SHA384 = univ.ObjectIdentifier(nist_hash_algs + [2])
id_SHA512 = univ.ObjectIdentifier(nist_hash_algs + [3])

def alg_id(id, param = None):
    alg = univ.Sequence()
    alg[0] = id
    if param is None:
        alg[1] = univ.Null()
    else:
        alg[1] = param
    return alg

sha1Identifier = alg_id(id_SHA1)
sha256Identifier = alg_id(id_SHA256)
sha384Identifier = alg_id(id_SHA384)
sha512Identifier = alg_id(id_SHA512)

def mgf1_with(hash):
    return alg_id(id_mgf1, hash)

mgf1SHA1Identifier = mgf1_with(sha1Identifier)
mgf1SHA256Identifier = mgf1_with(sha256Identifier)
mgf1SHA384Identifier = mgf1_with(sha384Identifier)
mgf1SHA512Identifier = mgf1_with(sha512Identifier)

def dump_pss_encoding(filename, hash, mgf1, salt):
    pss = univ.Sequence()
    pss[0] = univ.Sequence(tagSet = tag.TagSet().tagExplicitly(
                tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
    pss[0][0] = hash

    pss[1] = univ.Sequence(tagSet = tag.TagSet().tagExplicitly(
                tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
    pss[1][0] = mgf1

    pss[2] = univ.Integer(salt).subtype(
            explicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))

    alg = alg_id(id_RSASSA_PSS, pss)

    open('params-' + filename, 'wb').write(encoder.encode(pss))
    open('alg-' + filename, 'wb').write(encoder.encode(alg))

if __name__ == '__main__':
    dump_pss_encoding('pss-sha256.der', sha256Identifier, mgf1SHA256Identifier, 32)
    dump_pss_encoding('pss-sha384.der', sha384Identifier, mgf1SHA384Identifier, 48)
    dump_pss_encoding('pss-sha512.der', sha512Identifier, mgf1SHA512Identifier, 64)

