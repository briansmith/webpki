THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.



What is libwebpki?
==================

libwebpki is a library that validates Web PKI (TLS/SSL) certificates. libwebpki
is designed to provide a **full** implementation of the client side of the
**Web PKI** to a diverse rnage of applications and devices,
including embedded (IoT) applications, mobile apps, desktop applications, and
server infrastructure. libwebpki is intended to not only be the best
implementation of the Web PKI, but to also *precisely define* what the Web PKI
is.

libwebpki is written in [Rust](https://www.rust-lang.org/) and uses
[*ring*](https://github.com/briansmith/ring) for signature verification.

libwebpki is strongly influenced by
[mozilla::pkix](https://github.com/briansmith/mozillapkix). You can read a
little about the ideas underlying both mozilla::pkix and libwebpki in
[insanity::pkix: A New Certificate Path Building & Validation
Library](https://briansmith.org/insanity-pkix.html).

The Rust compiler static guarantees there are no buffer overflows,
uses-after-free, double-frees, data races, etc. in libwebpki. libwebpki takes
advantage of Rust's borrow checker to ensure that its **zero-copy parsing**
strategy is safe and efficient. libwebpki *never* allocates memory on the heap,
and it maintains a tight bound on the amount of stack memory it uses. libwebpki
avoids all superfluous PKIX features in order to keep its object code size
small. Further reducing the code size of libwebpki is an important goal.

This release is the very first prototype. Lots of improvements are planned,
including:

* An extensive automated test suite.
* Key pinning.
* Certificate Transparency support.
* Short-lived certificate, OCSP stapling, and CRLSet support.
* Customization of the supported algorithms, key sizes, and elliptic curves
  allowed during a validation.
* A C language wrapper interface to allow using libwebpki in non-Rust
  applications.
* A specification of precisely what the Web PKI is.



Demo
====

There is a demo program at https://github.com/briansmith/verify_tls_cert.


  
License
=======

See [LICENSE](LICENSE). This project happily accepts pull requests without any
formal copyright/contributor license agreement. Pull requests must explicitly
indicate who owns the copyright to the code being contributed and that the code
is being licensed under the same terms as the existing libwebpki code.



Bug Reporting
=============

Please report bugs either as pull requests or as issues in [the issue
tracker](https://github.com/briansmith/webpki/issues). libwebpki has a
**full disclosure** vulnerability policy. **Please do NOT attempt to report
any security vulnerability in this code privately to anybody.**



Online Automated Testing
========================

Travis CI is used for Linux and Mac OS X. Appveyor is used for Windows.

<table>
<tr><th>OS</th><th>Arch.</th><th>Compilers</th><th>Status</th>
<tr><td>Linux</td>
    <td>x86, x64<td>GCC 4.8, 4.9, 5; Clang 3.4, 3.5, 3.6</td>
    <td rowspan=2><a title="Build Status" href=https://travis-ci.org/briansmith/webpki><img src=https://travis-ci.org/briansmith/webpki.svg?branch=master></a>
</tr>
<tr><td>Mac OS X x64</td>
    <td>x86, x64</td>
    <td>Apple Clang 6.0 (based on Clang 3.5)</td>
</tr>
<tr><td>Windows</td>
    <td>x86, x64</td>
    <td>MSVC 2013 (12.0), 2015 (14.0)</td>
    <td><a title="Build Status" href=https://ci.appveyor.com/project/briansmith/webpki/branch/master><img src=https://ci.appveyor.com/api/projects/status/3wq9p54r9iym05rm/branch/master?svg=true></a>
</tr>
</table>



This Branch, ```wip```, Will Be Rebased
=======================================

This is a very early prototype of the code. The commits on this ```wip```
branch will be rebased as people review the code. In a couple of weeks, the
```master``` permanent branch will be created.
