#!/usr/bin/env bash
#
# Copyright 2021 Brian Smith.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

set -eux -o pipefail
IFS=$'\n\t'

export NULL=""
cargo clippy \
  --target-dir=target/clippy \
  --all-features --all-targets \
  -- \
  --deny warnings \
  \
  --deny clippy::as_conversions \
  \
  --allow clippy::clone_on_copy \
  --allow clippy::explicit_auto_deref \
  --allow clippy::len_without_is_empty \
  --allow clippy::new_without_default \
  --allow clippy::single_match \
  --allow clippy::single_match_else \
  --allow clippy::too_many_arguments \
  --allow clippy::type_complexity \
  --allow clippy::upper_case_acronyms \
  --allow clippy::useless_asref \
  $NULL
