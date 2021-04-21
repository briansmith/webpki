#!/bin/bash
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
  --all-features ---all-targets \
  -- \
  --deny warnings \
  --allow clippy::collapsible_if \
  --allow clippy::from_over_into \
  --allow clippy::identity_op \
  --allow clippy::len_without_is_empty \
  --allow clippy::len_zero \
  --allow clippy::ptr_arg \
  --allow clippy::let_unit_value \
  --allow clippy::many_single_char_names \
  --allow clippy::needless_range_loop \
  --allow clippy::new_without_default \
  --allow clippy::neg_cmp_op_on_partial_ord \
  --allow clippy::range_plus_one \
  --allow clippy::redundant_slicing \
  --allow clippy::too_many_arguments \
  --allow clippy::trivially_copy_pass_by_ref \
  --allow clippy::type_complexity \
  --allow clippy::unreadable_literal \
  --allow clippy::upper_case_acronyms \
  --allow clippy::vec_init_then_push \

  $NULL
