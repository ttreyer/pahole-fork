#ifndef _INLINE_ENCODER_H_
#define _INLINE_ENCODER_H_ 1
/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2025 Facebook

  Derived from btf_encoder.h, which is:
  Copyright (C) Arnaldo Carvalho de Melo <acme@redhat.com>
 */
#include <stdbool.h>

struct inline_encoder;
struct conf_load;
struct btf;
struct cu;

struct inline_encoder *inline_encoder__new(struct cu *cu, const char *detached_filename, struct btf *base_btf, bool verbose, struct conf_load *conf_load);
void inline_encoder__delete(struct inline_encoder *encoder);
int inline_encoder__encode_cu(struct inline_encoder *encoder, struct cu *cu, struct conf_load *conf_load);
int inline_encoder__encode(struct inline_encoder *encoder, struct conf_load *conf_load);

#endif /* _INLINE_ENCODER_H_ */
