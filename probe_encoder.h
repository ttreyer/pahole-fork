#ifndef _PROBE_ENCODER_H_
#define _PROBE_ENCODER_H_ 1
/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2024 Facebook

  Derived from ctf_encoder.h, which is:
  Copyright (C) Arnaldo Carvalho de Melo <acme@redhat.com>
 */
#include <stdbool.h>

struct probe_encoder;
struct conf_load;
struct btf;
struct cu;

struct probe_encoder *probe_encoder__new(struct cu *cu, const char *detached_filename, struct btf *base_btf, bool verbose, struct conf_load *conf_load);
void probe_encoder__delete(struct probe_encoder *encoder);
int probe_encoder__encode_cu(struct probe_encoder *encoder, struct cu *cu, struct conf_load *conf_load);

#endif /* _PROBE_ENCODER_H_ */