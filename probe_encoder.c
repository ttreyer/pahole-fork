/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2019 Facebook

  Derived from ctf_encoder.c, which is:

  Copyright (C) Arnaldo Carvalho de Melo <acme@redhat.com>
  Copyright (C) Red Hat Inc
 */

#include "dutil.h"
#include "probe_encoder.h"

#include <stdlib.h>
#include <pthread.h>

struct probe_encoder {
  struct list_head node;
};

static LIST_HEAD(encoders);
static pthread_mutex_t encoders__lock = PTHREAD_MUTEX_INITIALIZER;

/* mutex only needed for add/delete, as this can happen in multiple encoding
 * threads.  Traversal of the list is currently confined to thread collection.
 */

#define probe_encoders__for_each_encoder(encoder) \
  list_for_each_entry(encoder, &encoders, node)

static void probe_encoders__add(struct probe_encoder *encoder)
{
  pthread_mutex_lock(&encoders__lock);
  list_add_tail(&encoder->node, &encoders);
  pthread_mutex_unlock(&encoders__lock);
}

static void probe_encoders__delete(struct probe_encoder *encoder)
{
  struct probe_encoder *existing = NULL;

  pthread_mutex_lock(&encoders__lock);
  probe_encoders__for_each_encoder(existing) {
    if (encoder == existing)
      break;
  }
  if (encoder == existing)
    list_del(&encoder->node);
  pthread_mutex_unlock(&encoders__lock);
}

struct probe_encoder *probe_encoder__new(struct cu *cu, const char *detached_filename, struct btf *base_btf, bool verbose, struct conf_load *conf_load)
{
  struct probe_encoder *encoder = zalloc(sizeof(*encoder));

  if (encoder) {
    /* Add more initialisation above... */
    probe_encoders__add(encoder);
  }
  return encoder;

  probe_encoder__delete(encoder);
  return NULL;
}

void probe_encoder__delete(struct probe_encoder *encoder)
{
  if (encoder == NULL)
    return;

  probe_encoders__delete(encoder);

  free(encoder);
}

int probe_encoder__encode_cu(struct probe_encoder *encoder, struct cu *cu, struct conf_load *conf_load)
{
  // TODO: fill-in the magic!
  return 0;
}