/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2019 Facebook

  Derived from ctf_encoder.c, which is:

  Copyright (C) Arnaldo Carvalho de Melo <acme@redhat.com>
  Copyright (C) Red Hat Inc
 */

#include "dutil.h"
#include "dwarves.h"
#include "probe_encoder.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

struct probe {
  uint64_t address;
  uint64_t base_address;
  uint64_t semaphore_address;
  const char *provider;
  const char *name;
  const char *arguments;
};

struct probe_inline_expansion {
  struct list_head node;
  struct inline_expansion *exp;
};

struct probe_encoder {
  struct list_head node;
  struct list_head inline_expansions;
  int fd;
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

static const char *SDT_NOTE_NAME = "stapsdt";
static const uint32_t SDT_NOTE_TYPE = 3;

static inline uint32_t probe__length(struct probe *probe)
{
  return 8 + 8 + 8 + strlen(probe->provider) + 1 + strlen(probe->name) + 1 + strlen(probe->arguments) + 1;
}

static void probe_encoder__write_probe(struct probe_encoder *encoder, struct probe *probe)
{
  // Write the header
  uint32_t note_name_len = sizeof(SDT_NOTE_NAME);
  write(encoder->fd, &note_name_len, sizeof(note_name_len));
  uint32_t probe_len = probe__length(probe);
  write(encoder->fd, &probe_len, sizeof(probe_len));
  write(encoder->fd, &SDT_NOTE_TYPE, sizeof(SDT_NOTE_TYPE));
  write(encoder->fd, SDT_NOTE_NAME, sizeof(SDT_NOTE_NAME));

  // Write the probe
  write(encoder->fd, &probe->address, sizeof(probe->address));
  write(encoder->fd, &probe->base_address, sizeof(probe->base_address));
  write(encoder->fd, &probe->semaphore_address, sizeof(probe->semaphore_address));

  write(encoder->fd, probe->provider, strlen(probe->provider) + 1);
  write(encoder->fd, probe->name, strlen(probe->name) + 1);
  write(encoder->fd, probe->arguments, strlen(probe->arguments) + 1);

  const char padding[4] = {0, 0, 0, 0};
  uint32_t padding_len = 4 - (probe_len % 4);
  if (padding_len != 4)
    write(encoder->fd, padding, padding_len);
}

static struct probe_inline_expansion *probe_encoder__add_inline_expansion(struct probe_encoder *encoder, struct inline_expansion *exp)
{
  struct probe_inline_expansion *probe_exp = zalloc(sizeof(*probe_exp));

  if (probe_exp) {
    probe_exp->exp = exp;
    list_add_tail(&probe_exp->node, &encoder->inline_expansions);
  }

  return probe_exp;
}

struct probe_encoder *probe_encoder__new(struct cu *cu, const char *detached_filename, struct btf *base_btf, bool verbose, struct conf_load *conf_load)
{
  struct probe_encoder *encoder = zalloc(sizeof(*encoder));

  if (encoder) {
    INIT_LIST_HEAD(&encoder->inline_expansions);
    encoder->fd = open("/tmp/note.stapsdt.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (encoder->fd < 0) {
      fprintf(stderr, "Failed to open note.stapsdt.bin: %s\n", strerror(errno));
      goto out_cleanup;
    }
    /* Add more initialisation above... */
    probe_encoders__add(encoder);
  }
  return encoder;

out_cleanup:
  probe_encoder__delete(encoder);
  return NULL;
}

void probe_encoder__delete(struct probe_encoder *encoder)
{
  if (encoder == NULL)
    return;

  if (encoder->fd >= 0)
    close(encoder->fd);

  probe_encoders__delete(encoder);

  free(encoder);
}

int probe_encoder__encode_cu(struct probe_encoder *encoder, struct cu *cu, struct conf_load *conf_load)
{
  // TODO: fill-in the magic!
  uint32_t id = 0;
  struct function *func = NULL;
  cu__for_each_function(cu, id, func) {
    uint64_t addr = function__addr(func);
    if (addr == 0)
      continue;

    const char *name = function__name(func);
    printf("%s @%#zx\n", name, addr);

    struct tag *tag = NULL;
    list_for_each_entry(tag, &func->lexblock.tags, node) {
      if (tag->tag == DW_TAG_formal_parameter) {
        struct parameter *param = tag__parameter(tag);
        printf("  param: %s\n", parameter__name(param));
      }
      if (tag->tag != DW_TAG_inlined_subroutine)
        continue;

      struct inline_expansion *exp = tag__inline_expansion(tag);
      probe_encoder__add_inline_expansion(encoder, exp);
      
      struct probe p = {0};
      p.address = exp->ip.addr;

      p.provider = "";
      const struct tag *talias = cu__function(cu, exp->ip.tag.type);
      struct function *alias = tag__function(talias);
      p.name = function__name(alias);
      p.arguments = "";

      printf(" inlined: %s\n", p.name);

      probe_encoder__write_probe(encoder, &p);
    }

    lexblock__fprintf(&func->lexblock, cu, func, 0, conf_load->conf_fprintf, stdout);
    puts("");
  }
  return 0;
}