/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2025 Facebook

  Derived from ctf_encoder.c, which is:

  Copyright (C) Arnaldo Carvalho de Melo <acme@redhat.com>
  Copyright (C) Red Hat Inc
 */

#include "dutil.h"
#include "dwarves.h"
#include "inline_encoder.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

struct inline_parameter {
	uint32_t location_offset;
};

struct inline_instance {
	struct list_head node;
	uint64_t insn_offset;
	type_id_t type_id;
	uint16_t param_count;
	struct inline_parameter parameters[];
};

struct inline_encoder {
	struct btf *btf;
	struct cu *cu;
	const char *source_filename;
	const char *filename;

	struct list_head inline_instances;
};

struct inline_encoder *inline_encoder__new(struct cu *cu, const char *detached_filename, struct btf *base_btf, bool verbose, struct conf_load *conf_load)
{
	struct inline_encoder *encoder = zalloc(sizeof(*encoder));

	if (encoder) {
		encoder->cu = cu;
		encoder->source_filename = strdup(cu->filename);
		encoder->filename = strdup(detached_filename ?: cu->filename);
		encoder->btf = base_btf;

		INIT_LIST_HEAD(&encoder->inline_instances);
	}

	return encoder;
}

void inline_encoder__delete(struct inline_encoder *encoder)
{
	if (encoder == NULL)
		return;

	zfree(&encoder->source_filename);
	zfree(&encoder->filename);
	encoder->btf = NULL; // Non-owning pointer to base BTF

	struct inline_instance *exp, *n;
	list_for_each_entry_safe_reverse(exp, n, &encoder->inline_instances, node) {
		list_del_init(&exp->node);
		free(exp);
	}

	free(encoder);
}

static size_t inline_instance__sizeof(uint16_t param_count)
{
	return offsetof(struct inline_instance, parameters) + param_count * sizeof(struct inline_parameter);
}

static int inline_encoder__save_inline_expansion(struct inline_encoder *encoder, struct inline_expansion *exp)
{
	struct inline_instance *instance = zalloc(inline_instance__sizeof(exp->nr_parameters));
	if (instance == NULL)
		return -ENOMEM;

	instance->insn_offset = exp->ip.addr;
	instance->type_id = exp->ip.tag.type;
	instance->param_count = exp->nr_parameters;

	uint32_t param_index = 0;
	struct parameter *param = NULL;
	list_for_each_entry(param, &exp->parameters, tag.node) {
		instance->parameters[param_index++].location_offset = 0;
	}

	INIT_LIST_HEAD(&instance->node);
	list_add_tail(&instance->node, &encoder->inline_instances);

	return 0;
}

static int inline_encoder__encode_lexblock(struct inline_encoder *encoder, struct lexblock *lexblock, struct conf_load *conf_load)
{
	int err = 0;

	struct tag *tag = NULL;
	list_for_each_entry(tag, &lexblock->tags, node) {
		if (tag->tag == DW_TAG_lexical_block) {
			err = inline_encoder__encode_lexblock(encoder, tag__lexblock(tag), conf_load);
			if (err)
				goto out;
			continue;
		} else if (tag->tag != DW_TAG_inlined_subroutine) {
			continue;
		}

		struct inline_expansion *exp = tag__inline_expansion(tag);
		err = inline_encoder__save_inline_expansion(encoder, exp);
		if (err)
			goto out;
	}

	return err;

out:
	return err;
}

int inline_encoder__encode_cu(struct inline_encoder *encoder, struct cu *cu, struct conf_load *conf_load)
{
	int err = 0;

	uint32_t fn_id;
	struct function *fn;
	cu__for_each_function(cu, fn_id, fn) {
		if (fn->declaration)
			continue;
		if (function__addr(fn) == 0)
			continue;

		err = inline_encoder__encode_lexblock(encoder, &fn->lexblock, conf_load);
		if (err)
			goto out;
	}
	return err;
out:
	return err;
}

int inline_encoder__encode(struct inline_encoder *encoder, struct conf_load *conf_load)
{
	int fd = open("/tmp/inline_expansions.btf", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		fprintf(stderr, "Failed to open /tmp/inline_expansions.btf: %s\n", strerror(errno));
		return -1;
	}
	struct inline_instance *exp;
	list_for_each_entry(exp, &encoder->inline_instances, node) {
		const void *data = exp;
		write(fd, data + sizeof(struct list_head), inline_instance__sizeof(exp->param_count) - sizeof(struct list_head));
	}
	close(fd);

	return 0;
}
