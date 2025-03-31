/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2025 Facebook

  Derived from ctf_encoder.c, which is:

  Copyright (C) Arnaldo Carvalho de Melo <acme@redhat.com>
  Copyright (C) Red Hat Inc
 */
#include <bpf/btf.h>

#include "dutil.h"
#include "dwarves.h"
#include "inline_encoder.h"
#include "list.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

enum loc_type {
	LOC_END_OF_EXPR,
	LOC_SIGNED_CONST_1,
	LOC_SIGNED_CONST_2,
	LOC_SIGNED_CONST_4,
	LOC_SIGNED_CONST_8,
	LOC_UNSIGNED_CONST_1,
	LOC_UNSIGNED_CONST_2,
	LOC_UNSIGNED_CONST_4,
	LOC_UNSIGNED_CONST_8,
	LOC_REGISTER,
} __attribute__((packed));

struct loc {
	enum loc_type type;
	uint8_t size;
};

struct inline_parameter {
	struct loc *location[16];
};

struct inline_instance {
	struct list_head node;
	uint64_t die_offset;
	const char *name;
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
	size_t nonames;

	struct list_head inline_instances;
};

struct loc_node {
	struct rb_node rb_node;
	struct list_head node;
	struct loc loc;
};

struct inline_encoder__header {
	uint16_t magic;
	uint8_t version;
	uint8_t flags;
	uint32_t header_size;
	uint32_t inline_info_offset;
	uint32_t inline_info_size;
	uint32_t location_offset;
	uint32_t location_size;
};

struct inline_encoder *inline_encoder__new(struct cu *cu, const char *detached_filename, struct btf *base_btf, bool verbose, struct conf_load *conf_load)
{
	struct inline_encoder *encoder = zalloc(sizeof(*encoder));

	if (encoder) {
		encoder->cu = cu;
		encoder->source_filename = strdup(cu->filename);
		encoder->filename = strdup(detached_filename ?: cu->filename);
		encoder->btf = base_btf;
		encoder->nonames = 0;

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
		for (size_t i = 0; i < exp->param_count; ++i)
			for (size_t j = 0; j < 16; ++j)
				free(exp->parameters[i].location[j]);
		free(exp);
	}

	free(encoder);
}

static size_t inline_instance__sizeof(uint16_t param_count)
{
	return offsetof(struct inline_instance, parameters) + param_count * sizeof(struct inline_parameter);
}

static struct loc *loc__make_const(bool is_signed, size_t size, uint64_t value)
{
	struct loc *new_loc = zalloc(sizeof(*new_loc) + size);
	if (new_loc == NULL)
		return NULL;
	new_loc->size = sizeof(struct loc) + size;
	switch (size) {
		case 1:
			new_loc->type = is_signed ? LOC_SIGNED_CONST_1 : LOC_UNSIGNED_CONST_1;
			break;
		case 2:
			new_loc->type = is_signed ? LOC_SIGNED_CONST_2 : LOC_UNSIGNED_CONST_2;
			break;
		case 4:
			new_loc->type = is_signed ? LOC_SIGNED_CONST_4 : LOC_UNSIGNED_CONST_4;
			break;
		case 8:
			new_loc->type = is_signed ? LOC_SIGNED_CONST_8 : LOC_UNSIGNED_CONST_8;
			break;
		default:
			free(new_loc);
			return NULL;
	}
	uint8_t *data = (uint8_t *)new_loc + sizeof(struct loc);
	memcpy(data, &value, size);
	return new_loc;
}

static struct loc *loc__make_register(uint8_t reg, int64_t offset)
{
	struct loc *new_loc = zalloc(sizeof(*new_loc) + sizeof(reg) + sizeof(offset));
	if (new_loc == NULL)
		return NULL;
	new_loc->size = sizeof(struct loc) + sizeof(uint8_t) + sizeof(int64_t);
	new_loc->type = LOC_REGISTER;
	uint8_t *data = (uint8_t *)new_loc + sizeof(struct loc);
	*data = reg;
	data += sizeof(uint8_t);
	memcpy(data, &offset, sizeof(int64_t));
	return new_loc;
}

static struct loc *loc__make_eoe(void)
{
	struct loc *new_loc = zalloc(sizeof(*new_loc));
	if (new_loc == NULL)
		return NULL;
	new_loc->type = LOC_END_OF_EXPR;
	new_loc->size = sizeof(*new_loc);
	return new_loc;
}

static uint32_t expr__size(struct loc *expr[16])
{
	uint32_t size = 0;
	for (size_t i = 0; i < 16; ++i) {
		if (expr[i] == NULL)
			break;
		size += expr[i]->size;
	}
	return size;
}

static int inline_encoder__encode_location(struct inline_encoder *encoder, struct location *loc, struct loc *expr[16])
{
	if (loc->expr == NULL && loc->exprlen == 0)
		return 0; 

	if (loc->expr == NULL) {
		expr[0] = loc__make_const(false, 8, loc->exprlen);
		return 0;
	}

	size_t expr_i = 0;
	for (size_t i = 0; i < loc->exprlen; ++i) {
		Dwarf_Op op = loc->expr[i];
		switch (op.atom) {
			case DW_OP_const1u:
			case DW_OP_const1s:
				expr[expr_i++] = loc__make_const(op.atom == DW_OP_const1s, 1, op.number);
				break;
			case DW_OP_const2u:
			case DW_OP_const2s:
				expr[expr_i++] = loc__make_const(op.atom == DW_OP_const1s, 2, op.number);
				break;
			case DW_OP_const4u:
			case DW_OP_const4s:
				expr[expr_i++] = loc__make_const(op.atom == DW_OP_const1s, 4, op.number);
				break;
			case DW_OP_const8u:
			case DW_OP_const8s:
				expr[expr_i++] = loc__make_const(op.atom == DW_OP_const1s, 8, op.number);
				break;
			case DW_OP_constu:
			case DW_OP_consts:
				expr[expr_i++] = loc__make_const(op.atom == DW_OP_consts, 8, op.number);
				break;
			case DW_OP_lit0 ... DW_OP_lit31: 
				expr[expr_i++] = loc__make_const(false, 1, op.atom - DW_OP_lit0);
				break;
			case DW_OP_reg0 ... DW_OP_reg31:
				expr[expr_i++] = loc__make_register(op.atom - DW_OP_reg0, 0);
				break;
			case DW_OP_breg0 ... DW_OP_breg31: {
				expr[expr_i++] = loc__make_register(op.atom - DW_OP_breg0, op.number);
				break;
			}
			case DW_OP_stack_value: {
				// no-op
				break;
			}
			default:
				goto out_err;
		}
		if (expr_i >= 16)
			goto out_err;
	}

	expr[expr_i++] = loc__make_eoe();
	return 0;

out_err:
	for (size_t i = 0; i < expr_i; ++i) {
		free(expr[i]);
		expr[i] = NULL;
	}

	return -1;
}

static inline struct dwarf_tag *tag__dwarf(const struct tag *tag)
{
	uint8_t *data = (uint8_t *)tag;
	return (struct dwarf_tag *)data;
}

static inline uint64_t die_offset(const struct tag *tag)
{
	uint8_t *data = (uint8_t *)tag;
	data -= 64;
	data += 24;
	return *(uint64_t *)data;
}

static int inline_encoder__save_inline_expansion(struct inline_encoder *encoder, struct inline_expansion *exp)
{
	if (exp->name == NULL)
		return 0;

	struct inline_instance *instance = zalloc(inline_instance__sizeof(exp->nr_parameters));
	if (instance == NULL)
		return -ENOMEM;

	instance->die_offset = die_offset((struct tag *)exp);
	instance->name = exp->name;
	instance->insn_offset = exp->ip.addr;
	instance->type_id = -1;
	instance->param_count = exp->nr_parameters;
	encoder->nonames += exp->name ? 1 : 0;
	// printf("inline instance for %u (%s): %lx %lx\n", instance->type_id, exp->name, instance->die_offset, instance->insn_offset);

	uint32_t param_index = 0;
	struct parameter *param = NULL;
	list_for_each_entry(param, &exp->parameters, tag.node) {
		inline_encoder__encode_location(encoder, &param->location, instance->parameters[param_index++].location);
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
	printf("nonames = %zu\n", encoder->nonames);
	int fd = open("/tmp/inline_expansions.btf", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		fprintf(stderr, "Failed to open /tmp/inline_expansions.btf: %s\n", strerror(errno));
		return -1;
	}
	struct inline_encoder__header header = {
		.magic = 0xeb9f,
		.version = 1,
		.flags = 0,
		.header_size = sizeof(header),
		.inline_info_offset = sizeof(struct inline_encoder__header),
		.inline_info_size = 0,
		.location_offset = 0,
		.location_size = 2,
	};
	write(fd, &header, header.header_size);

	struct inline_instance *exp;
	list_for_each_entry(exp, &encoder->inline_instances, node) {
		int type_id = btf__find_by_name_kind(encoder->btf, exp->name, BTF_KIND_FUNC);
		if (type_id < 0) {
			// printf("Failed to find type id for %s\n", exp->name);
			continue;
		}
		printf("Found type id for %s: %d\n", exp->name, type_id);
		exp->type_id = type_id;
		const void *data = exp;
		header.inline_info_size += write(
			fd,
			data + offsetof(struct inline_instance, insn_offset),
			inline_instance__sizeof(0)
				- offsetof(struct inline_instance, insn_offset)
				- 2); // Skip padding at the end of the struct
		for (uint16_t i = 0; i < exp->param_count; ++i) {
			struct inline_parameter *param = &exp->parameters[i];
			if (param->location[0] == NULL) {
				uint32_t zero = 0;
				header.inline_info_size += write(fd, &zero, sizeof(zero));
			} else {
				header.inline_info_size += write(fd, &header.location_size, sizeof(header.location_size));
				header.location_size += expr__size(param->location);
			}
		}
	}
	struct loc end_of_expr = {
		.type = LOC_END_OF_EXPR,
		.size = sizeof(end_of_expr),
	};
	write(fd, &end_of_expr, sizeof(end_of_expr));
	list_for_each_entry(exp, &encoder->inline_instances, node) {
		if (exp->type_id == -1)
			continue;
		for (uint16_t i = 0; i < exp->param_count; ++i) {
			struct inline_parameter *param = &exp->parameters[i];
			for (size_t j = 0; j < 16; ++j) {
				struct loc *op = param->location[j];
				if (op == NULL)
					break;
				write(fd, op, op->size);
			}
		}
	}
	header.location_offset = header.inline_info_offset + header.inline_info_size;
	lseek(fd, 0, SEEK_SET);
	write(fd, &header, header.header_size);
	close(fd);

	return 0;
}

void inline_encoder__set_btf(struct inline_encoder *encoder, struct btf *btf)
{
	encoder->btf = btf;
}
