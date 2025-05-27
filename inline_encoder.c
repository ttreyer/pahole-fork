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
#include "gobuffer.h"
#include "inline_encoder.h"
#include "linux/btf.h"
#include "list.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

enum loc_type {
	LOC_NIL = 0,
	LOC_SIGNED_CONST_1,
	LOC_SIGNED_CONST_2,
	LOC_SIGNED_CONST_4,
	LOC_SIGNED_CONST_8,
	LOC_UNSIGNED_CONST_1,
	LOC_UNSIGNED_CONST_2,
	LOC_UNSIGNED_CONST_4,
	LOC_UNSIGNED_CONST_8,
	LOC_REGISTER,
	LOC_ADDR_REGISTER_OFFSET,
} __attribute__((packed));

struct loc {
	enum loc_type type;
	// operands[...]
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
	size_t inline_instance_cnt;

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
		encoder->inline_instance_cnt = 0;

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

static size_t loc__sizeof(enum loc_type type)
{
	size_t operands_size = 0;
	switch (type) {
		case LOC_NIL:
			operands_size = 0;
			break;
		case LOC_SIGNED_CONST_1:
		case LOC_UNSIGNED_CONST_1:
			operands_size = 1;
			break;
		case LOC_SIGNED_CONST_2:
		case LOC_UNSIGNED_CONST_2:
			operands_size = 2;
			break;
		case LOC_SIGNED_CONST_4:
		case LOC_UNSIGNED_CONST_4:
			operands_size = 4;
			break;
		case LOC_SIGNED_CONST_8:
		case LOC_UNSIGNED_CONST_8:
			operands_size = 8;
			break;
		case LOC_REGISTER:
			operands_size = 1;
			break;
		case LOC_ADDR_REGISTER_OFFSET:
			operands_size = 5;
			break;
	}
	return sizeof(struct loc) + operands_size;
}

static struct loc *loc__make_const(bool is_signed, size_t size, uint64_t value)
{
	struct loc *new_loc = zalloc(sizeof(*new_loc) + size);
	if (new_loc == NULL)
		return NULL;
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
	uint8_t *operands = (uint8_t *)new_loc + sizeof(*new_loc);
	memcpy(operands, &value, size);
	return new_loc;
}

static struct loc *loc__make_register(uint8_t reg)
{
	struct loc *new_loc = zalloc(loc__sizeof(LOC_REGISTER));
	if (new_loc == NULL)
		return NULL;
	new_loc->type = LOC_REGISTER;
	uint8_t *operands = (uint8_t *)new_loc + sizeof(*new_loc);
	memcpy(operands, &reg, sizeof(reg));
	return new_loc;
}

static struct loc *loc__make_addr_register_offset(uint8_t reg, int32_t offset)
{
	struct loc *new_loc = zalloc(loc__sizeof(LOC_ADDR_REGISTER_OFFSET));
	if (new_loc == NULL)
		return NULL;
	new_loc->type = LOC_ADDR_REGISTER_OFFSET;
	uint8_t *operands = (uint8_t *)new_loc + sizeof(*new_loc);
	memcpy(operands, &reg, sizeof(reg));
	operands += sizeof(reg);
	memcpy(operands, &offset, sizeof(offset));
	return new_loc;
}

static uint32_t expr__size(struct loc *expr[16])
{
	uint32_t size = 0;
	for (size_t i = 0; i < 16; ++i) {
		if (expr[i] == NULL)
			break;
		size += loc__sizeof(expr[i]->type);
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
				expr[expr_i++] = loc__make_register(op.atom - DW_OP_reg0);
				break;
			case DW_OP_breg0 ... DW_OP_breg31: {
				expr[expr_i++] = loc__make_addr_register_offset(op.atom - DW_OP_breg0, op.number);
				break;
			}
			case DW_OP_stack_value: {
				// no-op
				break;
			}
			default:
				goto out_err;
		}
		if (expr_i > 1)
			goto out_err;
	}

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

	struct inline_instance *instance = zalloc(inline_instance__sizeof(exp->nr_parms));
	if (instance == NULL)
		return -ENOMEM;

	instance->die_offset = die_offset((struct tag *)exp);
	instance->name = exp->name;
	instance->insn_offset = exp->ip.addr;
	instance->type_id = -1;
	instance->param_count = exp->nr_parms;
	// printf("inline instance for %u (%s): %lx %lx\n", instance->type_id, exp->name, instance->die_offset, instance->insn_offset);

	uint32_t param_index = 0;
	struct parameter *param = NULL;
	list_for_each_entry(param, &exp->parms, tag.node) {
		inline_encoder__encode_location(encoder, &param->location, instance->parameters[param_index++].location);
	}

	INIT_LIST_HEAD(&instance->node);
	list_add_tail(&instance->node, &encoder->inline_instances);
	encoder->inline_instance_cnt++;

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

struct node_type_id {
	const char *name;
	type_id_t type_id;
};

static int cmpstrp(const void *left, const void *right)
{
	struct node_type_id *left_node = (struct node_type_id*)left;
	struct node_type_id *right_node = (struct node_type_id*)right;
	return strcmp(left_node->name, right_node->name);
}

static struct node_type_id *build_type_id_cache(struct inline_encoder *encoder)
{
	struct node_type_id *exps = (struct node_type_id*)malloc(encoder->inline_instance_cnt * sizeof(struct node_type_id));

	size_t exp_id = 0;
	struct inline_instance *exp;
	list_for_each_entry(exp, &encoder->inline_instances, node) {
		exps[exp_id++] = (struct node_type_id){exp->name, 0};
	}

	qsort(exps, encoder->inline_instance_cnt, sizeof(struct node_type_id), cmpstrp);

	return exps;
}

static struct node_type_id *search_type_id_cache(struct btf *btf, struct node_type_id *cache, size_t cache_size, const char *name)
{
	struct node_type_id lookup_key = { name, 0 };
	struct node_type_id *found = bsearch(&lookup_key, cache, cache_size, sizeof(lookup_key), cmpstrp);
	assert(found != NULL);
	if (found->type_id == 0) {
		int type_id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);
		found->type_id = (type_id < 0) ? -1 : type_id;
	}
	return found;
}

static int inline_encoder__write_raw_file(struct inline_encoder *encoder, const char *filename)
{
	int err = -1;

	int fd = creat(filename, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		fprintf(stderr, "%s open(%s) failed!\n", __func__, filename);
		goto out;
	}

	struct inline_encoder__header header = {
		.magic = 0xeb9f,
		.version = 1,
		.flags = 0,
		.header_size = sizeof(header),
		.inline_info_offset = 0,
		.inline_info_size = 0,
		.location_offset = 0,
		.location_size = sizeof(struct loc), // first location is nil [1]
	};
	write(fd, &header, header.header_size);

	struct node_type_id *type_id_cache = build_type_id_cache(encoder);

	struct inline_instance *exp;
	list_for_each_entry(exp, &encoder->inline_instances, node) {
		struct node_type_id *found = search_type_id_cache(encoder->btf, type_id_cache, encoder->inline_instance_cnt, exp->name);
		exp->type_id = found->type_id;
		if (exp->type_id == -1) exp->type_id = 0;

		// Skip inline instances with no type information
		bool is_all_nil = exp->type_id == 0;
		for (uint16_t i = 0; i < exp->param_count; ++i) {
			struct inline_parameter *param = &exp->parameters[i];
			is_all_nil &= !param->location[0] || param->location[0]->type == LOC_NIL;
		}
		if (is_all_nil) continue;

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

	free(type_id_cache);

	enum loc_type nil = LOC_NIL;
	write(fd, &nil, sizeof(nil)); // Write first nil location [1]
	list_for_each_entry(exp, &encoder->inline_instances, node) {
		if (exp->type_id == -1)
			continue;
		for (uint16_t i = 0; i < exp->param_count; ++i) {
			struct inline_parameter *param = &exp->parameters[i];
			for (size_t j = 0; j < 16; ++j) {
				struct loc *op = param->location[j];
				if (op == NULL)
					break;
				write(fd, op, loc__sizeof(op->type));
			}
		}
	}
	header.location_offset = header.inline_info_offset + header.inline_info_size;
	lseek(fd, 0, SEEK_SET);
	write(fd, &header, header.header_size);

	close(fd);
	return 0;

out:
	if (fd != - 1)
		close(fd);
	unlink(filename);
	return err;
}

struct func_aux_header {
	uint16_t magic;
	uint8_t version;
	uint8_t flags;
	uint32_t header_size;

	uint32_t type_offset;
	uint32_t type_size;
	uint32_t string_offset;
	uint32_t string_size;
	uint32_t location_offset;
	uint32_t location_size;
};

static int btf_encoder__write_raw_file(struct btf *btf, struct gobuffer *params, const char *filename)
{
	__u32 raw_btf_size;
	const void *raw_btf_data = btf__raw_data(btf, &raw_btf_size);
	if (raw_btf_data == NULL) {
		fprintf(stderr, "%s: btf__raw_data failed!\n", __func__);
		return -1;
	}

	struct func_aux_header hdr = {};
	memcpy(&hdr, raw_btf_data, sizeof(hdr));
	hdr.header_size = sizeof(hdr);
	hdr.location_offset = hdr.string_offset + hdr.string_size;
	hdr.location_size = gobuffer__size(params);

	int fd = open(filename, O_WRONLY | O_CREAT, 0640);
	if (fd < 0) {
		fprintf(stderr, "%s: Couldn't open %s for writing the raw BTF info: %s\n", __func__, filename, strerror(errno));
		return -1;
	}
	int err = 0;
	err = write(fd, &hdr, sizeof(hdr));
	if (err < 0)
		fprintf(stderr, "%s: Couldn't write the BTF header to %s: %s\n", __func__, filename, strerror(errno));
	err = write(fd, raw_btf_data + sizeof(struct btf_header), raw_btf_size - sizeof(struct btf_header));
	if (err < 0)
		fprintf(stderr, "%s: Couldn't write the raw BTF info to %s: %s\n", __func__, filename, strerror(errno));
	if (params->entries) {
		params->entries[0] = 0;
		printf("%x %x %x %x %x %x %x %x\n", params->entries[0], params->entries[1], params->entries[2], params->entries[3], params->entries[4], params->entries[5], params->entries[6], params->entries[7]);
		err = write(fd, params->entries, gobuffer__size(params));
		if (err < 0)
			fprintf(stderr, "%s: Couldn't write the location info to %s: %s\n", __func__, filename, strerror(errno));
	}

	close(fd);

	// if ((uint32_t)err != raw_btf_size) {
	// 	fprintf(stderr, "%s: Could only write %d bytes to %s of raw BTF info out of %d, aborting\n", __func__, err, filename, raw_btf_size);
	// 	unlink(filename);
	// 	err = -1;
	// } else {
	// 	/* go from bytes written == raw_btf_size to an indication that all went fine */
	// 	err = 0;
	// }

	return err;
}

static int inline_encoder__write_func_aux(struct inline_encoder *encoder, const char *filename)
{
	int err = 0;

	int fd = creat(filename, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		fprintf(stderr, "%s open(%s) failed!\n", __func__, filename);
		err = errno;
		goto out;
	}

	struct btf *func_aux = btf__new_empty();
	if (func_aux == NULL) {
		err = -1;
		goto out_free_fd;
	}

	struct gobuffer *params = gobuffer__new();
	struct node_type_id *type_id_cache = build_type_id_cache(encoder);

	uint16_t max_funcsec_vlen = 0xfffc;
	uint16_t funcsec_vlen = 0xffff;

	size_t exp_count = 0;
	struct inline_instance *exp;
	list_for_each_entry(exp, &encoder->inline_instances, node) {
		if (funcsec_vlen++ == UINT16_MAX) {
			int funcsec_id = btf__add_funcsec(func_aux, ".text", 0);
			if (funcsec_id < 0) {
				fprintf(stderr, "btf__add_funcsec failed: %d\n", funcsec_id);
				err = funcsec_id;
				goto out_free;
			}
			funcsec_vlen = 1;
			if (max_funcsec_vlen < UINT16_MAX)
				max_funcsec_vlen++;
			printf("New funcsec id: %d, max vlen bumped to %x\n", funcsec_id, max_funcsec_vlen);
		}
		struct node_type_id *found = search_type_id_cache(encoder->btf, type_id_cache, encoder->inline_instance_cnt, exp->name);
		exp->type_id = found->type_id;
		if (exp->type_id == -1) exp->type_id = 0;

		exp_count++;
		btf__add_funcsec_fn_info(func_aux, exp->type_id, exp->insn_offset, gobuffer__size(params));
		for (uint16_t i = 0; i < exp->param_count; ++i) {
			struct inline_parameter *param = &exp->parameters[i];
			for (size_t j = 0; j < 16; ++j) {
				struct loc *op = param->location[j];
				if (op == NULL)
					break;
				gobuffer__add(params, op, loc__sizeof(op->type));
			}
		}
		// const struct btf_type *funcsec = btf__type_by_id(func_aux, 1);
		// printf("funcsec count=%4x, funcsec vlen=%4x\n", funcsec_vlen, btf_vlen(funcsec));
	}
	printf("Added %zu functions to funcsec\n", exp_count);

	free(type_id_cache);
	btf_encoder__write_raw_file(func_aux, params, filename);
	gobuffer__delete(params);

out_free:
	btf__free(func_aux);
out_free_fd:
	close(fd);
out:
	return err;
}

int inline_encoder__encode(struct inline_encoder *encoder, struct conf_load *conf_load)
{
	char tmp_fn[PATH_MAX];
	snprintf(tmp_fn, sizeof(tmp_fn), "%s.btf_inline", encoder->filename);

	int err = inline_encoder__write_raw_file(encoder, tmp_fn);
	if (err) return err;

	snprintf(tmp_fn, sizeof(tmp_fn), "%s.func_aux", encoder->filename);

	err = inline_encoder__write_func_aux(encoder, tmp_fn);
	if (err) return err;

	const char *llvm_objcopy = getenv("LLVM_OBJCOPY");
	if (!llvm_objcopy)
		llvm_objcopy = "llvm-objcopy";

	char cmd[PATH_MAX * 2];
	snprintf(cmd, sizeof(cmd), "%s --add-section .BTF_inline=%s %s",
		 llvm_objcopy, tmp_fn, encoder->filename);
	if (system(cmd)) {
		fprintf(stderr, "%s: failed to add .BTF_inline section '%s': %d!\n",
				__func__, tmp_fn, errno);
		err = -1;
		goto unlink;
	}

	err = 0;
unlink:
	// unlink(tmp_fn);
	return err;
}

void inline_encoder__set_btf(struct inline_encoder *encoder, struct btf *btf)
{
	encoder->btf = btf;
}
