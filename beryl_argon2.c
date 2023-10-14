#include <berylscript.h>
#include <argon2.h>

#include <assert.h>
#include <string.h>
#include <limits.h>

static struct { int iterations; unsigned mem; int p; unsigned len; } params = {
	2,
	1024 * 1024 / 8, //1/8 a gigabyte. I.e 1024 * 1024 / 8 kB. ~ 128 MB
	2,
	32
};

static struct i_val cstr_to_beryl_str(const char *cstr) {
	if(cstr == NULL)
		return BERYL_NULL;
	
	size_t len = strlen(cstr);
	if(len > I_SIZE_MAX)
		return BERYL_NULL;
	
	return beryl_new_string(len, cstr);
}

static struct i_val hash_callback(const struct i_val *args, i_size n_args) {
	(void) n_args;
	if(BERYL_TYPEOF(args[0]) != TYPE_STR) {
		beryl_blame_arg(args[0]);
		return BERYL_ERR("Expected string as first argument for 'hash'");
	}
	if(BERYL_TYPEOF(args[1]) != TYPE_STR) {
		beryl_blame_arg(args[1]);
		return BERYL_ERR("Expected salt (string) as second argument for 'hash'");
	}
	
	i_size str_len = BERYL_LENOF(args[0]);
	i_size salt_len = BERYL_LENOF(args[1]);
	
	struct i_val hash_res = beryl_new_string(params.len, NULL);
	if(BERYL_TYPEOF(hash_res) == TYPE_NULL)
		return BERYL_ERR("Out of memory");
	
	char *hash_to = (char *) beryl_get_raw_str(&hash_res);
	int res = argon2i_hash_raw(
		params.iterations, 
		params.mem, 
		params.p, 
		beryl_get_raw_str(&args[0]), 
		str_len, 
		beryl_get_raw_str(&args[1]), 
		salt_len, 
		hash_to, 
		params.len
	);
	
	if(res != ARGON2_OK) {
		struct i_val str_msg = cstr_to_beryl_str(argon2_error_message(res));
		beryl_blame_arg(str_msg);
		beryl_release(str_msg);
		return BERYL_ERR("Argon2 error");
	}
	
	return hash_res;
}

static struct i_val encode_callback(const struct i_val *args, i_size n_args) {
	(void) n_args;
	if(BERYL_TYPEOF(args[0]) != TYPE_STR) {
		beryl_blame_arg(args[0]);
		return BERYL_ERR("Expected string as first argument for 'hash'");
	}
	if(BERYL_TYPEOF(args[1]) != TYPE_STR) {
		beryl_blame_arg(args[1]);
		return BERYL_ERR("Expected salt (string) as second argument for 'hash'");
	}
	
	i_size salt_len = BERYL_LENOF(args[1]);
	size_t total_len = argon2_encodedlen(params.iterations, params.mem, params.p, salt_len, params.len, Argon2_i);
	if(total_len > I_SIZE_MAX)
		return BERYL_ERR("Resulting string would be too large");
	
	struct i_val res = beryl_new_string(total_len, NULL);
	if(BERYL_TYPEOF(res) == TYPE_NULL)
		return BERYL_ERR("Out of memory");
	char *hash_to = (char *) beryl_get_raw_str(&res);
	
	int err = argon2i_hash_encoded(
		params.iterations, 
		params.mem, 
		params.p, 
		beryl_get_raw_str(&args[0]), 
		BERYL_LENOF(args[0]),
		beryl_get_raw_str(&args[1]),
		salt_len,
		params.len,
		hash_to,
		total_len
	);
	
	if(err != ARGON2_OK) {
		struct i_val str_msg = cstr_to_beryl_str(argon2_error_message(err));
		beryl_blame_arg(str_msg);
		beryl_release(str_msg);
		return BERYL_ERR("Argon2 error");
	}
	
	return res;
}

static struct i_val verify_callback(const struct i_val *args, i_size n_args) {
	(void) n_args;
	if(BERYL_TYPEOF(args[0]) != TYPE_STR) {
		beryl_blame_arg(args[0]);
		return BERYL_ERR("Expected string as first argument for 'verify'");
	}
	if(BERYL_TYPEOF(args[1]) != TYPE_STR) {
		beryl_blame_arg(args[1]);
		return BERYL_ERR("Expected string as second argument for 'verify'");
	}
	
	char *c_hashstr = beryl_talloc(BERYL_LENOF(args[0]) + 1);
	if(c_hashstr == NULL)
		return BERYL_ERR("Out of memory");
	
	memcpy(c_hashstr, beryl_get_raw_str(&args[0]), BERYL_LENOF(args[0]));
	c_hashstr[BERYL_LENOF(args[0])] = '\0';
	
	const char *pswd = beryl_get_raw_str(&args[1]);
	i_size pswd_len = BERYL_LENOF(args[1]);
	
	int res = argon2i_verify(c_hashstr, pswd, pswd_len);
	if(res == ARGON2_OK)
		return BERYL_BOOL(1);
	else if(res == ARGON2_VERIFY_MISMATCH)
		return BERYL_BOOL(0);
	else {
		struct i_val err_msg = cstr_to_beryl_str(argon2_error_message(res));
		beryl_blame_arg(err_msg);
		beryl_release(err_msg);
		return BERYL_ERR("Argon2 error");
	}
}

static bool loaded = false;

static struct i_val lib_val;

#define LENOF(a) (sizeof(a)/sizeof(a[0]))


static void init_lib() {
	#define FN(name, arity, fn) { arity, false, name, sizeof(name) - 1, fn }
	static struct beryl_external_fn fns[] = {
		FN("hash", 2, hash_callback),
		FN("encode", 2, encode_callback),
		FN("verify", 2, verify_callback)
	};
	
	
	
	struct i_val table = beryl_new_table(LENOF(fns), true);
	if(BERYL_TYPEOF(table) == TYPE_NULL) {
		lib_val = BERYL_ERR("Out of memory");
		return;
	}
	
	for(size_t i = 0; i < LENOF(fns); i++) {
		beryl_table_insert(&table, BERYL_STATIC_STR(fns[i].name, fns[i].name_len), BERYL_EXT_FN(&fns[i]), false);
	}
	
	lib_val = table;
}

struct i_val beryl_lib_load() {
	bool ok_version = BERYL_LIB_CHECK_VERSION("0", "0");
	if(!ok_version) {
		return BERYL_ERR("Library `Argon2` only works for version 0:0:x");
	}
	
	if(!loaded) {
		init_lib();
		loaded = true;
	}
	return beryl_retain(lib_val);
}
