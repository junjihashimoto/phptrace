/*
 * apmobs — a minimal Zend Observer-API extension for the bench.
 *
 * This is the *in-process, selective* competitor to the eBPF approaches:
 * `zend_observer_fcall_register` lets an extension attach begin/end hooks to
 * exactly the functions it wants (deciding once per function, cached), and —
 * unlike hooking zend_execute_ex — it does NOT disable the VM's DO_UCALL/
 * DO_ICALL specialization. It's what Datadog's ddtrace uses.
 *
 * Modes (env, read at MINIT):
 *   OBS_ALL=1        observe every userland function (per-call, but no trap,
 *                    no deopt) — the "observe everything" ceiling.
 *   OBS_FUNCS=a,b,c  observe only these function/method names (selective —
 *                    the realistic case: hook just what you need).
 *   (neither)        extension loaded but observes nothing — measures the
 *                    fixed cost of merely having the observer engine on.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "php.h"
#include "Zend/zend_observer.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned long long apmobs_calls = 0;
static int apmobs_all = 0;
static char apmobs_funcs[8192] = "";   /* ",name1,name2," for substring match */

static int should_observe(zend_function *fn)
{
    if (!fn || fn->type != ZEND_USER_FUNCTION)
        return 0;                       /* userland only */
    if (apmobs_all)
        return 1;
    if (!fn->common.function_name || apmobs_funcs[0] == '\0')
        return 0;
    char needle[256];
    snprintf(needle, sizeof(needle), ",%s,", ZSTR_VAL(fn->common.function_name));
    return strstr(apmobs_funcs, needle) != NULL;
}

/* representative per-call work: in-process, direct access to the frame
 * (no copy_from_user) — count the call and touch the function name. */
static void apmobs_begin(zend_execute_data *ex)
{
    apmobs_calls++;
    if (ex && ex->func && ex->func->common.function_name) {
        volatile size_t l = ZSTR_LEN(ex->func->common.function_name);
        (void)l;
    }
}
static void apmobs_end(zend_execute_data *ex, zval *retval)
{
    (void)ex; (void)retval;
}

static zend_observer_fcall_handlers apmobs_init(zend_execute_data *execute_data)
{
    zend_observer_fcall_handlers h = { NULL, NULL };
    if (should_observe(execute_data->func)) {
        h.begin = apmobs_begin;
        h.end = apmobs_end;
    }
    return h;
}

PHP_MINIT_FUNCTION(apmobs)
{
    const char *all = getenv("OBS_ALL");
    apmobs_all = (all && all[0] == '1');
    const char *fns = getenv("OBS_FUNCS");
    if (fns && fns[0])
        snprintf(apmobs_funcs, sizeof(apmobs_funcs), ",%s,", fns);
    zend_observer_fcall_register(apmobs_init);
    fprintf(stderr, "apmobs: MINIT all=%d funcs=%s\n", apmobs_all,
            apmobs_funcs[0] ? apmobs_funcs : "(none)");
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(apmobs)
{
    fprintf(stderr, "apmobs: observed calls=%llu\n", apmobs_calls);
    return SUCCESS;
}

zend_module_entry apmobs_module_entry = {
    STANDARD_MODULE_HEADER,
    "apmobs",
    NULL,                       /* functions */
    PHP_MINIT(apmobs),
    PHP_MSHUTDOWN(apmobs),
    NULL, NULL, NULL,
    "0.1",
    STANDARD_MODULE_PROPERTIES
};

ZEND_GET_MODULE(apmobs)
