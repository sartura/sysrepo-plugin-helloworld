#include <sys/wait.h>
#include <unistd.h>
#include <uci.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>

#include "sysrepo.h"
#include "sysrepo/plugins.h"
#include "sysrepo/values.h"

#include "common.h"

#define XPATH_MAX_LEN 100
#define UCIPATH_MAX_LEN 100

static const char *CONFIG_FILE = "helloworld";
static const char *MODULE_NAME = "helloworld";

/* Run-time information */
struct model {
    /* Sysrepo context */
    sr_subscription_ctx_t *subscription;

    /* UCI context */
    struct uci_context *uci_ctx;

    /* Model */
    char *name;
    char *greeting;
};

static int
rpc_greet_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt,
             sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    SRP_LOG_DBG_MSG("Helloworld 'Greet' RPC called.");

    int rc = SR_ERR_OK;
    struct model *model = private_ctx;
    char buf[100];

    if (model) {
        sprintf(buf, "%s, %s!", model->name, model->greeting);
        rc = sr_new_values(1, output);
        (*output)[0].type = SR_STRING_T;
        (*output)[0].data.string_val = model->name;
        *output_cnt = 1;
        return rc;
    }

    return SR_ERR_OK;
}

/**
 * Update running datastore with data from model.
 *
 * @param[model] model Run-time context.
 * @return UCI error code, UCI_OK on success.
 */
static int
model_to_sysrepo(sr_session_ctx_t *sess, struct model *model)
{
    int rc = SR_ERR_OK;
    sr_val_t val = { 0, };
    char xpath[XPATH_MAX_LEN];


    val.type = SR_STRING_T;
    val.data.string_val = model->name;
    snprintf(xpath,
             XPATH_MAX_LEN, "/helloworld:world/name");
    rc = sr_set_item(sess, xpath, &val, SR_EDIT_DEFAULT);
    SR_CHECK_RET(rc, exit, "sr_set_item fail: %s", sr_strerror(rc));

    val.type = SR_STRING_T;
    val.data.string_val = model->greeting;
    snprintf(xpath,
             XPATH_MAX_LEN, "/helloworld:world/greeting");
    rc = sr_set_item(sess, xpath, &val, SR_EDIT_DEFAULT);
    SR_CHECK_RET(rc, exit, "sr_set_item fail: %s", sr_strerror(rc));

    rc = sr_commit(sess);
    SR_CHECK_RET(rc, exit, "sr_commit fail: %s", sr_strerror(rc));

  exit:
    return rc;
}


/**
 * @brief Submit UCI option.
 *
 * @param[in] ctx Context used for looking up and setting UCI objects.
 * @param[in] str_opt Options key.
 * @param[in] str_val Options value.
 * @param[fmt] fmt Format for path identifier used in UCI.
 * @return UCI error code, UCI_OK on success.
 */
static int
submit_to_uci(struct uci_context *ctx, void *str_opt, char *str_val, char *fmt)
{
    int rc = UCI_OK;
    struct uci_ptr up;
    char ucipath[UCIPATH_MAX_LEN];

    sprintf(ucipath, fmt, str_opt, str_val);

    rc = uci_lookup_ptr(ctx, &up, ucipath, true);
    UCI_CHECK_RET(rc, exit, "uci_lookup_ptr fail: %d", rc);

    rc = uci_set(ctx, &up);
    UCI_CHECK_RET(rc, exit, "uci_set fail: %d", rc);

  exit:
    return rc;
}


/**
 * Update UCI configuration with data from model.
 *
 * @param[model] model Run-time context.
 * @return UCI error code, UCI_OK on success.
 */
static int
model_to_uci(struct model *model)
{
    int rc = UCI_OK;
    struct uci_package *package = NULL;

    rc = uci_load(model->uci_ctx, CONFIG_FILE, &package);
    UCI_CHECK_RET(rc, exit, "uci_load fail: %d", rc);

    rc = submit_to_uci(model->uci_ctx, model->name, "", "helloworld.helloworld.name=%s");
    UCI_CHECK_RET(rc, exit, "submit_to_uci fail: %d", rc);

    rc = submit_to_uci(model->uci_ctx, model->greeting, "",  "helloworld.helloworld.greeting=%s");
    UCI_CHECK_RET(rc, exit, "submit_to_uci fail: %d", rc);

    rc = uci_commit(model->uci_ctx, &package, false);
    UCI_CHECK_RET(rc, exit, "uci_commit fail: %d", rc);

    rc = uci_unload(model->uci_ctx, package);

    return UCI_OK;

  exit:
    if (package) {
        uci_unload(model->uci_ctx, package);
    }

    return rc;
}


/**
 * Update model from running datastore..
 *
 * @param[model] session Sysrepo session
 * @param[model] model Run-time context.
 * @return SR error code, SR_ERR_OK on success.
 */
static int
sysrepo_to_model(sr_session_ctx_t *session, struct model *model)
{
    char xpath[XPATH_MAX_LEN];
    sr_val_t *val= NULL;
    int rc = SR_ERR_OK;

    rc = sr_get_item(session, "/helloworld:world/name", &val);
    if (SR_ERR_OK == rc) {
        model->name = strdup(val->data.string_val);
    }

    rc = sr_get_item(session, "/helloworld:world/greeting", &val);
    if (SR_ERR_OK == rc) {
        model->greeting = strdup(val->data.string_val);
    }

    return rc;
}


/**
 * Update model from running datastore..
 *
 * @param[model] model Run-time context.
 * @param[s] s Section to get options from.
 */
static void
parse_section(struct model *model, struct uci_section *s)
{
    struct uci_element *e;
    struct uci_option  *o;

    printf("parse_section name %s\n", model->name);

    uci_foreach_element(&s->options, e) {
        o = uci_to_option(e);
        printf("opt: %s %s\n", o->e.name, o->v.string);
        if (!strcmp("name", o->e.name)) {
            /* Different device. */
            model->name = strdup(o->v.string);
            INF("Set name %s\n", model->name);
        }
        if (!strcmp("greeting", o->e.name)) {
            model->greeting = strdup(o->v.string);
            INF("Set greeting %s\n", model->greeting);
        }
    }
}

/**
 * Fill run-time model with  data from used system.
 *
 * @param[model] model Run-time context.
 * @return SR error code, SR_ERR_OK on success.
 */
static int
uci_to_model(struct model *model)
{
    struct uci_package *package = NULL;
    struct uci_element *e;
    struct uci_section *s;
    int rc;

    rc = uci_load(model->uci_ctx, CONFIG_FILE, &package);
    if (rc != UCI_OK) {
        fprintf(stderr, "No configuration (package): %s\n", CONFIG_FILE);
        goto out;
    }

    uci_foreach_element(&package->sections, e) {
        s = uci_to_section(e);
        INF("section: %s %s\n", s->type, s->e.name);
        if        (!strcmp(s->type, "demo")) {
            model->name = strdup(s->e.name);
            parse_section(model, s);
        }
    }

    if (package) {
        uci_unload(model->uci_ctx, package);
    }

    return UCI_OK;

  out:
    if (package) {
        uci_unload(model->uci_ctx, package);
    }
    return rc;
}


/* Check if running datastore has any nodes. */
static bool
is_datastore_empty(sr_session_ctx_t *session)
{
    sr_val_t *values = NULL;
    size_t count = 0;
    int rc = SR_ERR_OK;
    const char *xpath ="/helloworld:*//*";

    rc = sr_get_items(session, xpath, &values, &count);
    if (count) {
        INF("There are %d items in datastore\n", (int)count);
    }

    return SR_ERR_OK == rc ? count == 0 : -1;
}


/* If RUNNING configuration is empty, read configuration from UCI configuration file.
 * If UCI configuration is also empty, leave configuration empty
 */
static int
sync_datastores(sr_session_ctx_t *session, struct model *model)
{
    int rc = 0;
    bool empty = false;

    /* check if startup datastore is empty  */
    empty = is_datastore_empty(session);
    INF("datastore is %s empty", empty ? "" : "not");

    /* running datastre non-empty */
    if (!empty) {

        rc = sysrepo_to_model(session, model);
        SR_CHECK_RET(rc, error, "sync_datastores -> sysrepo_to_model: %s", sr_strerror(rc));

        rc = model_to_uci(model);
        SR_CHECK_RET(rc, error, "sync_datastores -> model_to_uci: %s", sr_strerror(rc));

        return SR_ERR_OK;

    } else if ((rc = uci_to_model(model)) != UCI_OK) {
        /* If running is empty than startup is empty so we have to fill it from UCI */
        WRN("Cant initialize data from UCI file [rc=%d].\n", rc);
        return SR_ERR_DATA_MISSING;

    } else {
        rc = model_to_sysrepo(session, model);
        SR_CHECK_RET(rc, error, "sync_datastores -> model_to_uci: %s", sr_strerror(rc));
    }

    return SR_ERR_OK;

  error:
    return rc;
}


int
module_change_cb(sr_session_ctx_t *session, const char *module_name,
                 sr_notif_event_t event, void *private_ctx)
{
    (void) event, (void) module_name;

    struct model *model = private_ctx;
    int rc = SR_ERR_OK;

    /* Handle module changes. */
    if (!model) {
        fprintf(stderr, "no runtime data available\n");
        goto error;
    }

    if (SR_EV_VERIFY == event) {
        printf("\n\n ========== VERIFYING: ==========\n\n");
        return SR_ERR_OK;
    }

    if (SR_EV_APPLY == event) {
        printf("\n\n ========== CONFIG HAS CHANGED, CURRENT RUNNING CONFIG: ==========\n\n");
    }

    rc = sysrepo_to_model(session, model);
    SR_CHECK_RET(rc, error, "sysrepo_to_model fail: %s", sr_strerror(rc));

    rc = model_to_uci(model);
    SR_CHECK_RET(rc, error, "module_change_cb %s", sr_strerror(rc));


    return SR_ERR_OK;

  error:
    return rc;
}


int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    sr_subscription_ctx_t *subscription = NULL;
    struct uci_context *uci_ctx = NULL;
    struct model *model = NULL;
    int rc = SR_ERR_OK;

    /* Allocate UCI context for uci files. */
    uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        fprintf(stderr, "Can't allocate uci\n");
        goto error;
    }

    rc = sr_rpc_subscribe(session, "/helloworld:greet", rpc_greet_cb, NULL,
                          SR_SUBSCR_CTX_REUSE, &subscription);
    SR_CHECK_RET(rc, error, "Rpc subscribe: %s", sr_strerror(rc));

    model = malloc(sizeof *model);
    model->uci_ctx = uci_ctx;
    model->subscription = subscription;

    /* Startup datastore is main one, if it is empty fill config from UCI file. */
    /* If UCI file is empty, run without initialized data. */
    rc = sync_datastores(session, model);
    SR_CHECK_RET(rc, error, "sync datastore: %s", sr_strerror(rc));

    /* Initialize module change handlers. */
    /* Store model to private context. */
    *private_ctx = model;

    rc = sr_module_change_subscribe(session, MODULE_NAME, module_change_cb, *private_ctx,
                                    0, SR_SUBSCR_DEFAULT, &model->subscription);
    SR_CHECK_RET(rc, error, "sr_module_change_subscribe failed: %s", sr_strerror(rc));

    return SR_ERR_OK;

  error:

    if (subscription) {
        sr_unsubscribe(session, model->subscription);
    }
    if (uci_ctx) {
        uci_free_context(uci_ctx);
    }
    if (model) {
        free(model);
    }

    return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    struct model *m = private_ctx;

    if (m) {
        sr_unsubscribe(session, m->subscription);
        uci_free_context(m->uci_ctx);
        free(m);
    }
}
