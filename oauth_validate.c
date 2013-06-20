/* Oauth SASL plugin
 * Bill Mills
 * $Id:  $
 *
 * Copyright (c) 2010, Yahoo! Inc.
 * All rights reserved.
 *
 * OAuth Validation auxprop plugin.  This validates the OAuth specific
 * stuff specific to the OAuth impelemntation external to the SASL stuff.
 */


#include <config.h>

#include <stdio.h>

#include "sasl.h"
#include "saslutil.h"
#include "saslplug.h"

#include "plugin_common.h"

#include "oauth_validate.h"

#include <jansson.h>


static char oauth_validate[] = "oauth_validate";

typedef struct oauth_validatectx {
  char *username;
  char *payload;
                        /* We need al the OAuth validation stuff here too. */
  char *secret;	        /* OAuth token validation secret fir exampple.  */
  char *scopes[];       /* OAuth scopes accepted.  */
  
} oauth_validatectx_t;

oauth_validatectx_t glob_context;
/*
** A global context, not sure when it gets freed though.
*/
struct {
  /* We need al the OAuth validation stuff here too. */
  char *secret;         /* OAuth token validation secret fir exampple.  */
  char *scopes[];       /* OAuth scopes accepted.  */
} oauth_validate_globctx;

/*
** This is a no-op.  The store puts the values if any into the sparams->propctx.
*/ 
static void oauth_validate_auxprop_lookup(void *glob_context,
				  sasl_server_params_t *sparams,
				  unsigned flags,
				  const char *user,
				  unsigned ulen)
{
    return;
}

/*
** We're validating the credential on the store call.  The user parameter is overloaded
** here with the user credential to validate.  IN this case it's the whole payload
** which looks like an HTTP request (mostly).
**
** Success: returns SASL_OK and sets the username and payload strings in the 
** sparams->propctx context.
**
** The things we know about are:
**   OAUTH_VALIDATE_USERNAME       The name of the user from the token.
**   OAUTH_VALIDATE_PAYLOAD        Implementation specific data payload of the OAuth token. 
**
** Failure returs an appropriate error code and sets the error message if there's
** explanation needed.
*/
static int oauth_validate_auxprop_store(void *glob_context,
				  sasl_server_params_t *sparams,
				  struct propctx *prctx,
				  const char *user,
				  unsigned ulen)
{
  //    oauth_validatectx_t *ctx = glob_context;
    const struct propval *pr;
    int authhdrlen;
    unsigned decodedlen;
    int ret = SASL_OK;
    char *authhdr, *eolstr, *authbuf, *decoded;
    char *authhrdstr = "\r\nAuthorization: ";
    char *token_label = " token=\"";
    const char *username;
    const char *scope;
    int expires;
    json_t *jobj;
    json_error_t jerror;
    char *proplist[] = {OAUTH_VALIDATE_USERNAME,  
			      OAUTH_VALIDATE_PAYLOAD, 
			      NULL };


    /* just checking if we are enabled */
    if (!sparams || !user) return SASL_BADPARAM;

    pr = sparams->utils->prop_get(prctx);
    if (!pr) return SASL_BADPARAM;

    /* clear and previously set values (which shoudl be NULL anyway) */
    ret = sparams->utils->prop_request(prctx, proplist);
    if (!pr) return ret;
    ret = sparams->utils->prop_set(prctx, OAUTH_VALIDATE_USERNAME, NULL, 0);
    if (!pr) return ret;
    ret = sparams->utils->prop_set(prctx, OAUTH_VALIDATE_PAYLOAD, NULL, 0);
    if (!pr) return ret;

    /*
    ** In a real implementation we care about the GET line, the Host header
    ** and the Authorization header.  In our stub example we only care about
    ** the Authorization header line.
    **
    ** IN fact we only care about the token= part of the Auth header.
    */

    /* Get the contents of the Authoriaztion header. */
    if (!(authhdr = strstr(user, authhrdstr))) {
      return SASL_BADPROT; /* we must have the Authorization header. */
    }
    authhdr += strlen(authhrdstr); /* ignore the header label */
    /* properly formatted we must have a CRLF */
    if (!(eolstr = strstr(authhdr, "\r\n"))) {
      return SASL_BADPROT;
    }
    /* Now find the token=" withing the auth header */
    if (!(authhdr = strstr(authhdr, token_label))) {
      return SASL_BADPROT; /* we must have a token */
    }
    authhdr += strlen(token_label); /* ignore the token label */    
    for (eolstr = authhdr; *eolstr != '"'; eolstr++);

    authhdrlen = eolstr - authhdr ;

    /* slight optimization, 1 malloc for 2 spaces. */
    authbuf = sparams->utils->malloc(2*(authhdrlen+1));
    if (!authbuf) return SASL_NOMEM;
    decoded = authbuf + authhdrlen + 1;

    /* 
    ** In our stub we're expecting a base64 encoded JSON string. If we get
    ** one that works then we'll extract the fields we want and do rudimentary
    ** validation
    ** "userid" => $arguser
    ** "scope" => $argscope
    ** "expires" => time()+60
    */
    strncpy(authbuf, authhdr, authhdrlen);
    authbuf[authhdrlen] = 0;

    if (sparams->utils->decode64(authbuf, authhdrlen, decoded, authhdrlen, &decodedlen))
      ret = SASL_BADPROT; /* base64 decode failed */

    if (!(jobj = json_loads(decoded, 0, &jerror))) {
      ret = SASL_FAIL;
      goto cleanup;
    }
    
    username = json_string_value(json_object_get(jobj, "userid"));
    scope = json_string_value(json_object_get(jobj, "scope"));
    expires = json_integer_value(json_object_get(jobj, "expires"));

    /* we've extracted, now validate */
    if (!username || !strcmp(username, "")) {
      ret = SASL_BADAUTH;
      goto cleanup;
    }
    if (expires < time(NULL)) {
      ret = SASL_EXPIRED;
      goto cleanup;
    }
    /* 
    ** stub accepts unscoped or demo at the moment.  
    ** 
    ** XXXXXXX test in the global context for the configured scopes.
    */
    if (strcmp(scope, "") && strcmp(scope, "demo")) {
      ret = SASL_NOAUTHZ;
      goto cleanup;
    }

    /* 
    ** We're valid, pass back the values. We could also pass back 
    ** payload here, but the stub does not. 
    */
    ret = sparams->utils->prop_set(prctx, OAUTH_VALIDATE_USERNAME, username, 0);

 cleanup:
    if (authbuf) sparams->utils->free(authbuf);
    if (jobj) json_object_clear(jobj);
    return ret;
}

static void oauth_validate_auxprop_free(void *glob_ctx, const sasl_utils_t *utils)
{
  oauth_validatectx_t *text = (oauth_validatectx_t *)glob_ctx;

  if (text->username) utils->free(text->username);
  if (text->payload) utils->free(text->payload);

  utils->free(text);
}

static sasl_auxprop_plug_t oauth_validate_auxprop_plugin = {
    0,				/* Features */
    0,				/* spare */
    &glob_context,			/* glob_context */
    oauth_validate_auxprop_free,	/* auxprop_free */
    oauth_validate_auxprop_lookup,	/* auxprop_lookup */
    oauth_validate,			/* name */
    oauth_validate_auxprop_store	/* auxprop store */
};

int oauth_validate_auxprop_plug_init(const sasl_utils_t *utils,
                             int max_version,
                             int *out_version,
                             sasl_auxprop_plug_t **plug,
                             const char *plugname __attribute__((unused))) 
{
    const char *s;

    memset(&glob_context, 0, sizeof(oauth_validatectx_t));

    if(!out_version || !plug) return SASL_BADPARAM;

    if(max_version < SASL_AUXPROP_PLUG_VERSION) return SASL_BADVERS;
    
    utils->getopt(utils->getopt_context, oauth_validate, "oauth_validate_scope", &s, NULL);
    /*
    ** IF !s we only accept unscoped things.
    */
    if (s) {
      /* 
      ** XXXXX need to parse scopes here and put them into a scopes 
      ** list in a global context. 
      */
    }

    oauth_validate_auxprop_plugin.glob_context = &oauth_validate_globctx;

    *out_version = SASL_AUXPROP_PLUG_VERSION;

    *plug = &oauth_validate_auxprop_plugin;

    return SASL_OK;
}
