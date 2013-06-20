/* Oauth SASL plugin
 * Bill Mills
 * $Id:  $
 *
 * Copyright (c) 2010, Yahoo! Inc.
 * All rights reserved.
 */


#include <config.h>
#include <stdio.h>
#include <string.h> 
#include <sasl.h>
#include <saslplug.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <curl/curl.h>
#include <curl/easy.h>

#include <jansson.h>

// #include <plugin_common.h>
#include "oauth_validate.h"

#ifdef macintosh 
#include <sasl_oauth_plugin_decl.h> 
#endif 

char *base64(const unsigned char *input, int length);
int base64d(const unsigned char *input, int length, char **outbuf);

#define SASL_UTIL_MALLOC       sparams->utils->malloc
#define SASL_UTIL_FREE         sparams->utils->free

#define MECH_NAME              "OAUTH"
#define DEFAULT_VALIDATOR      "oauth_validate"

#define CSTATE_NEW             0     /* don't have anything yet. */
#define CSTATE_DISCOVER        1     /* sent a discovery request */
#define CSTATE_TOKEN           2     /* have discovery information, 
				     ** now we might need to fetch 
				     ** tokens, or we might have a 
				     ** valid token already
				     */
#define OAUTH_MAX_DISCOVER     4096
#define ERRBUFFLEN 128

#define DISCOVERY_HDR_BANNER   "HTTP/1.1 401 Unauthorized\r\n"
#define HTTP_RPY_1_1           "HTTP/1.1 "
#define HTTP_HDR_BANNER        "GET / HTTP/1.1\r\n"
#define WWW_AUTHENTICATE       "WWW-Authenticate: Token "
#define HDR_AUTH_STR           "\r\nAuthorization: "
#define HDR_USER_STR           "\r\nUser: "
#define HDR_HOST_STR           "\r\nHost: "
#define DISCOVERY_HDR_AURI     "auth_uri=\""
#define DISCOVERY_HDR_TURI     "token_uri=\""
#define DISCOVERY_HDR_SCOPE    "scope=\""
#define DISCOVERY_HDR_ERROR    "error=\""


int oauth_client_mech_step_disco(void *conn_context,
                                 sasl_client_params_t *params,
                                 const char *serverin,
                                 unsigned serverinlen,
                                 sasl_interact_t **prompt_need,
                                 const char **clientout,
                                 unsigned *clientoutlen,
                                 sasl_out_params_t *oparams);

int oauth_client_mech_step_token(void *conn_context,
                                 sasl_client_params_t *params,
                                 const char *serverin,
                                 unsigned serverinlen,
                                 sasl_interact_t **prompt_need,
                                 const char **clientout,
                                 unsigned *clientoutlen,
                                 sasl_out_params_t *oparams);


/*****************************  Common Section  *****************************/

static const char plugin_id[] = "$Id: plain.c,v 1.64 2004/09/08 11:06:11 mel Exp $";

/*****************************  Server Section  *****************************/


typedef struct server_context {
  int result;
  char *name;
  char *error;
  char *validator_name;
  sasl_auxprop_plug_t oauth_validator;
  struct propctx *propctx;
} server_context_t;

/*
** Callback to store the oauth_validator auxprop plugin pointer
*/
void oauth_validator_info_callback_t (sasl_auxprop_plug_t *m,
				      sasl_info_callback_stage_t stage,
				      void *rock) {

  server_context_t *text = (server_context_t *)rock;

  switch (stage) {
  case SASL_INFO_LIST_START:
  case SASL_INFO_LIST_END:
    break;
  case SASL_INFO_LIST_MECH:
    memcpy(&text->oauth_validator, m, sizeof(sasl_auxprop_plug_t));
    break;
  }
}

/*
** Mech initializer
*/
static int
oauth_server_mech_new(void *glob_context __attribute__((unused)),
		      sasl_server_params_t *sparams,
		      const char *challenge __attribute__((unused)),
		      unsigned challen __attribute__((unused)),
		      void **conn_context)
{
  server_context_t *text;
  const char *tmp;
  int ret;
    
  /* holds state are in */
  text = sparams->utils->malloc(sizeof(server_context_t));
  if (text == NULL) {
    MEMERROR( sparams->utils );
    return SASL_NOMEM;
  }
    
  memset(text, 0, sizeof(server_context_t));
  text->result = SASL_BADPROT;
  /*    text->error = strdup("OAUTH mechanism: no transactions sent before ending."); */
  *conn_context = text;

  /*
  ** XXXXXX Should this really be in a more global palce and done just once?
  ** I don't think so because we can't do it on library init because the
  ** loading order may not be right for us.
  **
  ** Get the name of our validation auxprop plugin and then find the 
  ** handle to that plugin for use later.
  */
  sparams->utils->getopt(sparams->utils->getopt_context, MECH_NAME, 
			 "oauth_validator_mechanism", &tmp, NULL);
  if(!tmp) {
    if (!(tmp = strdup(DEFAULT_VALIDATOR))) return SASL_NOMEM;
  }
  /* need a prctx to use for holding authenticated user info  */
  if (NULL == (text->propctx = sparams->utils->prop_new(3)))
    return SASL_NOMEM;

  /*
  ** Now find our validator 
  */
  ret = auxprop_plugin_info(tmp, oauth_validator_info_callback_t, text);
  if (!text->oauth_validator.auxprop_lookup) {
    SETERROR(sparams->utils, "OAUTH: Counld not find oauth validator plugin.");
    return SASL_FAIL;
  }
    
  /* */
  return ret;
}

/*
** oauth_server_fmt_discovery
**
** Function to format the discovery info in the session.
*/
char *oauth_auth_uri = "http://frustration.corp.yahoo.com/oauth.php";
char *oauth_token_uri = "http://frustration.corp.yahoo.com/oauth.php";
char *oauth_server_scope = "";

int oauth_server_fmt_discovery(server_context_t *text,
			       sasl_server_params_t *sparams,
			       int ecode,
			       const char *error) {
  const char *discover_format;

  discover_format = "HTTP/1.1 %d Unauthorized\r\nWWW-Authenticate: Token realm=\"Service\", error=\"%s\", auth_uri=\"%s\", token_uri=\"%s\", scope=\"%s\"\r\n\r\n";

  if (NULL == text->error) {
    text->error = sparams->utils->malloc(OAUTH_MAX_DISCOVER +1);
    if (text->error == NULL) {
      MEMERROR(sparams->utils);
      return SASL_NOMEM;
    }
    text->error[OAUTH_MAX_DISCOVER] = '\0';

    /* Format the proper error/discovery info */
    if (OAUTH_MAX_DISCOVER < snprintf(text->error, OAUTH_MAX_DISCOVER+1, 
				      discover_format, ecode, error, 
				      oauth_auth_uri, oauth_token_uri,
				      oauth_server_scope)) {
      SETERROR(sparams->utils, "OAUTH: discovery information too long.");
      return SASL_BUFOVER;
    }
  }
  return SASL_OK;
}


/*
** oauth_server_mech_step
**
** Standard server plugin step handler.
*/
static int
oauth_server_mech_step(void *conn_context,
		       sasl_server_params_t *sparams,
		       const char *clientin,
		       unsigned clientinlen,
		       const char **serverout,
		       unsigned *serveroutlen,
		       sasl_out_params_t *oparams)
{
  server_context_t *text = (server_context_t *)conn_context;
  char *tmpstr;
  int hdrlen = strlen(HDR_AUTH_STR);
  int result, result2;
  const struct propval *pv;

  /* 
  ** If we got nothing this indicates the end of the negotiation. This is the
  ** server's cue to send back whatever result state we have pending.  Note that
  ** we're setting the default state as SASL_BADPROT in the mech_new step.
  */
  if (clientinlen == 0) {
    return text->result;
  }

  /*
  ** The basics here are that evrything requires an HTTP GET string and Host 
  ** header.
  */
  if ((0 != strncmp(clientin, HTTP_HDR_BANNER, strlen(HTTP_HDR_BANNER))) ||
      (NULL == strstr(clientin, HDR_HOST_STR)) ||
      (NULL == (tmpstr = strstr(clientin, HDR_AUTH_STR)))) {
    SETERROR(sparams->utils, "OAUTH: GET banner, Host, and Authorization headers required.");
    return SASL_BADPROT;
  }
  /*
  ** If we got here we have something to think about.  Basically, if we get something
  ** in that looks kind of right we'll hand it off to be authenticated, otherwise
  ** we return discovery.  In this very basic implementation, we're not actually 
  ** doing variable discovery info.
  **
  ** Simple to see if we have an empty Authorization header now.
  */
  if (tmpstr[hdrlen] == '\r' && tmpstr[hdrlen+1] == '\n') {
    /* 
    ** format discovery info into text-error.  We send 'discovery' as
    ** the error.
    **
    ** XXXXXXX N.B. 'discovery' is not in the OAuth protocol right now.
    */
    result = oauth_server_fmt_discovery(text, sparams, 401, "discovery");
    if (SASL_OK != result)
      return result;

    /* take our error/discovery and send it. */
    *serverout = text->error;
    *serveroutlen = (unsigned) strlen(text->error);
    
    /*
    ** At this point we've sent discovery information back to the user, at 
    ** this point we set SASL_FAIL as our pending return value, which is 
    ** strictly true since if you're querying discovery info and do nothing
    ** else authentication has failed.
    */
    text->result = SASL_FAIL;
    return SASL_CONTINUE;
  }
  /*
  ** If we get here it's a nominally valid, non-discovery request.  Here
  ** we cal out to the validation plugin and see what we get.
  ** 
  ** XXXXXXX is using a propctx local to the connection right here, or should it be sparams->propctx?
  ** we could use text->propctx.  Also, I don't think the global context is right here.
  */
  result = text->oauth_validator.auxprop_store(text->propctx, sparams, text->propctx, 
					       clientin, clientinlen);
  /*
  ** Failure means set the error state.  We don't end because we give 
  ** the client the opportunity to correct an expired token.  We need to
  ** send back the proper error code.
  */
  switch (result) {
  case SASL_OK:
    /* 
    ** if we were able to store the credential that means validation succeeded,
    ** and the data we probably care about is now stored in the propctx in
    ** sparams.
    **
    ** go ahead and finalize successfully.
    **
    ** Several others are fatal.
    */
    //    prop_request(text->propctx, (const char**)names);
    pv = prop_get(text->propctx);
    while (pv && strcmp(OAUTH_VALIDATE_USERNAME, pv->name)) pv++;
    if (!pv) 
      return SASL_FAIL;
    
    result = sparams->canon_user(sparams->utils->conn, pv->values[0], 
				 0, SASL_CU_AUTHID, oparams);
    result = sparams->canon_user(sparams->utils->conn, pv->values[0], 
				 0, SASL_CU_AUTHZID, oparams);
    if (result != SASL_OK) return result;
    /* set oparams, we succeeded */
    oparams->doneflag = 1;
    oparams->mech_ssf = 0;
    oparams->maxoutbuf = 0;
    oparams->encode_context = NULL;
    oparams->encode = NULL;
    oparams->decode_context = NULL;
    oparams->decode = NULL;
    oparams->param_version = 0;

    return SASL_OK;
    break;
  case SASL_FAIL:
  case SASL_BADPROT:
  case SASL_NOMEM:
  case SASL_BADAUTH:
    // BAD_AUTH could be 
    //   if (SASL_OK != oauth_server_fmt_discovery(text, sparams, 401, "invalid-token"))
    return result;
    break;
  case SASL_EXPIRED:
    if (SASL_OK != (result2 = oauth_server_fmt_discovery(text, sparams, 
							 401, "expired-token")))
      return result2;
    break;
  case SASL_NOAUTHZ:
    /* using this for scope failure */
    if (SASL_OK != (result2 = oauth_server_fmt_discovery(text, sparams, 
							 403, "insufficient-scope")))
      return result;
    break;
    text->result = result;
  }
    
  return SASL_CONTINUE;
}


static void oauth_server_mech_dispose(void *conn_context,
				      const sasl_utils_t *utils)
{
  server_context_t *text = (server_context_t *) conn_context;
    
  if (!text) return;
    
  if (text->error) _plug_free_string(utils,&(text->error));
  if (text->name) _plug_free_string(utils,&(text->name));
  if (text->error) _plug_free_string(utils,&(text->error));
  if (text->validator_name) utils->free(text->validator_name);
  //  if (text->oauth_validator) utils->free(text->oauth_validator);
  if (text->propctx) utils->prop_dispose(&(text->propctx));
    
  utils->free(text);
}

static sasl_server_plug_t oauth_server_plugins[] = 
  {
    {
      MECH_NAME,			/* mech_name */
      0,				/* max_ssf */
      SASL_SEC_NOPLAINTEXT
      | SASL_SEC_NOANONYMOUS,		/* security_flags */
      SASL_FEAT_WANT_CLIENT_FIRST,	/* features */
      NULL,				/* glob_context */
      &oauth_server_mech_new,	/* mech_new */
      &oauth_server_mech_step,	/* mech_step */
      &oauth_server_mech_dispose,	/* mech_dispose */
      NULL,				/* mech_free */
      NULL,				/* setpass */
      NULL,				/* user_query */
      NULL,				/* idle */
      NULL,				/* mech avail */
      NULL				/* spare */
    }
  };

/*   printf("debug: %s %d \n", __FILE__, __LINE__); */

int oauth_server_plug_init(const sasl_utils_t *utils,
			   int maxversion,
			   int *out_version,
			   sasl_server_plug_t **pluglist,
			   int *plugcount)
{
  if (maxversion < SASL_SERVER_PLUG_VERSION) {
    SETERROR( utils, "OAUTH version mismatch");
    return SASL_BADVERS;
  }
  
  *out_version = SASL_SERVER_PLUG_VERSION;
  *pluglist = oauth_server_plugins;
  *plugcount = 1;  
  
  return SASL_OK;
}


/*****************************  Client Section  *****************************/

#define MAX_OAUTH_CRSIZE 4096  /* Max auth header size is about 2k so 4k shoudl be enough */
typedef struct curl_data {
  char *data;
  int code;
  int size;
  int offset;
} curl_data_t;

typedef struct client_context {
  char *out_buf;
  unsigned out_buf_len;
  char *username;
  char *password;
  char *refresh;
  char *access;
  char *auth_uri;
  char *token_uri;
  char *scope;
  int access_expiry;
  int state;
  char cr_buffer[MAX_OAUTH_CRSIZE+1];
  char authhdr_buffer[MAX_OAUTH_CRSIZE+1];
  curl_data_t curl;
  int token_sent;
} client_context_t;



static int oauth_client_mech_new(void *glob_context __attribute__((unused)),
				 sasl_client_params_t *params,
				 void **conn_context)
{
  client_context_t *text;
    
  /* holds state are in */
  text = params->utils->malloc(sizeof(client_context_t));
  if (text == NULL) {
    MEMERROR( params->utils );
    return SASL_NOMEM;
  }
  memset(text, 0, sizeof(client_context_t));
 
  *conn_context = text;
    
  return SASL_OK;
}
/*
** oauth_client_curl_write_cb
**
** Catches the data read by CURL
**
** XXXXXXXX Note that we're assuming that we'll have Content-Length.
** This probably needs to be fixed.
*/
size_t oauth_client_curl_hdr_cb(void *buffer, size_t size, 
				  size_t nmemb, void *userp) {
  curl_data_t *curldata = userp;
  int sizeN = size * nmemb;
  char *buff = buffer;

  if (0 == strncmp("HTTP/1.1 ", buff, 8)) {
    if (curldata->data) {
      free(curldata->data);
      memset(curldata, 0, sizeof(curl_data_t));
    }
    curldata->code = atoi(buff+8);
  }

  if (0 == strncmp("Content-Length: ", buff, 16)) {
    curldata->size = atoi(buff+16);
    curldata->data = malloc(curldata->size +1);
    if (NULL == curldata->data) return 0;
    curldata->data[curldata->size] = 0;
  }

  return sizeN;
}

size_t oauth_client_curl_write_cb( void *ptr, size_t size, size_t nmemb, void *stream) {
  curl_data_t *curldata = stream;
  char *buff = ptr;
  int sizeN = size * nmemb;
  int cpsize=sizeN;
  int freesize;

  freesize = curldata->size - curldata->offset;
  if (sizeN > freesize) 
    cpsize = freesize;

  if (NULL == curldata->data || 0 == curldata->size) return 0;
  if (curldata->offset < curldata->size) {
    strncpy(curldata->data + curldata->offset, buff, cpsize);
    curldata->offset += cpsize;
  }

  return sizeN;
}

/*
** We evidently have an expired access token, let's get a new one.
*/
int oauth_client_refresh_token(void *conn_context,
			       sasl_client_params_t *params,
			       const char *serverin,
			       unsigned serverinlen,
			       sasl_interact_t **prompt_need,
			       const char **clientout,
			       unsigned *clientoutlen,
			       sasl_out_params_t *oparams)
{
  client_context_t *text = (client_context_t *) conn_context;
  int result=SASL_OK;
  char errbuff[ERRBUFFLEN + 1];
  CURL *easyhandle = curl_easy_init();

  //  char data[2048];
  //  char *data="name=daniel&project=curl";

  char *reqfmt = "grant_type=refresh-token&client_id=unreg:&client_secret=N/A&refresh_token=%s&format=json";

  char *safe_refresh = curl_easy_escape(easyhandle, text->refresh, 0);
  int bufflen = strlen(reqfmt)+1;
  char *postbuffer;
  json_t *jobj, *jtmp;
  json_error_t jerror;

  
  errbuff[ERRBUFFLEN] = 0;

  bufflen += strlen(safe_refresh);

  postbuffer = params->utils->malloc(bufflen);
  if (!postbuffer)
    return SASL_NOMEM;

  sprintf(postbuffer, reqfmt, safe_refresh);


  /* Set the form info */  
  curl_easy_setopt(easyhandle, CURLOPT_URL, text->auth_uri);
  curl_easy_setopt(easyhandle, CURLOPT_POSTFIELDS, postbuffer); 
  curl_easy_setopt(easyhandle, CURLOPT_POST, 1);
  curl_easy_setopt(easyhandle, CURLOPT_HEADER, 0);
  curl_easy_setopt(easyhandle, CURLOPT_HEADERFUNCTION, oauth_client_curl_hdr_cb);
  curl_easy_setopt(easyhandle, CURLOPT_WRITEFUNCTION, oauth_client_curl_write_cb);
  curl_easy_setopt(easyhandle, CURLOPT_WRITEDATA, &text->curl);
  curl_easy_setopt(easyhandle, CURLOPT_HEADERDATA, &text->curl);
  curl_easy_perform(easyhandle); /* post away! */ 

  /*
  ** Find out if we succeeded.  Failure means going back for 
  ** a new username/password.
  */
  switch (text->curl.code) {
  case 401:
    /* XXXXXXXX Should we send back to the password prompt here?  Right
    ** now we're returning out.
    */
    params->utils->free(text->username);
    text->username = NULL;
    text->state = CSTATE_NEW;
    result = SASL_BADAUTH;
    break;
  case 200:
    /* A 200 OK shoudl really have a JSON response in it... */
    if (!text->curl.data) {
      snprintf(errbuff, ERRBUFFLEN, 
	       "Remote auth server returned %d but no text.", text->curl.code);
      SETERROR( params->utils, errbuff);
      return SASL_BADPROT;
    }    
    jobj = json_loads(text->curl.data, 0, &jerror);
    if (!jobj) {
	SETERROR( params->utils, "JSON parse failed.");
	return SASL_BADPROT;
    } else {
      jtmp = json_object_get(jobj, "access_token");
      if (jtmp) {
	text->access = strdup(json_string_value(jtmp));
      } else {
	SETERROR( params->utils, "No access token returned.");
	return SASL_BADPROT;
      }
      /* returned scope is optional */
       jtmp = json_object_get(jobj, "scope");
      if (jtmp) {
	if (text->scope) 
	  params->utils->free(text->scope);
	text->scope = strdup(json_string_value(jtmp));
      }
      /* returned expiry is optional */
      jtmp = json_object_get(jobj, "expires");
      if (jtmp) {
	text->access_expiry = time(NULL) + json_integer_value(jtmp) - 1;
      }
   
      json_object_clear(jobj);
    }
    break;
  default:
    snprintf(errbuff, ERRBUFFLEN, 
	     "Remote auth server returns HTTP code %d", text->curl.code);
    SETERROR( params->utils, errbuff);
    return SASL_UNAVAIL;
  }


  return result;
}

/*
** 
** know the access token is expired we'll refresh it if we can.
*/

int oauth_client_get_access(void *conn_context,
			    sasl_client_params_t *params,
			    const char *serverin,
			    unsigned serverinlen,
			    sasl_interact_t **prompt_need,
			    const char **clientout,
			    unsigned *clientoutlen,
			    sasl_out_params_t *oparams)
{
  client_context_t *text = (client_context_t *) conn_context;
  int result=SASL_OK;
  char errbuff[ERRBUFFLEN + 1];
  CURL *easyhandle = curl_easy_init();
  
  char *reqfmt = "grant_type=basic-credentials&client_id=unreg:&client_secret=N/A&user=%s&password=%s&scope=%s&format=json";

  char *safe_user = curl_easy_escape(easyhandle, text->username, 0);
  char *safe_password = curl_easy_escape(easyhandle, text->password, 0);
  char *safe_scope = NULL;

  int bufflen = strlen(reqfmt)+1;
  char *postbuffer;

  json_t *jobj, *jtmp;
  json_error_t jerror;
  
  errbuff[ERRBUFFLEN] = 0;

  bufflen += strlen(safe_user) + strlen(safe_password);

  if (text->scope) {
    safe_scope = curl_easy_escape(easyhandle, text->scope, 0);
    bufflen += strlen(safe_scope);
  } else {
    safe_scope = "";
  }

  postbuffer = params->utils->malloc(bufflen);
  if (!postbuffer)
    return SASL_NOMEM;

  sprintf(postbuffer, reqfmt, safe_user, safe_password, safe_scope);


  /* Set the form info */  
  curl_easy_setopt(easyhandle, CURLOPT_URL, text->auth_uri);
  curl_easy_setopt(easyhandle, CURLOPT_POSTFIELDS, postbuffer); 
  curl_easy_setopt(easyhandle, CURLOPT_POST, 1);
  curl_easy_setopt(easyhandle, CURLOPT_HEADER, 0);
  curl_easy_setopt(easyhandle, CURLOPT_HEADERFUNCTION, oauth_client_curl_hdr_cb);
  curl_easy_setopt(easyhandle, CURLOPT_WRITEFUNCTION, oauth_client_curl_write_cb);
  curl_easy_setopt(easyhandle, CURLOPT_WRITEDATA, &text->curl);
  curl_easy_setopt(easyhandle, CURLOPT_HEADERDATA, &text->curl);
  curl_easy_perform(easyhandle); /* post away! */ 

  /* once we have an token we don't want the password anymore */
  params->utils->free(postbuffer);
  if (text->password) {
    memset(text->password, 0, strlen(text->password));
    params->utils->free(text->password);
    text->password = NULL;
  }

  /*
  ** Find out if we succeeded.  Failure means going back for 
  ** a new username/password.
  */
  switch (text->curl.code) {
  case 401:
    /* XXXXXXXX Should we send back to the password prompt here?  Right
    ** now we're returning out.
    */
    params->utils->free(text->username);
    text->username = NULL;
    text->state = CSTATE_NEW;
    result = SASL_BADAUTH;
    break;
  case 200:
    /* A 200 OK shoudl really have a JSON response in it... */
    if (!text->curl.data) {
      snprintf(errbuff, ERRBUFFLEN, 
	       "Remote auth server returned %d but no text.", text->curl.code);
      SETERROR( params->utils, errbuff);
      return SASL_BADPROT;
    }    
    jobj = json_loads(text->curl.data, 0, &jerror);
    if (!jobj) {
	SETERROR( params->utils, "JSON parse failed.");
	return SASL_BADPROT;
    } else {
      jtmp = json_object_get(jobj, "access_token");
      if (jtmp) {
	text->access = strdup(json_string_value(jtmp));
      } else {
	SETERROR( params->utils, "No access token returned.");
	return SASL_BADPROT;
      }
      /* returned refresh token is optional */
      jtmp = json_object_get(jobj, "refresh_token");
      if (jtmp) {
        if (text->refresh)
          params->utils->free(text->refresh);
	text->refresh = strdup(json_string_value(jtmp));
      }
      /* returned scope is optional */
      jtmp = json_object_get(jobj, "scope");
      if (jtmp) {
        if (text->scope)
          params->utils->free(text->scope);
        text->scope = strdup(json_string_value(jtmp));
      }
      /* returned expiry is optional */
      jtmp = json_object_get(jobj, "expires_in");
      if (jtmp) {
	text->access_expiry = time(NULL) + json_integer_value(jtmp) - 1;
      }

      json_object_clear(jobj);
    }
    break;
  default:
    snprintf(errbuff, ERRBUFFLEN, 
	     "Remote auth server returns HTTP code %d", text->curl.code);
    SETERROR( params->utils, errbuff);
    return SASL_UNAVAIL;
  }

  return result;
}

char oauth_client_request_format[] = "%sUser: %s\r\nHost: %s\r\nAuthorization: %s\r\n\r\n";

/*
** oauth_client_mech_step_one
**
** Sorts out what we have and what we need to do next, this is 
** where much of the brains are.
*/
int oauth_client_mech_step_one(void *conn_context,
			       sasl_client_params_t *params,
			       const char *serverin __attribute__((unused)),
			       unsigned serverinlen __attribute__((unused)),
			       sasl_interact_t **prompt_need,
			       const char **clientout,
			       unsigned *clientoutlen,
			       sasl_out_params_t *oparams)
{
  client_context_t *text = (client_context_t *) conn_context;
  const char *user = NULL, *authid = NULL;
  sasl_secret_t *password = NULL;
  unsigned int free_password = 0; /* set if we need to free password */
  int user_result = SASL_OK;
  int auth_result = SASL_OK;
  int pass_result = SASL_OK;
  int result;
  char *dupuser, *duppasswd;
    
  *clientout = NULL;
  *clientoutlen = 0;
    
  /* doesn't really matter how the server responds */
    
  /* check if sec layer strong enough */
  if (params->props.min_ssf > params->external_ssf) {
    SETERROR( params->utils, "SSF requested of OAUTH plugin");
    return SASL_TOOWEAK;
  }

  /*
  ** NOTE: need to implement auxprop storage for stuff.  Have to figure
  ** out how to do the default settings such as "remember me" should be
  ** done.  Question to answer, can we store an auxprop under an empty
  ** username ("")?
  **
  ** ALSO: need to figure out if multiple OAUTH mechanisms in a single
  ** process shoudl be sharing on the client side.  I believe the answer
  ** is yes.
  */
    
  /*
  ** Check and see if we yet have the username and password.  Make 
  ** sure we have taken the first step. If we prompt of one we'll prompt
  ** for both.
  **
  ** XXXXXXX Need to check for stored discovery information, if we have it
  ** we never need to go to the discover state.
  **
  ** XXXXXXX Will need to check for a stored valid acess token, or refresh 
  ** token before prompting for password sometime soon.
  */
  if (!text->username) {
    /* try to get the userid */
    if (oparams->user == NULL) {
      user_result = _plug_get_userid(params->utils, &user, prompt_need);
	
      if ((user_result != SASL_OK) && (user_result != SASL_INTERACT))
	return user_result;
    }
    if (!(dupuser = strdup(user)))
      return SASL_NOMEM;
    /* in this case authid = userid */
    authid = dupuser;
    
    /* try to get the password */
    if (password == NULL) {
      pass_result = _plug_get_password(params->utils, &password,
				       &free_password, prompt_need);
	
      if ((pass_result != SASL_OK) && (pass_result != SASL_INTERACT))
	return pass_result;
    }
    if (!(duppasswd = strdup((char *)password->data)))
      return SASL_NOMEM;
    
    /* free prompts we got */
    if (prompt_need && *prompt_need) {
      params->utils->free(*prompt_need);
      *prompt_need = NULL;
    }
    
    /* if there are prompts not filled in */
    if ((user_result == SASL_INTERACT) || (pass_result == SASL_INTERACT)) {
      /* make the prompt list */
      result =
	_plug_make_prompts(params->utils, prompt_need,
			   user_result == SASL_INTERACT ?
			   "Please enter your authorization name" : NULL,
			   NULL,
			   auth_result == SASL_INTERACT ?
			   "Please enter your authentication name" : NULL,
			   NULL,
			   pass_result == SASL_INTERACT ?
			   "Please enter your password" : NULL, NULL,
			   NULL, NULL, NULL,
			   NULL, NULL, NULL);
      if (result != SASL_OK) goto cleanup;
	
      return SASL_INTERACT;
    }
    
    if (!user || !password) {
      PARAMERROR(params->utils);
      return SASL_BADPARAM;
    }

    result = params->canon_user(params->utils->conn, user, 0,
				SASL_CU_AUTHZID, oparams);
    if (result != SASL_OK) goto cleanup;
    
    result = params->canon_user(params->utils->conn, authid, 0,
				SASL_CU_AUTHID, oparams);

    if (result != SASL_OK) goto cleanup;

    /*
    ** OK, so now we have a username and password.  Save them. 
    */
    text->username = dupuser;
    text->password = duppasswd;
  }

  /*
  ** We have the username/password now do something with it.  Next we 
  ** need discovery info for the user.  We'll know to ask for it if the
  ** auth_uri is not yet set.  We might already have it, if so then 
  ** use it.
  */
  if (!text->auth_uri) {
  
    /* we need to construct the reuqest to the server */
    text->authhdr_buffer[0] = '\0';
    *clientoutlen = snprintf(text->cr_buffer, MAX_OAUTH_CRSIZE+1, 
			     oauth_client_request_format, HTTP_HDR_BANNER,
			     user, params->serverFQDN, text->authhdr_buffer);
    if (MAX_OAUTH_CRSIZE < *clientoutlen) {
    SETERROR( params->utils, "Client request buffer size exceeded");
    return SASL_BUFOVER;
    }
    
    *clientout = text->cr_buffer;
    text->state = CSTATE_DISCOVER;
  } else {
    /* use the already discovered endpoints */
    result = oauth_client_get_access(conn_context, params, serverin,
                                     serverinlen, prompt_need, clientout,
                                     clientoutlen, oparams);
    if (SASL_OK != result)
      return result;

    text->state = CSTATE_TOKEN;
    result = oauth_client_mech_step_token(conn_context, params, serverin,
                                          serverinlen, prompt_need, clientout,
                                          clientoutlen, oparams);
    goto cleanup;
  }
  /*
  ** If we drop through to here send an empty message to end things.
  ** The way we know is if nothing else has set clientout.
  **
  ** This should just work because at the start of things we set
  **    *clientout = "";
  **    *clientoutlen = 0;
  */
    
  /* set oparams */
  oparams->doneflag = 0;
  oparams->mech_ssf = 0;
  oparams->maxoutbuf = 0;
  oparams->encode_context = NULL;
  oparams->encode = NULL;
  oparams->decode_context = NULL;
  oparams->decode = NULL;
  oparams->param_version = 0;
    
  result = SASL_CONTINUE;

  cleanup:
  /* free sensitive info */
  if (free_password) _plug_free_secret(params->utils, &password);
    
  return result;
}

/*
** If we have a token then we'll want to send it.  If we 
** know the access token is expired we'll refresh it if we can.
**
** We can also come here when we get a response to a token sent.
*/
int oauth_client_mech_step_token(void *conn_context,
				 sasl_client_params_t *params,
				 const char *serverin,
				 unsigned serverinlen,
				 sasl_interact_t **prompt_need,
				 const char **clientout,
				 unsigned *clientoutlen,
				 sasl_out_params_t *oparams)
{
  client_context_t *text = (client_context_t *) conn_context;
  int result, olen, ecode;
  unsigned tmplen;
  char *oauth_token_auth_format = "%sHost: \"%s\"\r\nAuthorization:  Token token=\"%s\"\r\n\r\n";
  char *tmpstr, *eolstr, *valstr, *eov, errbuf[128];

  /*
  ** If we have not yet sent a token then we'll send one.  Otherwise
  ** we'll need to figure out what the result of that token was.
  */
  if (!text->token_sent) {
    /* Do we need a new access token? If so, get one. */
    if (time(NULL) >= text->access_expiry) {
      result = oauth_client_refresh_token(conn_context, params, serverin,
					  serverinlen, prompt_need, clientout,
					  clientoutlen, oparams);
      if (SASL_OK != result) 
	return result;
    }
    /* Format the auth package info */
    olen = snprintf(text->cr_buffer, OAUTH_MAX_DISCOVER+1, oauth_token_auth_format,
		    HTTP_HDR_BANNER, params->serverFQDN, text->access);
    if (OAUTH_MAX_DISCOVER < olen) {
      SETERROR(params->utils, "OAUTH: access token too long.");
      return SASL_BUFOVER;
    }

    /* set oparams */
    *clientout = text->cr_buffer;
    *clientoutlen = strlen(text->cr_buffer);

    oparams->doneflag = 0;
    oparams->mech_ssf = 0;
    oparams->maxoutbuf = 0;
    oparams->encode_context = NULL;
    oparams->encode = NULL;
    oparams->decode_context = NULL;
    oparams->decode = NULL;
    oparams->param_version = 0;

    text->token_sent = 1;

    return SASL_CONTINUE;
  } else {
    /* 
    ** If we have already sent a token and ended up here then
    ** we got an error back from the server and we need to figure
    ** out what's next.
    **
    ** The first line must be an "HTTP/1.1 " from which we'll get 
    ** the result code.  
    */
    if (0 == serverinlen)
      return SASL_OK; /* empty reply we'll say is OK. */
    if (strncmp(HTTP_RPY_1_1, serverin, strlen(HTTP_RPY_1_1))) {
      SETERROR(params->utils, "OAUTH: Expecting HTTP/1.1 format response.");
      return SASL_BADPROT;
    }
    ecode = atoi(serverin + strlen(HTTP_RPY_1_1));
    /* And go find the error string. */
    if (NULL == (tmpstr = strstr(serverin, WWW_AUTHENTICATE)))
      return SASL_BADPROT;
    tmpstr += strlen(WWW_AUTHENTICATE);
    if (NULL == (eolstr = strstr(serverin, "\r\n")))
      return SASL_BADPROT;

    valstr = strstr(tmpstr, DISCOVERY_HDR_ERROR);
    if (NULL == valstr || valstr > eolstr)
      return SASL_BADPROT;
    valstr += strlen(DISCOVERY_HDR_ERROR);
    for (eov = valstr; '"' != *eov && eov < eolstr; eov++);
    if (eolstr == eov)
      return SASL_BADPROT;
    /* copy the error string */
    tmplen = eov - tmpstr;
    if (tmplen > sizeof(errbuf))
      return SASL_BUFOVER;
    strncpy(errbuf, tmpstr, tmplen);
    errbuf[tmplen] = '\0';

    /* 
    ** Now, having the error code and string we can do work. Being
    ** detail oriented here for supporting new returns that might 
    ** creep in.
    **
    ** N.B. that the 400 return code is actually handled at the SASL
    ** level, we don't need it here.
    */
    switch (ecode) {
    case 401: /* invalid-token and expired-token */
    case 403: /* right now this is only insufficient-scope */
      /* 
      ** So we have an invalid scope, which means the tokens are invalid.
      ** Only thing to do at this point is invalidate everything and start
      ** from scratch.
      */
      if (text->access) params->utils->free(text->access);
      if (text->refresh) params->utils->free(text->refresh);
      text->state = CSTATE_DISCOVER;
      return oauth_client_mech_step_disco(conn_context, params, serverin,
					  serverinlen, prompt_need,
					  clientout, clientoutlen, oparams);
    default:
      SETERROR(params->utils, "OAUTH: Expecting HTTP/1.1 format, no error code.");
      return SASL_BADPROT;
    }
  }

  return result;
}

/*
** findthis find and return the value flagged by the variable name
*/
int findthis(sasl_client_params_t *params, const char* haystack, 
	     const char* valname, char **ret) {
  char *this, *that;
  int len;

  *ret=NULL;

  if ((this = strstr(haystack, valname))){
    /* needs to be start of string or have a space or comma in front */
    if (!(this == haystack || ' ' == *(this-1) || ',' == *(this-1)))
      return SASL_BADPROT;
    this += strlen(valname);
    if (!(that = strstr(this, "\"")))
      return SASL_BADPROT;

    /* OK got it, get a copy and eturn it. */
    len = that - this;
    if (!(*ret = params->utils->malloc(len+1)))
      return SASL_NOMEM;
    (*ret)[len] = 0;
    strncpy(*ret, this, len);
  }

  return SASL_OK;
}
/*
** oauth_client_mech_step_disco
**
** The state of expecting discovery information to come back from 
** the server.  We'll parse it and store it.  Somewhere in here
** we'll be going to get an access and refresh token.
**
** This is  gonna be a very basic parser, since I don't want to
** pull in a general purpose one.
*/
int oauth_client_mech_step_disco(void *conn_context,
				 sasl_client_params_t *params,
				 const char *serverin,
				 unsigned serverinlen,
				 sasl_interact_t **prompt_need,
				 const char **clientout,
				 unsigned *clientoutlen,
				 sasl_out_params_t *oparams)
{
  client_context_t *text = (client_context_t *) conn_context;
  int result=SASL_OK, len;
  const char *here = serverin, *there;
  char *tmpstr;
  
  /* We're expecting a specific format in the response. */
  len = strlen(HTTP_RPY_1_1);
  if (strncasecmp(here, HTTP_RPY_1_1, len))
    return SASL_BADPROT;
  here += len;

  /* Be a little flexible now, other stuff may creep in over time. */
  if (NULL == (here=strstr(here, WWW_AUTHENTICATE)))
    return SASL_BADPROT;

  here += strlen(WWW_AUTHENTICATE); 
  if (NULL == (there=strstr(here, "\r\n")))
    return SASL_BADPROT;

  /* make a copy of the WWW-Authenticate repsonse so we can modify */
  len = there - here;
  if (!(tmpstr = params->utils->malloc(len+1)))
    return SASL_NOMEM;
  strncpy(tmpstr, here, len);
  tmpstr[len] = 0;

  /* now find the parts we need */
  result = findthis(params, tmpstr, DISCOVERY_HDR_AURI, &(text->auth_uri));
  if (SASL_OK == result) {
    result = findthis(params, tmpstr, DISCOVERY_HDR_TURI, &(text->token_uri));
    if (SASL_OK == result) {
      result = findthis(params, tmpstr, DISCOVERY_HDR_SCOPE, &(text->scope));
    }
  }
  params->utils->free(tmpstr);

  if (text->password) {
    text->state = CSTATE_TOKEN;
    /* 
    ** Since we now have discovery info we can go get a token and use it 
    */
    result = oauth_client_get_access(conn_context, params, serverin,
				     serverinlen, prompt_need, clientout,
				     clientoutlen, oparams);
    if (SASL_OK != result)
      return result;
    
    result = oauth_client_mech_step_token(conn_context, params, serverin,
					  serverinlen, prompt_need, clientout,
					  clientoutlen, oparams);
  } else {
    /* 
    ** this is spaghetti but expedient right now. We get here if we 
    ** had discovery info to parse but we don't have a password 
    ** anymore so we need to prompt for it.
    */
    text->state = CSTATE_NEW;
    result = oauth_client_mech_step_one(conn_context, params, serverin,
					  serverinlen, prompt_need, clientout,
					  clientoutlen, oparams);
  }
  return result;
}

/*
** oauth_client_mech_step
**
** Switcher function based on our current state to break this up into 
** digestable pieces.
*/
static int oauth_client_mech_step(void *conn_context,
				  sasl_client_params_t *params,
				  const char *serverin,
				  unsigned serverinlen,
				  sasl_interact_t **prompt_need,
				  const char **clientout,
				  unsigned *clientoutlen,
				  sasl_out_params_t *oparams)
{
  client_context_t *text = (client_context_t *) conn_context;
  int result;
  
  switch (text->state) {
  case CSTATE_NEW:
    result = oauth_client_mech_step_one(conn_context, params, serverin, 
					serverinlen, prompt_need, clientout, 
					clientoutlen, oparams);
    break;
  case CSTATE_DISCOVER:
    result = oauth_client_mech_step_disco(conn_context, params, serverin, 
					  serverinlen, prompt_need, clientout, 
					  clientoutlen, oparams);
    break;
  case CSTATE_TOKEN:
    result = oauth_client_mech_step_token(conn_context, params, serverin, 
					  serverinlen, prompt_need, clientout, 
					  clientoutlen, oparams);
    break;
  default:
    result = SASL_FAIL;
  }
  
  result = SASL_CONTINUE;
  
  return result;
}





static void oauth_client_mech_dispose(void *conn_context,
				      const sasl_utils_t *utils)
{
  client_context_t *text = (client_context_t *) conn_context;
    
  if (!text) return;
    
  if (text->out_buf) utils->free(text->out_buf);
  if (text->username) utils->free(text->username);
  if (text->password) utils->free(text->password);
  if (text->refresh) utils->free(text->refresh);
  if (text->access) utils->free(text->access);
  if (text->auth_uri) utils->free(text->auth_uri);
  if (text->token_uri) utils->free(text->token_uri);
  if (text->scope) utils->free(text->scope);
  if (text->curl.data) utils->free(text->curl.data);
    
  utils->free(text);
}

static sasl_client_plug_t oauth_client_plugins[] = 
  {
    {
      MECH_NAME,			/* mech_name */
      0,				/* max_ssf */
      SASL_SEC_NOANONYMOUS,		/* security_flags */
      SASL_FEAT_WANT_CLIENT_FIRST
      | SASL_FEAT_ALLOWS_PROXY,	/* features */
      NULL,				/* required_prompts */
      NULL,				/* glob_context */
      &oauth_client_mech_new,		/* mech_new */
      &oauth_client_mech_step,	/* mech_step */
      &oauth_client_mech_dispose,	/* mech_dispose */
      NULL,				/* mech_free */
      NULL,				/* idle */
      NULL,				/* spare */
      NULL				/* spare */
    }
  };

int oauth_client_plug_init(sasl_utils_t *utils,
			   int maxversion,
			   int *out_version,
			   sasl_client_plug_t **pluglist,
			   int *plugcount)
{
  if (maxversion < SASL_CLIENT_PLUG_VERSION) {
    SETERROR(utils, "OAUTH version mismatch");
    return SASL_BADVERS;
  }
    
  *out_version = SASL_CLIENT_PLUG_VERSION;
  *pluglist = oauth_client_plugins;
  *plugcount = 1;
    
  return SASL_OK;
}

/* */
