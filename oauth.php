<?php
  /* Oauth SASL plugin
   * Bill Mills
   * $Id:  $
   *
   * Copyright (c) 2010, Yahoo! Inc.  All rights reserved.
   *
   * Licensed under the Apache License, Version 2.0 (the "License"). You may
   * obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
   * See accompanying LICENSE file for terms.
   *
   */

define("AUTH_OK", 0);
define("AUTH_FAIL", 1);
/* */
// $argtype=$_GET["grant_type"];
$argtype=$_POST["grant_type"];
$argcid=$_POST["client_id"];
$argcs=$_POST["client_secret"];
$argscope=$_POST["scope"];
/* */
$arguser=$_POST["user"];
$argpw=$_POST["password"];
$argformat=$_POST["format"];
$argrefresh=$_POST["refresh_token"];
/* */

/* At a minimum we require teh type parameter
 */
if (NULL == $argtype) {
  return error_result(400, "Bad Request", "bad_request (grant_type)");
 }
/*Check to see if we support the requested format.
 */
if (("" !== $argformat) && ("json" !== $argformat)) {
  return error_result(501, "Not Implemented", "format_not_implemented -- " .  $argformat);
 }
/* */


switch ($argtype) {
 case "basic-credentials":
   /* Check to see if we have the correct set of required arguments.
    */
   if ((NULL == $argcid) || (NULL == $argcs) || 
       (NULL == $arguser) || (NULL == $argpw)) {  
     return error_result(400, "Bad Request", "bad_request (fields)");
   }
   /* Call our authentication stub for the user.
    */
   if (AUTH_OK == authenticate($arguser, $argpw)) {
     /* OK we have a good request, send back a token
      */
     
     $access_token=base64_encode(json_encode(array("userid" => $arguser, 
						   "scope" => $argscope, 
						   "expires" => time()+60)));
     $refresh_token=base64_encode(json_encode(array("userid" => $arguser, 
						    "scope" => $argscope, 
						    "seq" => rand())));
     header("Content-Type: application/json");
     header("Cache-Control: no-store");
     $out = json_encode(array("access_token" => $access_token, 
			    "expires_in" => 300, 
			    "refresh_token" => $refresh_token));
     header("Content-Length: " . strlen($out));
     echo $out;
   } else {
     /* All authentication failures look the same.  For a grace note
      we implement a random delay on login failure to prevent timing
      attacks, trivially easy for a basic implementation.
      */
     usleep(10000 + rand(0,10000000));
     error_result(401, "Not Authorized", "incorrect_client_credentials");
   }

   break;
 case "refresh-token":
   /* Take the refresh token and decide if we're willing to issue a new 
    access token.
   */
   /* Check to see if we have the correct set of required arguments.
    */
   if ((NULL == $argcid) || (NULL == $argcs) || 
       (NULL == $argrefresh)) {  
     return error_result(400, "Bad Request", "bad_request (null arg line=75)");
   }
   $rtokenarr = json_decode(base64_decode($argrefresh), TRUE);
   if (NULL == $rtokenarr) {
     return error_result(400, "Bad Request", "bad_request (decode)");
   }

   if ((NULL == $rtokenarr["userid"]) || (NULL == $rtokenarr["seq"])) {
     error_result(400, "Bad Request", "incorrect_client_credentials");
   } else {
     $access_token=base64_encode(json_encode(array("userid" => $rtokenarr["userid"],
                                                   "scope" => $rtokenarr["scope"],
						   "expires" => time()+300)));
     header("Content-Type: application/json");
     header("Cache-Control: no-store");
     $out = json_encode(array("access_token" => $access_token,
			      "expires_in" => 300));
     header("Content-Length: " . strlen($out));
     echo $out;
   }
   break;
   /* Anything else in unimplemented
    */
 default:
   return error_result(501, "Not Implemented", "type not implemented -- " . $argtype);
 }

/* Stub authentication function.
 */

function authenticate($id, $pw)
{
  $users = array("testuser" => "testpasswd", "foo" => "bar");
  if ($users[$id] == $pw) {
    return AUTH_OK;
  }
  return AUTH_FAIL;
}

/* Simple error formatting function.
 */
function error_result($code, $httpdiag, $jsondiag) {
  header("HTTP/1.1 " . $code . " " . $httpdiag, true, $code);
  header("Content-Type: application/json");
  header("Cache-Control: no-store");
  $out = json_encode(array("error", $jsondiag));
  header("Content-Length: " . strlen($out));
  echo $out;
  return;
}
?> 
