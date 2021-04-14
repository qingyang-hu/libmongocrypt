/*
 * Copyright 2020-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "test_kms_online_util.h"

#include "test_kms.h"

#include <kms_message/kms_response_parser.h>

#include <kms_message/kms_kmip_request.h>



/* Create a TLS stream to a host. */
mongoc_stream_t *
connect_with_tls (const char *host, const char* port)
{
   mongoc_stream_t *stream;
   mongoc_socket_t *sock = NULL;
   struct addrinfo hints;
   struct addrinfo *result, *rp;
   int64_t expire_at;
   int s;
   const int connecttimeoutms = 5000;

   memset (&hints, 0, sizeof hints);
   hints.ai_family = AF_INET;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_flags = 0;
   hints.ai_protocol = 0;

   s = getaddrinfo (host, port, &hints, &result);
   TEST_ASSERT (s == 0);

   for (rp = result; rp; rp = rp->ai_next) {
      if (!(sock = mongoc_socket_new (
               rp->ai_family, rp->ai_socktype, rp->ai_protocol))) {
         continue;
      }

      expire_at = bson_get_monotonic_time () + (connecttimeoutms * 1000L);
      if (0 !=
          mongoc_socket_connect (
             sock, rp->ai_addr, (mongoc_socklen_t) rp->ai_addrlen, expire_at)) {
         mongoc_socket_destroy (sock);
         sock = NULL;
         continue;
      }

      break;
   }

   if (!sock) {
      TEST_ERROR ("Failed to connect: %s", host);
   }

   freeaddrinfo (result);

   stream = mongoc_stream_socket_new (sock);
   TEST_ASSERT (stream);

   mongoc_ssl_opt_t opts;
   memcpy(&opts, mongoc_ssl_opt_get_default(), sizeof(opts) );

   // Disable TLS validation when testing against KMIP since it wil be using non-public certs
   if( strcmp(port, "5696")==0) {
      // opts.ca_file = "/home/mark/projects/kmip/test_data/ca.pem";
      opts.weak_cert_validation = true;
      opts.allow_invalid_hostname = true;
   }

   return mongoc_stream_tls_new_with_hostname (
      stream, host, (mongoc_ssl_opt_t *) &opts, 1);
}

/* Helper to send an HTTP request and receive a response. */
kms_response_t *
send_kms_request (kms_request_t *req, const char *host)
{
   mongoc_stream_t *tls_stream;
   char *req_str;
   int32_t socket_timeout_ms = 5000;
   ssize_t write_ret;
   kms_response_parser_t *response_parser;
   int bytes_to_read;
   int bytes_read;
   uint8_t buf[1024];
   kms_response_t *response;

   tls_stream = connect_with_tls (host, "443");
   req_str = kms_request_to_string (req);

   write_ret = mongoc_stream_write (
      tls_stream, req_str, strlen (req_str), socket_timeout_ms);
   TEST_ASSERT (write_ret == (ssize_t) strlen (req_str));

   response_parser = kms_response_parser_new ();
   while ((bytes_to_read =
              kms_response_parser_wants_bytes (response_parser, 1024)) > 0) {
      bytes_read = (int) mongoc_stream_read (
         tls_stream, buf, bytes_to_read, 0, socket_timeout_ms);
      if (!kms_response_parser_feed (response_parser, buf, bytes_read)) {
         TEST_ERROR ("read failed: %s",
                     kms_response_parser_error (response_parser));
      }
   }

   response = kms_response_parser_get_response (response_parser);
   TEST_ASSERT (response);

   kms_request_free_string (req_str);
   kms_response_parser_destroy (response_parser);
   mongoc_stream_destroy (tls_stream);
   return response;

}

/* Helper to send an HTTP request and receive a response. */
kms_request_str_t*
send_kms_binary_request (kms_request_t *req, const char *host)
{
   mongoc_stream_t *tls_stream;
   int32_t socket_timeout_ms = 5000;
   ssize_t write_ret;
   kms_kmip_response_parser_t *response_parser;
   int bytes_to_read;
   int bytes_read;
   uint8_t buf[1024];
   char* req_buffer;
   size_t req_length;
   uint8_t* resp_buffer;
   size_t resp_length;
   kms_request_str_t* response;

   tls_stream = connect_with_tls (host, "5696");
   kms_request_to_binary (req, &req_buffer, &req_length);

   write_ret = mongoc_stream_write (
      tls_stream, req_buffer, req_length, socket_timeout_ms);
   // TEST_ASSERT (write_ret == (ssize_t)req_length);
   TEST_ASSERT (write_ret >= 0);

   response_parser = kms_kmip_response_parser_new ();
   while ((bytes_to_read =
              kms_kmip_response_parser_wants_bytes (response_parser, 1024)) > 0) {
      bytes_read = (int) mongoc_stream_read (
         tls_stream, buf, bytes_to_read, 0, socket_timeout_ms);
      if (!kms_kmip_response_parser_feed (response_parser, buf, bytes_read)) {
         TEST_ERROR ("read failed: %s",
                     kms_kmip_response_parser_error (response_parser));
      }
   }

   kms_kmip_response_get_response (response_parser, &resp_buffer, &resp_length);
   response = kms_request_str_new_from_chars((char*)resp_buffer, resp_length);

   kms_kmip_response_parser_destroy (response_parser);
   mongoc_stream_destroy (tls_stream);
   return response;
}