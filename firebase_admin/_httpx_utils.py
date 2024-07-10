# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Internal HTTP client module.

 This module provides utilities for creating resources to use the httpx library.
 """

import os
import time
import functools
import logging
import httpx
from google.auth import transport, exceptions
import google.auth
from google.auth.transport.requests import TimeoutGuard, _Response
from google.oauth2 import service_account

_LOGGER = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 120

class Request(transport.Request):
    """Requests request adapter.

    This class is used internally for making requests using various transports
    in a consistent way. If you use :class:`HttpxAuthorizedClient` you do not need
    to construct or use this class directly.

    This class can be useful if you want to manually refresh a
    :class:`~google.auth.credentials.Credentials` instance::

        import google.auth.transport.requests
        import httpx

        request = google.auth.transport.requests.Request()

        credentials.refresh(request)

    Args:
        session (httpx.Client): An instance :class:`httpx.Client` used
            to make HTTP requests. If not specified, a client will be created.

    .. automethod:: __call__
    """

    def __init__(self, session=None):
        if not session:
            session = httpx.Client(http2=True)

        self.session = session

    def __del__(self):
        try:
            if hasattr(self, "session") and self.session is not None:
                self.session.close()
        except TypeError:
            # NOTE: For certain Python binary built, the queue.Empty exception
            # might not be considered a normal Python exception causing
            # TypeError.
            pass

    def __call__(
            self,
            url,
            method="GET",
            body=None,
            headers=None,
            timeout=DEFAULT_TIMEOUT_SECONDS,
            **kwargs
    ):
        """Make an HTTP request using httpx.

        Args:
            url (str): The URI to be requested.
            method (str): The HTTP method to use for the request. Defaults
                to 'GET'.
            body (bytes): The payload or body in HTTP request.
            headers (Mapping[str, str]): Request headers.
            timeout (Optional[int]): The number of seconds to wait for a
                response from the server. If not specified or if None, a
                default timeout will be used.
            kwargs: Additional arguments passed through to the underlying
                client :meth:`~httpx.Client.request` method.

        Returns:
            google.auth.transport.Response: The HTTP response.

        Raises:
            google.auth.exceptions.TransportError: If any exception occurred.
        """
        try:
            _LOGGER.debug("Making request: %s %s", method, url)
            response = self.session.request(
                method, url, data=body, headers=headers, timeout=timeout, **kwargs
            )
            return _Response(response)
        except httpx.RequestError as caught_exc:
            new_exc = exceptions.TransportError(caught_exc)
            raise new_exc from caught_exc


class CustomRetryTransport(httpx.BaseTransport):
    """ Custom transport for httpx that retries requests with backoff and jitter.

    Args:
        retries: The maximum number of retries to attempt.
        backoff_factor: The backoff factor to apply between retries.
        status_forcelist: A list of status codes that should trigger a retry.

    Returns:
        httpx.BaseTransport: A transport that retries requests with backoff and jitter.
    """
    def __init__(self, retries=3, backoff_factor=0.5, status_forcelist=None):
        self.retries = retries
        self.backoff_factor = backoff_factor
        self.status_forcelist = status_forcelist or [500, 503]

    def handle_request(self, request):
        request_handler = httpx.HTTPTransport(http2=True)
        attempt = 0
        retry = self.retries
        while attempt < retry:
            try:
                response = request_handler.handle_request(request)
                if response.status_code not in self.status_forcelist:
                    return response
            except (httpx.ConnectError, httpx.ReadTimeout):
                pass

            attempt += 1
            if attempt < self.retries:
                time.sleep(self.backoff_factor * (2 ** (attempt - 1)))
        # Send one last request after exhausting all retries
        response = request_handler.handle_request(request)
        return response

class _MutualTlsClient(httpx.Client):
    """A Client that enables mutual TLS.

    Args:
        cert (bytes): client certificate in PEM format
        key (bytes): client private key in PEM format

    Raises:
        OpenSSL.crypto.Error: if client cert or key is invalid
    """
    # pylint: disable=missing-param-doc
    def __init__(self, *args, cert, key, **kwargs):
        import certifi
        import ssl
        from OpenSSL import crypto # pylint: disable=import-error

        # Load client certificate and private key
        pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

        # Create an SSL context
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=certifi.where())
        ssl_context.load_cert_chain(certfile=cert, keyfile=key)

        # Use the loaded certificate and key in the SSL context
        ssl_context.use_certificate(x509) # pylint: disable=no-member
        ssl_context.use_privatekey(pkey) # pylint: disable=no-member

        # Ensure the client uses this SSL context
        kwargs['verify'] = ssl_context

        super(_MutualTlsClient, self).__init__(*args, **kwargs)

class HttpxAuthorizedClient(httpx.Client):
    """Authorized HTTP client used to make HTTP calls.

    This class is a altered version of the `google.auth.transport.requests.AuthorizedSession`
    class and therefore contains some identical functions. If you would like
    to know more about the original class and/or method implementations, please visit:

        https://github.com/googleapis/google-auth-library-python/blob/main/google/auth/transport/requests.py#L295

    This class is used to perform requests to API endpoints that require
    authorization::

        from firebase_admin.httpx_client import HttpxAuthorizedClient

        auth_client = HttpxAuthorizedClient(credentials)
        response = auth_client.request(
            'GET', 'https://www.googleapis.com/storage/v1/b')

    The underlying :meth:`request` implementation handles adding the
    credentials' headers to the request and refreshing credentials as needed.
    """
    # pylint: disable=line-too-long
    def __init__(
            self,
            credentials,
            request_handler,
            refresh_status_codes=transport.DEFAULT_REFRESH_STATUS_CODES,
            max_refresh_attempts=transport.DEFAULT_MAX_REFRESH_ATTEMPTS,
            refresh_timeout=None,
            auth_request=None,
            default_host=None,
    ):
        super(HttpxAuthorizedClient, self).__init__()
        self.credentials = credentials
        self._refresh_status_codes = refresh_status_codes
        self._max_refresh_attempts = max_refresh_attempts
        self._refresh_timeout = refresh_timeout
        self._is_mtls = False
        self._default_host = default_host

        if auth_request is None:
            self._auth_request_session = httpx.Client(http2=True, transport=request_handler)
            auth_request = Request(self._auth_request_session)
        else:
            self._auth_request_session = None

        self._auth_request = auth_request

        if isinstance(self.credentials, service_account.Credentials):
            self.credentials._create_self_signed_jwt( # pylint: disable=protected-access
                f"https://{self._default_host}/" if self._default_host else None
            )

    def request(self, method, url, data=None, headers=None, max_allowed_time=None, timeout=DEFAULT_TIMEOUT_SECONDS, **kwargs):
        """Implementation of Requests' request.

        Args:
            timeout (Optional[Union[float, Tuple[float, float]]]):
                The amount of time in seconds to wait for the server response
                with each individual request. Can also be passed as a tuple
                ``(connect_timeout, read_timeout)``. See :meth:`requests.Session.request`
                documentation for details.
            max_allowed_time (Optional[float]):
                If the method runs longer than this, a ``Timeout`` exception is
                automatically raised. Unlike the ``timeout`` parameter, this
                value applies to the total method execution time, even if
                multiple requests are made under the hood.

                Mind that it is not guaranteed that the timeout error is raised
                at ``max_allowed_time``. It might take longer, for example, if
                an underlying request takes a lot of time, but the request
                itself does not timeout, e.g. if a large file is being
                transmitted. The timout error will be raised after such
                request completes.
        """
        # pylint: disable=missing-param-doc,missing-return-doc,missing-return-type-doc,arguments-differ
        _credential_refresh_attempt = kwargs.pop("_credential_refresh_attempt", 0)
        request_headers = headers.copy() if not None else {}

        auth_request = (self._auth_request
                        if timeout is None
                        else functools.partial(self._auth_request, timeout=timeout))
        remaining_time = max_allowed_time

        with TimeoutGuard(remaining_time) as guard:
            self.credentials.before_request(auth_request, method, url, request_headers)
        remaining_time = guard.remaining_timeout

        with TimeoutGuard(remaining_time) as guard:
            response = super(HttpxAuthorizedClient, self).request(
                method,
                url,
                data=data,
                headers=request_headers,
                timeout=timeout,
                **kwargs
            )
        remaining_time = guard.remaining_timeout

        # If the response indicated that the credentials needed to be
        # refreshed, then refresh the credentials and re-attempt the
        # request.
        # A stored token may expire between the time it is retrieved and
        # the time the request is made, so we may need to try twice.
        if (
                response.status_code in self._refresh_status_codes
                and _credential_refresh_attempt < self._max_refresh_attempts
        ):

            _LOGGER.info(
                "Refreshing credentials due to a %s response. Attempt %s/%s.",
                response.status_code,
                _credential_refresh_attempt + 1,
                self._max_refresh_attempts,
            )

            auth_request = (
                self._auth_request
                if timeout is None
                else functools.partial(self._auth_request, timeout=timeout)
            )
            with TimeoutGuard(remaining_time) as guard:
                self.credentials.refresh(auth_request)
            remaining_time = guard.remaining_timeout

            # Recurse. Pass in the original headers, not our modified set, but
            # do pass the adjusted max allowed time (i.e. the remaining total time).
            return self.request(
                method,
                url,
                data=data,
                headers=headers,
                max_allowed_time=remaining_time,
                timeout=timeout,
                _credential_refresh_attempt=_credential_refresh_attempt + 1,
                **kwargs
            )

        return response

    def configure_mtls_channel(self, client_cert_callback=None):
        """Configure the client certificate and key for SSL connection.
        This function is identical to the one found in the
        `google.auth.transport.requests.AuthorizedSession` class.
        More information: https://github.com/googleapis/google-auth-library-python/blob/main/google/auth/transport/requests.py#L425 # pylint: disable=line-too-long
         
        Args:
            client_cert_callback (Optional[Callable[[], (bytes, bytes)]]):
                The optional callback returns the client certificate and private
                key bytes both in PEM format.
                If the callback is None, application default SSL credentials
                will be used.

        Raises:
            google.auth.exceptions.MutualTLSChannelError: If mutual TLS channel
                creation failed for any reason.
        """
        use_client_cert = os.getenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
        if use_client_cert != "true":
            self._is_mtls = False
            return
        try:
            import OpenSSL
        except ImportError as caught_exc:
            new_exc = exceptions.MutualTLSChannelError(caught_exc)
            raise new_exc from caught_exc
        try:
            (
                self._is_mtls,
                cert,
                key,
            ) = google.auth.transport._mtls_helper.get_client_cert_and_key( # pylint: disable=protected-access
                client_cert_callback
            )

            if self._is_mtls:
                mtls_adapter = _MutualTlsClient(cert=cert, key=key)
                self._mounts("https://", mtls_adapter)
        except (
                exceptions.ClientCertError,
                ImportError,
                OpenSSL.crypto.Error,
        ) as caught_exc:
            new_exc = exceptions.MutualTLSChannelError(caught_exc)
            raise new_exc from caught_exc

    @property
    def is_mtls(self):
        return self._is_mtls

    def close(self):
        if self._auth_request_session is not None:
            self._auth_request_session.close()
        super(HttpxAuthorizedClient, self).close()
