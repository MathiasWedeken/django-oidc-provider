from hashlib import sha224

from django.http import HttpResponse, HttpRequest
from django.utils.cache import patch_vary_headers
from django.urls import reverse
from oidc_provider import settings


def redirect(uri: str) -> HttpResponse:
    """
    Custom Response object for redirecting to a Non-HTTP url scheme.
    """
    response = HttpResponse('', status=302)
    response['Location'] = uri
    return response


def get_issuer_url(issuer_url: str = None, request: HttpRequest = None) -> str:
    """
    Construct the issuer url.

    Orders to decide site url:
        1. valid `issuer_url` parameter
        2. valid `ISSUER_URL` in settings
        3. construct from `request` object
    """
    issuer_url = issuer_url or settings.get('ISSUER_URL')
    if issuer_url:
        return issuer_url
    elif request:
        return '{}://{}'.format(request.scheme, request.get_host())
    else:
        raise Exception('Either pass `issuer_url`, '
                        'or set `ISSUER_URL` in settings, '
                        'or pass `request` object.')


def get_issuer(issuer_url: str = None, request: HttpRequest = None) -> str:
    """
    Construct the issuer full url. Basically is the site url with some path
    appended.
    """
    issuer_url = get_issuer_url(issuer_url=issuer_url, request=request)
    path = reverse('oidc_provider:provider-info') \
        .split('/.well-known/openid-configuration')[0]
    issuer = issuer_url + path

    return str(issuer)


def default_userinfo(claims, user):
    """
    Default function for setting OIDC_USERINFO.
    `claims` is a dict that contains all the OIDC standard claims.
    """
    return claims


def default_sub_generator(user) -> str:
    """
    Default function for setting OIDC_IDTOKEN_SUB_GENERATOR.
    """
    return str(user.id)


def default_after_userlogin_hook(request, user, client):
    """
    Default function for setting OIDC_AFTER_USERLOGIN_HOOK.
    """
    return None


def default_after_end_session_hook(
        request, id_token=None, post_logout_redirect_uri=None,
        state=None, client=None, next_page=None):
    """
    Default function for setting OIDC_AFTER_END_SESSION_HOOK.

    :param request: Django request object
    :type request: django.http.HttpRequest

    :param id_token: token passed by `id_token_hint` url query param.
                     Do NOT trust this param or validate token
    :type id_token: str

    :param post_logout_redirect_uri: redirect url from url query param.
                                     Do NOT trust this param
    :type post_logout_redirect_uri: str

    :param state: state param from url query params
    :type state: str

    :param client: If id_token has `aud` param and associated Client exists,
        this is an instance of it - do NOT trust this param
    :type client: oidc_provider.models.Client

    :param next_page: calculated next_page redirection target
    :type next_page: str
    :return:
    """
    return None


def default_idtoken_processing_hook(
        id_token, user, token, request, **kwargs):
    """
    Hook to perform some additional actions to `id_token` dictionary just before serialization.

    :param id_token: dictionary contains values that going to be serialized into `id_token`
    :type id_token: dict

    :param user: user for whom id_token is generated
    :type user: User

    :param token: the Token object created for the authentication request
    :type token: oidc_provider.models.Token

    :param request: the request initiating this ID token processing
    :type request: django.http.HttpRequest

    :return: custom modified dictionary of values for `id_token`
    :rtype: dict
    """
    return id_token


def default_introspection_processing_hook(introspection_response, client, id_token):
    """
    Hook to customise the returned data from the token introspection endpoint
    :param introspection_response:
    :param client:
    :param id_token:
    :return:
    """
    return introspection_response


def get_browser_state_or_default(request: HttpRequest) -> str:
    """
    Determine value to use as session state.
    """
    key = (request.session.session_key or
           settings.get('OIDC_UNAUTHENTICATED_SESSION_MANAGEMENT_KEY'))
    return sha224(key.encode('utf-8')).hexdigest()


def run_processing_hook(subject, hook_settings_name, **kwargs):
    processing_hooks = settings.get(hook_settings_name)
    if not isinstance(processing_hooks, (list, tuple)):
        processing_hooks = [processing_hooks]

    for hook_string in processing_hooks:
        hook = settings.import_from_str(hook_string)
        subject = hook(subject, **kwargs)

    return subject


def cors_allow_any(request: HttpRequest, response: HttpResponse) -> HttpResponse:
    """
    Add headers to permit CORS requests from any origin, with or without credentials,
    with any headers.
    """
    origin = request.META.get('HTTP_ORIGIN')
    if not origin:
        return response

    # From the CORS spec: The string "*" cannot be used for a resource that supports credentials.
    response['Access-Control-Allow-Origin'] = origin
    patch_vary_headers(response, ['Origin'])
    response['Access-Control-Allow-Credentials'] = 'true'

    if request.method == 'OPTIONS':
        if 'HTTP_ACCESS_CONTROL_REQUEST_HEADERS' in request.META:
            response['Access-Control-Allow-Headers'] \
                = request.META['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']
        response['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'

    return response
