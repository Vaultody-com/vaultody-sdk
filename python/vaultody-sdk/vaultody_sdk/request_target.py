"""The request target (path and query) of a call, built so it is exactly what goes on the request line
and what is signed (test-vectors/path-encoding-v1.json)."""

import re
from urllib.parse import quote

from .errors import ParameterError

_PLACEHOLDER = re.compile(r"\{([A-Za-z0-9_]+)\}")


def percent_encode(text):
    """Every UTF-8 byte outside the RFC 3986 unreserved set as %XX, uppercase hex, "/" included.

    :raises UnicodeEncodeError: for text with no UTF-8 form (a lone surrogate)
    """
    # quote() with no safe characters keeps exactly A-Z a-z 0-9 - . _ ~
    return quote(text.encode("utf-8"), safe="")


def _well_formed(text):
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _path_value(name, params):
    if name not in params or params[name] is None:
        raise ParameterError("missing_path_param", "{} is required".format(name))
    value = params[name]
    if isinstance(value, str):
        text = value
    elif isinstance(value, int) and not isinstance(value, bool):
        text = str(value)
    else:
        raise ParameterError("invalid_path_param", "{} must be a string or an integer".format(name))
    # An empty segment, or a dot segment a URL would remove, changes the path that is signed.
    if text in ("", ".", "..") or not _well_formed(text):
        raise ParameterError("invalid_path_param", '{} must be a non-empty value other than "." and ".."'.format(name))
    return percent_encode(text)


def _query_value(name, value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        if not _well_formed(value):
            raise ParameterError("invalid_query_param", "{} is not valid Unicode".format(name))
        return percent_encode(value)
    raise ParameterError("invalid_query_param", "{} must be a string, an integer or a boolean".format(name))


def build_request_target(template, path_params, query=()):
    """The path and query of a call.

    :param template: the operation path, such as ``"/vaults/{vaultId}/utxos"``
    :param path_params: name → string or integer
    :param query: ``(name, value)`` pairs in the order to send; a None value leaves the pair out
    :returns: such as ``"/vaults/abc/utxos?limit=10"``
    :raises ParameterError: ``missing_path_param``, ``invalid_path_param`` or ``invalid_query_param``
    """
    params = path_params or {}
    path = _PLACEHOLDER.sub(lambda match: _path_value(match.group(1), params), template)
    pairs = ["{}={}".format(percent_encode(name), _query_value(name, value)) for name, value in query if value is not None]
    return path + ("?" + "&".join(pairs) if pairs else "")


__all__ = ["build_request_target", "percent_encode"]
