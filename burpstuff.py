import base64
import http.cookies
from collections import defaultdict
import urllib.parse
import email.parser
import json
import re

import os

junk_param_pattern = re.compile(r'\'|"|-|<|>|\(|\)|/')
junk_controller_pattern = re.compile(r'\'|"|-|<|>|\(|\)|/|\.|&|\$|=|%')
junk_method_pattern = re.compile(r'\'|"|-|<|>|\(|\)|/|\.|&|\$|=|%')

def str_is_int(s):
    try:
        int(s)
        return True
    except ValueError:
        return False

def param_name_prefix(param_name):
    if '_' in param_name and not '[' in param_name:
        return param_name.split('_', 1)[0]
    return None

def simplify_param_name(param_name):
    if '[' in param_name:
        return param_name.split('[')[0] + '[]'
    return param_name

def param_is_probably_junk(param_name):
    if junk_param_pattern.findall(param_name):
        return True
    return False

def maybe_add_param(param_name, destination):
    if not param_is_probably_junk(param_name):
        destination.add(simplify_param_name(param_name))

def maybe_filename(request_path):
    filename = os.path.basename(request_path)
    if '.' in filename:
        return filename
    return ""

def parse_http_headers(r, is_decoded=False):

    if is_decoded == False:
        decoded = base64.b64decode(r)
    else:
        decoded = r

    try:
        header_lines = decoded[:decoded.index(b'\r\n\r\n')].decode('UTF-8').split("\r\n")
    except:
        print(decoded)
        raise

    # remove GET line
    header_lines.pop(0)
    headers = defaultdict(list)
    for line in header_lines:
        header_name, header_value = line.split(": ", 1)
        headers[header_name.lower()].append(header_value)
    return headers

def get_http_request_body(r, is_decoded=False):

    if is_decoded == False:
        decoded = base64.b64decode(r)
    else:
        decoded = r

    try:
        post_body = decoded[decoded.index(b'\r\n\r\n'):]
    except:
        print(decoded)
        raise

    return post_body

def parse_post_body(content_type, body_bytes):

    if 'multipart/form-data' in content_type:
        return parse_post_form_multipart(content_type, body_bytes)
    elif 'application/x-www-form-urlencoded' in content_type:
        return parse_url_encoded_params(body_bytes, 'POST')
    elif 'application/json' in content_type:
        return parse_post_form_json(body_bytes)
    else:
        return []

def parse_url_encoded_params(body_bytes, location):
    params = []
    prefixes = {}
    if type(body_bytes) is bytes:
        try:
            body_bytes = body_bytes.decode('UTF-8')
        except UnicodeDecodeError:
            print("bailed early for bad unicode param")
            return params
    for param_name, param_value in urllib.parse.parse_qsl(body_bytes, keep_blank_values=True):
        param = {}
        param['paramName'] = param_name.strip()
        prefix = param_name_prefix(param['paramName'])
        if prefix is not None:
            if prefix in prefixes:
                param['paramNamePrefix'] = prefix
            prefixes[prefix] = 1
        param['paramType'] = 'urlencoded'
        param['paramLocation'] = location
        param['paramValue'] = urllib.parse.unquote_plus(param_value).strip()
        param['paramNameValueCombined'] = param['paramName'] + '=' + param['paramValue']
        params.append(param)
    return params

def parse_post_form_multipart(content_type, body_bytes):

    params = []
    prefixes = {}
    msg = email.parser.BytesParser().parsebytes(b"Content-Type: " + content_type.encode('UTF-8') + b"\r\n\r\n" + body_bytes)

    for part in msg.walk():
        param_name = part.get_param('name', header='content-disposition')

        if param_name is not None:
            param = {}
            param['paramName'] = param_name.strip()
            prefix = param_name_prefix(param['paramName'])
            if prefix is not None:
                if prefix in prefixes:
                    param['paramNamePrefix'] = prefix
                prefixes[prefix] = 1
            param['paramType'] = 'form-data'
            param['paramLocation'] = 'POST'
            if part.get_filename() is not None:
                param['paramValue'] = '<binary file>'
            else:
                param['paramValue'] = urllib.parse.unquote_plus(part.get_payload(decode=True).decode('UTF-8')).strip()
            param['paramNameValueCombined'] = param['paramName'] + '=' + param['paramValue']
            params.append(param)

    return params

def parse_post_form_json(body_bytes):

    body_decoded = json.loads(body_bytes)
    params = []
    prefixes = {}

    if type(body_decoded) is dict:
        for param_name, param_value in body_decoded.items():
            param = {}
            param['paramName'] = param_name.strip()
            prefix = param_name_prefix(param['paramName'])
            if prefix is not None:
                if prefix in prefixes:
                    param['paramNamePrefix'] = prefix
                prefixes[prefix] = 1
            param['paramType'] = 'json'
            param['paramLocation'] = 'POST'
            param['paramValue'] = urllib.parse.unquote_plus(str(param_value)).strip()
            param['paramNameValueCombined'] = param['paramName'] + '=' + param['paramValue']
            params.append(param)

    return params

def parse_json_response_body(body_bytes):

    params = []

    try:
        body_decoded = json.loads(body_bytes)
    except json.decoder.JSONDecodeError:
        return params

    params.extend(parse_json_response_param("", body_decoded))

    return params

def parse_json_response_param(param_key, param_value):

    params = []

    param_key = param_key.strip()

    if param_key != "" and not str_is_int(param_key):
            param = {}
            param['paramName'] = param_key
            param['paramType'] = type(param_value)
            temp_val = str(param_value).strip()
            if len(temp_val) > 30000:
                param['paramValue'] = '<long truncated>'
            else:
                param['paramValue'] = temp_val
            param['paramNameValueCombined'] = param['paramName'] + '=' + param['paramValue']
            params.append(param)

    if type(param_value) is dict:
        for sub_param_name, sub_param_value in param_value.items():
            params.extend(parse_json_response_param(sub_param_name, sub_param_value))
    elif type(param_value) is list:
        for sub_param_value in param_value:
            params.extend(parse_json_response_param("", sub_param_value))

    return params


def parse_cookies(cookie_header):
    params = []
    prefixes = {}
    try:
        for param_name, param_value in http.cookies.SimpleCookie(cookie_header).items():
            param = {}
            param['paramName'] = param_name.strip()
            prefix = param_name_prefix(param['paramName'])
            if prefix is not None:
                if prefix in prefixes:
                    param['paramNamePrefix'] = prefix
                prefixes[prefix] = 1
            param['paramType'] = 'urlencoded'
            param['paramLocation'] = 'COOKIE'
            param['paramValue'] = urllib.parse.unquote_plus(param_value.value).strip()
            param['paramNameValueCombined'] = param['paramName'] + '=' + param['paramValue']
            params.append(param)
    except http.cookies.CookieError:
        pass
    return params

def get_request_cookie_names(cookie_header):
    try:
        return list(http.cookies.SimpleCookie(cookie_header).keys())
    except http.cookies.CookieError:
        return []

def get_query_params(query_string):
    param_names = set()
    for param_name in urllib.parse.parse_qs(query_string, keep_blank_values=True).keys():
        if '[' in param_name:
            param_names.add(param_name.split('[')[0] + '[]')
        else:
            param_names.add(param_name)
    return list(param_names)

def get_query_param_names(query_string):
    param_names = set()
    for param_name in urllib.parse.parse_qs(query_string).keys():
        if '[' in param_name:
            param_names.add(param_name.split('[')[0] + '[]')
        else:
            param_names.add(param_name)
    return list(param_names)

def get_response_cookie_names(cookie_header):
    cookie_names = []
    for cookie in cookie_header:
        cookie_names.append(cookie.split('=')[0])
    return cookie_names

def get_vary(vary_header):
    vary = set()
    for item in vary_header.split(','):
        vary.add(item.strip().lower())
    return list(vary)

def get_content_type(content_type):
    return content_type.split(';')[0]

def get_request_path(request_path):
    return '/' +  request_path.lstrip('/').split('?')[0]