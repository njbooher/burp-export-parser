from burpstuff import *
from xml.etree import ElementTree
import os

def process_file(input_file, filenames, post_params, query_params, cookies, headers, request_paths):

    try:

        for event, elem in ElementTree.iterparse(input_file):

            if elem.tag != "item":
                continue

            item = elem

            if item.find('status').text is None:
                continue

            request_path = get_request_path(item.find('path').text)
            request_paths.add(request_path)

            request_filename = maybe_filename(request_path)
            if request_filename != "":
                filenames.add(request_filename)

            request_decoded = base64.b64decode(item.find('request').text)

            request_headers = parse_http_headers(request_decoded, is_decoded=True)

            headers.update(request_headers.keys())

            try:
                if item.find('method').text == 'POST':
                    if len(request_headers['content-type']) < 1:
                        continue
                    for param in parse_post_body(request_headers['content-type'][0], get_http_request_body(request_decoded, is_decoded=True)):
                        maybe_add_param(param['paramName'], post_params)
            except Exception:
                print("error loading params for {}".format(request_path))

            if '?' in item.find('path').text:
                for param in parse_url_encoded_params(item.find('path').text.split('?')[1], 'GET'):
                    maybe_add_param(param['paramName'], query_params)

            if 'cookie' in request_headers:
                for param in parse_cookies(request_headers['cookie'][0]):
                    maybe_add_param(param['paramName'], cookies)

            response_headers = parse_http_headers(item.find('response').text)
            headers.update(response_headers.keys())

    except ElementTree.ParseError as e:
        print("error while parsing %s, might be incomplete", input_file)

def main(output_dir, input_files):

    filenames = set()
    post_params = set()
    query_params = set()
    cookies = set()
    headers = set()
    request_paths = set()

    for input_file in input_files:
        process_file(input_file, filenames, post_params, query_params, cookies, headers, request_paths)

    with open(os.path.join(output_dir, 'BurpHistoryRequestPaths.pay'),'w') as f:
        f.write('\n'.join(sorted(request_paths)))

    with open(os.path.join(output_dir, 'BurpHistoryRequestBaseNames.pay'),'w') as f:
        f.write('\n'.join(sorted(set([os.path.basename(request_path) for request_path in request_paths]))))

    with open(os.path.join(output_dir, 'BurpHistoryFileNames.pay'),'w') as f:
        f.write('\n'.join(sorted(filenames)))

    filenames_no_ext = set([filename.split('.')[0] for filename in filenames])

    with open(os.path.join(output_dir, 'BurpHistoryFileNamesNoExtension.pay'),'w') as f:
        f.write('\n'.join(sorted(filenames_no_ext)))

    with open(os.path.join(output_dir, 'BurpHistoryPostParams.pay'),'w') as f:
        f.write('\n'.join(sorted(post_params)))

    with open(os.path.join(output_dir, 'BurpHistoryQueryParams.pay'),'w') as f:
        f.write('\n'.join(sorted(query_params)))

    with open(os.path.join(output_dir, 'BurpHistoryRequestParams.pay'),'w') as f:
        f.write('\n'.join(sorted(post_params | query_params)))

    with open(os.path.join(output_dir, 'BurpHistoryCookies.pay'),'w') as f:
        f.write('\n'.join(sorted(cookies)))

    with open(os.path.join(output_dir, 'BurpHistoryHeaders.pay'),'w') as f:
        f.write('\n'.join(sorted(headers)))

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Turns exported burp history into wordlists')
    parser.add_argument('outputdir', metavar='OUTPUTDIR', type=str, help='Where to save output files')
    parser.add_argument('inputfiles', metavar='FILE', type=str, nargs='+',
                        help='burp xml file to import')
    args = parser.parse_args()
    main(args.outputdir, args.inputfiles)