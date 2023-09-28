#!/usr/bin/env python3

# Kibana documentation:
# https://www.elastic.co/guide/en/kibana/current/saved-objects-api-export.html
# https://www.elastic.co/guide/en/kibana/current/saved-objects-api-import.html

import sys
import argparse
import boto3
import requests
import json
import glob
import re
from collections import OrderedDict
from pprint import pprint
from requests_aws4auth import AWS4Auth

# Error message from Kibana listing all possible saved objects types:
# \"type\" must be one of [ alert, config, canvas-workpad, canvas-element, dashboard, index-pattern, map, query, search, url, visualization ]
saved_objects_types = (
    'config',
    'dashboard',
    'index-pattern',
    'query',
    'search',
    'url',
    'visualization'
)

def aws_auth():
    aws_service = 'es'

    aws_session = boto3.Session()
    aws_credentials = aws_session.get_credentials()

    if aws_session.region_name:
        aws_region = aws_session.region_name
    else:
        aws_region = 'us-west-2'

    auth = AWS4Auth(aws_credentials.access_key, aws_credentials.secret_key, aws_region, aws_service, session_token=aws_credentials.token)

    return auth

def get_all_tenants(kibana_url, auth, verify_ssl=True):
    """Return list of all tenant ids in kibana, default tenant id goes as an empty string"""
    url = kibana_url + '/_plugins/_security/api/tenants/'
    r = requests.get(
        url,
        auth=auth,
        headers={'Content-Type': 'application/json', 'osd-xsrf': 'true'},
        verify=verify_ssl,
    )
    r.raise_for_status()  # Raises stored HTTPError, if one occurred.

    tenants_json = json.loads(r.text)
    tenants_list = []
    for i in tenants_json.keys():
        if i == 'global_tenant':
            tenants_list.append('')
        else:
            tenants_list.append(i)
    return tenants_list


def backup(kibana_url, tenant_id, auth, verify_ssl=True):
    """Return string with newline-delimitered json containing Kibana saved objects"""
    url = kibana_url + '/_dashboards/api/saved_objects/_export'
    r = requests.post(
        url,
        auth=auth,
        headers={'Content-Type': 'application/json', 'osd-xsrf': 'true', 'securitytenant': tenant_id},
        data='{"type":["index-pattern","config","url","search","visualization","dashboard","query"],"includeReferencesDeep":true}',
        verify=verify_ssl,
    )
    r.raise_for_status()  # Raises stored HTTPError, if one occurred.

    return r.content

def restore(kibana_url, tenant_id, auth, text, verify_ssl=True):
    """Restore given newline-delimitered json containing saved objects to Kibana"""

    url = kibana_url + '/_dashboards/api/saved_objects/_import?overwrite=true'
    print('POST ' + url)
    r = requests.post(
        url,
        auth=auth,
        headers={'osd-xsrf': 'true', 'securitytenant': tenant_id},
        files={'file': ('backup.ndjson', text)},
        verify=verify_ssl,
    )

    print(r.status_code, r.reason, '\n', r.text)
    r.raise_for_status()  # Raises stored HTTPError, if one occurred.


if __name__ == '__main__':
    args_parser = argparse.ArgumentParser(
        description='Backup and restore Kibana saved objects. Writes backup to stdout or file and reads from stdin or file.'
    )
    args_parser.add_argument('action', choices=['backup', 'restore'])
    args_parser.add_argument(
        '--kibana-url',
        default='http://127.0.0.1:5601',
        help='URL to access Kibana API, default is http://127.0.0.1:5601',
    )
    args_parser.add_argument('--aws-auth', action='store_true', default=False, help='Use AWS Authentication to connect to the Elasticache/OpenSearch server instead of user/password.')
    args_parser.add_argument('--user', default='', help='Kibana user')
    args_parser.add_argument('--password', default='', help='Kibana password')
    args_parser.add_argument(
        '--no-verify-ssl',
        action='store_true',
        default=False,
        help='UNSAFE: Do not verify SSL/TLS certificates',
    )
    args_parser.add_argument(
        '--backup-file',
        default='',
        help='File to save or restore backup, stdout or stdin is used if not defined',
    )
    args_parser.add_argument(
        '--tenant-id',
        default='',
        help='Kibana tenant id. If not set then the default tenant is used.',
    )
    args_parser.add_argument(
        '--all-tenants',
        action='store_true',
        help='Backup all tenants to separate files.',
    )
    args_parser.add_argument(
        '--backup-file-prefix',
        default='',
        help='Backup file prefix for all tenants option: <prefix><tenant id>.ndjson',
    )
    args = args_parser.parse_args()

    if args.aws_auth:
        auth = aws_auth()
    else:
        auth = (args.user, args.password)

    s = requests.Session()

    if args.all_tenants:
        if len(args.backup_file_prefix) == 0:
            raise Exception(
                'ERROR: all tenants option requires backup file prefix to be specified'
            )
        elif args.action == 'restore':
            backup_files_wildcard = args.backup_file_prefix + '*.ndjson'
            backup_files = glob.glob(backup_files_wildcard)
            if len(backup_files) == 0:
                raise Exception(
                    'ERROR: no files like {backup_files_wildcard} were found'.format(
                        **locals()
                    )
                )
            for backup_file in backup_files:
                regexp = '{args.backup_file_prefix}(.*)\\.ndjson'.format(**locals())
                tenant_id = re.match(regexp, backup_file).group(1)
                if len(tenant_id) == 0:
                    raise Exception(
                        'File {backup_file} does not contain a valid tenant id'.format(
                            **locals()
                        )
                    )
                restore_content = open(backup_file, 'rb')
                restore(
                    args.kibana_url,
                    tenant_id,
                    auth,
                    restore_content,
                    verify_ssl=not args.no_verify_ssl,
                )
        elif args.action == 'backup':
            tenants = get_all_tenants(
                args.kibana_url,
                auth,
                verify_ssl=not args.no_verify_ssl,
            )
            for tenant in tenants:
                backup_content = backup(
                    args.kibana_url,
                    tenant,
                    auth,
                    verify_ssl=not args.no_verify_ssl,
                )
                suffix = tenant if len(tenant) != 0 else 'global_tenant'
                open(
                    '{args.backup_file_prefix}{suffix}.ndjson'.format(**locals()), 'wb'
                ).write(backup_content)
    else:
        if args.action == 'backup':
            backup_content = backup(
                args.kibana_url,
                args.tenant_id,
                auth,
                verify_ssl=not args.no_verify_ssl,
            )
            if len(args.backup_file) == 0:
                print(backup_content, end='')
            else:
                open(args.backup_file, 'w').write(backup_content)
        elif args.action == 'restore':
            if len(args.backup_file) == 0:
                restore_content = ''.join(sys.stdin.readlines())
            else:
                restore_content = ''.join(open(args.backup_file, 'r').readlines())
            restore(
                args.kibana_url,
                args.tenant_id,
                auth,
                restore_content,
                verify_ssl=not args.no_verify_ssl,
            )
