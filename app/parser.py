"""Configurable deterministic incident extraction (Python 3.6)."""
import ipaddress
import re
import logging

from app.main import read_json, validate_result

LOG = logging.getLogger(__name__)
FLAGS = re.I | re.M
IP = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
HOST = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9_-]*)*')
ACCOUNT = re.compile(r'(?:(?:[\w.-]+|NT AUTHORITY|NT SERVICE|Window Manager|Font Driver Host)\\)?(?:LOCAL SERVICE|NETWORK SERVICE|ЛОКАЛЬНАЯ СЛУЖБА|СЕТЕВАЯ СЛУЖБА|[\w$.-]+(?:@[\w.-]+)?)', re.I)


def config(directory, name):
    path = directory / (name + '.json')
    return read_json(path if path.is_file() else directory / (name + '.example.json'))


def matches(patterns, text):
    return [bool(re.search(p, text, FLAGS)) for p in patterns]


def condition(rule, text):
    any_patterns = rule.get('match_any', [])
    return (rule.get('enabled', True)
            and all(matches(rule.get('match_all', []), text))
            and (not any_patterns or any(matches(any_patterns, text)))
            and not any(matches(rule.get('exclude', []), text)))


def parse(text, directory):
    patterns = config(directory, 'patterns')
    normalization = config(directory, 'normalization')
    local = config(directory, 'known_local_accounts')
    zones = config(directory, 'network_zones')
    classification = config(directory, 'parser_classification')
    refs = {name: config(directory, name) for name in
            ('categories', 'incident_types', 'data_fields', 'exceptions')}
    data = {key: [] for key in refs['data_fields']}
    local_names = {v.casefold() for k, values in local.items()
                   if k not in ('local_authorities', 'local_account_patterns')
                   for v in values}
    domains = {v.casefold() for v in normalization['corporate_domains']}
    source_names = []
    source_ips = []

    def add(field, value):
        if field in data and value and value not in data[field]:
            data[field].append(value)

    def extract(field, value):
        value = value.strip().strip('"').strip()
        if not value or re.match(r'не\s|определить|отсутств|unknown|n/a', value, re.I):
            return
        if field.endswith('.host'):
            role = field.split('.')[0]
            # Stop at narrative text before scanning for either IPs or hosts.
            # Cyrillic prose cannot be part of the supported ASCII host syntax.
            boundary = patterns.get('host_boundary', r'[А-Яа-яЁё]')
            value = re.split(boundary, value, maxsplit=1, flags=re.I)[0]
            for match in IP.finditer(value):
                try:
                    addr = str(ipaddress.ip_address(match.group()))
                except ValueError:
                    continue
                add(role + '.ip', addr)
                if role == 'src':
                    source_ips.append(addr)
            value = IP.sub(' ', value)
            value = re.sub(r'(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b', ' ', value)
            value = re.sub(r'\([^)]*\)', ' ', value)
            value = re.sub(r'(?i)\bMAC\s*:.*', '', value)
            for token in re.split(r'[\s,;…]+', value):
                token = token.strip('().:[]"')
                if (not HOST.fullmatch(token) or not any(c.isalpha() for c in token)
                        or re.fullmatch(r'[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}', token)):
                    continue
                if role == 'src':
                    source_names.append(token)
                name = token.split('.')[0] if normalization.get('short_name', True) else token
                add(role + '.hostname', name.lower() if normalization.get('lowercase', True) else name)
            return
        match = ACCOUNT.match(value)
        if not match:
            return
        account = match.group().rstrip('.')
        if not account:
            return
        if field != 'username':
            add(field, account)
        if '\\' in account:
            domain, name = account.split('\\', 1)
            corporate = domain.casefold() in domains
            unknown = False
        elif '@' in account:
            name, domain = account.rsplit('@', 1)
            corporate = domain.casefold() in domains
            unknown = False
        else:
            name = account
            corporate = False
            unknown = (name.casefold() not in local_names and not
                       any(matches(local.get('local_account_patterns', []), name)))
        if corporate or (unknown and normalization.get('include_unknown', True)):
            add('username', name)

    label_items = list(patterns['labels'].items())
    labels = re.compile('|'.join('(?P<L%d>%s)\\s*:' % (i, p)
                                 for i, (_, p) in enumerate(label_items)), FLAGS)
    facts = []
    for block in re.split(patterns['update'], text):
        block = re.split(patterns['explanation'], block, maxsplit=1)[0]
        facts.append(block)
        markers = list(labels.finditer(block))
        for i, marker in enumerate(markers):
            field = label_items[int(marker.lastgroup[1:])][0]
            if field == 'ignore':
                continue
            end = markers[i + 1].start() if i + 1 < len(markers) else len(block)
            value = block[marker.end():end].strip()
            # Host lists can span lines, but narrative paragraphs cannot.
            value = re.split(r'\n\s*\n|\n(?=[А-Яа-я])', value, maxsplit=1)[0]
            extract(field, value)
        for rule in patterns['inline']:
            for match in re.finditer(rule['pattern'], block, FLAGS):
                value = labels.split(match.group(1), maxsplit=1)[0]
                extract(rule['field'], value)

    category, incident_type = classification['fallback']
    selected = None
    for rule in sorted(classification['rules'], key=lambda r: -r['priority']):
        if any(condition(rule, block) for block in facts):
            category, incident_type = rule['category'], rule['incident_type']
            selected = rule
            break
    if selected and selected.get('zone'):
        networks = [ipaddress.ip_network(v) for v in zones['controlled_networks']]
        suffixes = [v.lower().lstrip('.') for v in zones['controlled_domains']]
        inside = any(ipaddress.ip_address(ip) in network
                     for ip in source_ips for network in networks)
        inside = inside or any(name.lower() == suffix or name.lower().endswith('.' + suffix)
                               for name in source_names for suffix in suffixes)
        if inside:
            incident_type = zones['inside_type']
        elif source_ips and zones.get('complete_inventory', False):
            incident_type = zones['outside_type']

    for rule in refs['exceptions']:
        if not rule.get('enabled', True) or rule.get('action') != 'exclude':
            continue
        field = rule['object_field']
        cond = rule.get('condition')
        if isinstance(cond, dict):
            pats = cond.get('patterns', [])
            test = all if cond.get('match') == 'all' else any
            applies = bool(pats) and any(test(matches(pats, block)) for block in facts)
            values = rule.get('values', [])
        elif rule.get('id') == 'exclude_dc_ip_wrong_password':
            applies = any(re.search(r'неуспешн\w*\s+попыт\w*\s+пре[- ]?аутентификации', b, FLAGS)
                          for b in facts)
            values = IP.findall(rule.get('object_description', ''))
        else:
            LOG.warning('Unsupported legacy exception: %s', rule.get('id'))
            continue
        if applies and field in data:
            data[field] = [v for v in data[field] if v not in values]
    result = dict(category=category, incident_type=incident_type, data=data)
    LOG.info('Classification rule: %s; extracted: %d',
             selected['id'] if selected else 'fallback', sum(map(len, data.values())))
    return validate_result(result, refs).model_dump(), refs
