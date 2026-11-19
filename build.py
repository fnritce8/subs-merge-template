#!/usr/bin/env python3
"""Fetch several subscriptions, merge them, and build OpenClash/FlClash
configs with the Cash-All rule template (template.json).

Configuration is via environment variables (in GitHub Actions these come
from repository Secrets / Variables):

  SUBS            Required. One subscription per line:  label|https://...
                  Any labels, any count. Labels name the per-subscription
                  groups and prefix every node name.
  EXTRA_NODES     Optional. Extra single-node links (vless:// / trojan://),
                  one per line. They are merged in under the EXTRA_LABEL
                  group, next to the subscription nodes.
  EXTRA_LABEL     Group name for EXTRA_NODES. Default: 自定义
  EXTRA_RULES     Optional. Extra Clash rules, one per line, e.g.
                  DOMAIN-SUFFIX,example.com,✨ AI
                  They are inserted just before the final MATCH rule.
                  The target must be an existing group name, DIRECT or
                  REJECT; rules with unknown targets are skipped with a
                  warning in the log.
  MIN_TOTAL_NODES Minimum total nodes for a build to be published
                  (default 10). A build that fails validation exits
                  non-zero and nothing is published.
  TEMPLATE_URL    Optional. Use someone else's rule template instead of
                  the bundled template.json. Two formats are accepted:
                  (1) a template.json in this project's format;
                  (2) a complete Clash YAML config — its dns,
                  rule-providers, rules and proxy-group structure are
                  reused, while the nodes inside the groups are
                  refilled with your own (group references are kept,
                  region groups get region nodes, other groups get
                  all nodes). If the URL cannot be fetched or parsed,
                  the bundled template is used and a warning is logged.

Each subscription's last good payload is cached under cache/; a failed
or suspicious (<5 links) fetch falls back to the cache instead of
publishing a broken config.

For local testing, --from-raw DIR reads subscription payloads from
DIR/*.txt (file stem = label) instead of fetching.

Outputs (identical content, two names):
  out/openclash.yaml
  out/flclash.yaml
"""
import argparse, base64, json, os, re, sys, urllib.parse, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/126.0 Safari/537.36')

ZW = re.compile(r'[​‌‍⁠﻿]')
BAD_FILENAME_CHARS = re.compile(r'[\\/:*?"<>|\s]+')


def clean_name(n):
    return ZW.sub('', n or '').strip()


def cache_name(label):
    return BAD_FILENAME_CHARS.sub('_', label) + '.txt'


def decode_payload(data: bytes) -> list:
    text = data.decode('utf-8', 'replace').strip()
    if not text:
        return []
    if '://' in text.splitlines()[0]:
        lines = text.splitlines()
    else:
        try:
            dec = base64.b64decode(text + '=' * (-len(text) % 4)).decode('utf-8', 'replace')
        except Exception:
            dec = text
        lines = dec.splitlines()
    return [l.strip() for l in lines if '://' in l]


def parse_vless(u):
    p = urllib.parse.urlparse(u)
    q = {k: v[0] for k, v in urllib.parse.parse_qs(p.query).items()}
    proxy = {
        'name': clean_name(urllib.parse.unquote(p.fragment)),
        'type': 'vless',
        'server': p.hostname,
        'port': p.port,
        'uuid': urllib.parse.unquote(p.username or ''),
        'udp': True,
        'network': q.get('type', 'tcp'),
    }
    if q.get('security') == 'tls':
        proxy['tls'] = True
        if q.get('sni'):
            proxy['servername'] = q['sni']
        if q.get('fp'):
            proxy['client-fingerprint'] = q['fp']
        if q.get('alpn'):
            proxy['alpn'] = [a for a in q['alpn'].split(',') if a]
    elif q.get('security') == 'reality':
        proxy['tls'] = True
        if q.get('sni'):
            proxy['servername'] = q['sni']
        if q.get('fp'):
            proxy['client-fingerprint'] = q['fp']
        ro = {}
        if q.get('pbk'):
            ro['public-key'] = q['pbk']
        if q.get('sid'):
            ro['short-id'] = q['sid']
        if ro:
            proxy['reality-opts'] = ro
    if proxy['network'] == 'ws':
        wo = {}
        if q.get('path'):
            wo['path'] = q['path']
        if q.get('host'):
            wo['headers'] = {'Host': q['host']}
        if wo:
            proxy['ws-opts'] = wo
    elif proxy['network'] == 'grpc':
        if q.get('serviceName'):
            proxy['grpc-opts'] = {'grpc-service-name': q['serviceName']}
    if q.get('flow'):
        proxy['flow'] = q['flow']
    return proxy


def parse_trojan(u):
    p = urllib.parse.urlparse(u)
    q = {k: v[0] for k, v in urllib.parse.parse_qs(p.query).items()}
    proxy = {
        'name': clean_name(urllib.parse.unquote(p.fragment)),
        'type': 'trojan',
        'server': p.hostname,
        'port': p.port,
        'password': urllib.parse.unquote(p.username or ''),
        'udp': True,
    }
    if q.get('sni'):
        proxy['sni'] = q['sni']
    if q.get('type'):
        proxy['network'] = q['type']
    if proxy.get('network') == 'ws':
        wo = {}
        if q.get('path'):
            wo['path'] = q['path']
        if q.get('host'):
            wo['headers'] = {'Host': q['host']}
        if wo:
            proxy['ws-opts'] = wo
    if q.get('alpn'):
        proxy['alpn'] = [a for a in q['alpn'].split(',') if a]
    return proxy


PARSERS = {'vless': parse_vless, 'trojan': parse_trojan}

REGION_PATTERNS = [
    ('香港-自动', re.compile(r'香港|Hong\s?Kong|(?<![A-Za-z])HK(?![A-Za-z])')),
    ('台湾-自动', re.compile(r'台湾|臺灣|Taiwan|(?<![A-Za-z])TW(?![A-Za-z])')),
    ('日本-自动', re.compile(r'日本|Japan|(?<![A-Za-z])JP(?![A-Za-z])')),
    ('新加坡-自动', re.compile(r'新加坡|Singapore|(?<![A-Za-z])SG(?![A-Za-z])')),
    ('韩国-自动', re.compile(r'韩国|韓國|Korea|(?<![A-Za-z])KR(?![A-Za-z])')),
    ('美国-自动', re.compile(r'美国|United\s?States|(?<![A-Za-z])USA?(?![A-Za-z])')),
    ('其他-自动', re.compile(
        r'乌克兰|烏克蘭|Ukraine|印度|India|英国|英國|Britain|'
        r'德国|德國|Germany|法国|法國|France|加拿大|Canada|澳大利亚|澳洲|Australia|'
        r'俄罗斯|俄羅斯|Russia|泰国|泰國|Thailand|越南|Vietnam|马来|馬來|Malaysia|'
        r'印尼|Indonesia|菲律宾|菲律賓|Philippines|土耳其|Turkey|巴西|Brazil|'
        r'荷兰|荷蘭|Netherlands|意大利|Italy|西班牙|Spain|瑞士|Switzerland|'
        r'瑞典|Sweden|挪威|Norway|芬兰|芬蘭|Finland|丹麦|丹麥|Denmark|'
        r'波兰|波蘭|Poland|爱尔兰|愛爾蘭|Ireland|葡萄牙|Portugal|希腊|希臘|Greece|'
        r'以色列|Israel|阿联酋|阿聯酋|迪拜|Dubai|沙特|埃及|Egypt|南非|墨西哥|Mexico|'
        r'阿根廷|Argentina|智利|Chile|新西兰|新西蘭|New\s?Zealand|冰岛|冰島|Iceland')),
]


def classify(orig_name):
    for group, pat in REGION_PATTERNS:
        if pat.search(orig_name):
            return group
    return None


def fetch(url, attempts=3):
    last = None
    for i in range(attempts):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': UA})
            with urllib.request.urlopen(req, timeout=45) as r:
                return r.read()
        except Exception as e:
            last = e
            print(f'fetch attempt {i + 1} failed: {e}', file=sys.stderr)
    raise last


def parse_subs_env():
    entries = []
    for line in os.environ.get('SUBS', '').splitlines():
        line = line.strip()
        if not line or '|' not in line:
            continue
        label, url = line.split('|', 1)
        entries.append((label.strip(), url.strip()))
    return entries


def collect(from_raw=None):
    """Return (proxies, per_sub_names, region_members, labels)."""
    sources = []  # (label, payload_bytes, required)
    if from_raw:
        for fn in sorted(os.listdir(from_raw)):
            if fn.endswith('.txt'):
                with open(os.path.join(from_raw, fn), 'rb') as f:
                    sources.append((fn[:-4], f.read(), True))
    else:
        entries = parse_subs_env()
        if not entries:
            raise SystemExit('SUBS is empty: add a SUBS secret with one '
                             '"label|https://..." line per subscription.')
        cache_dir = os.path.join(HERE, 'cache')
        os.makedirs(cache_dir, exist_ok=True)
        for label, url in entries:
            cache_path = os.path.join(cache_dir, cache_name(label))
            try:
                payload = fetch(url)
                n_uris = len(decode_payload(payload))
                if n_uris < 5:
                    raise ValueError(f'suspicious payload: only {n_uris} URIs')
                with open(cache_path, 'wb') as f:
                    f.write(payload)
                sources.append((label, payload, True))
                print(f'fetched {label}', file=sys.stderr)
            except Exception as e:
                if os.path.exists(cache_path):
                    with open(cache_path, 'rb') as f:
                        sources.append((label, f.read(), True))
                    print(f'WARN: fetch failed for {label} ({e}); using cache', file=sys.stderr)
                else:
                    print(f'WARN: fetch failed for {label} ({e}); no cache, skipped', file=sys.stderr)
        extra = os.environ.get('EXTRA_NODES', '').strip()
        if extra:
            label = os.environ.get('EXTRA_LABEL', '').strip() or '自定义'
            sources.append((label, extra.encode('utf-8'), False))

    proxies, per_sub, regions = [], {}, {}
    seen = {}
    labels = []
    for label, payload, _required in sources:
        labels.append(label)
        names = []
        for uri in decode_payload(payload):
            scheme = uri.split('://', 1)[0].lower()
            parser = PARSERS.get(scheme)
            if not parser:
                continue
            try:
                proxy = parser(uri)
            except Exception:
                continue
            if not proxy.get('name') or not proxy.get('server'):
                continue
            orig = proxy['name']
            name = f'{label} | {orig}'
            if name in seen:
                seen[name] += 1
                name = f'{name} #{seen[name]}'
            else:
                seen[name] = 1
            proxy['name'] = name
            proxies.append(proxy)
            names.append(name)
            region = classify(orig)
            if region:
                regions.setdefault(region, []).append(name)
        per_sub[label] = names
        print(f'{label}: {len(names)} nodes', file=sys.stderr)
    return proxies, per_sub, regions, labels


def convert_yaml_template(data, labels):
    """Turn a complete Clash YAML config into this project's template
    structure: keep its groups/rules/providers, refill the nodes."""
    groups_in = data.get('proxy-groups') or []
    names = {g.get('name') for g in groups_in if isinstance(g, dict)}
    label_by_box = {f'📦 {l}': l for l in labels}
    group_tpls = []
    for g in groups_in:
        if not isinstance(g, dict) or not g.get('name'):
            continue
        name = g['name']
        gtype = g.get('type', 'select')
        proxies = g.get('proxies') or []
        refs = [p for p in proxies if p in names or p in ('DIRECT', 'REJECT')]
        base = {k: v for k, v in g.items() if k != 'proxies'}
        if name in label_by_box:
            group_tpls.append({'def': base, 'fill': 'sub', 'sub': label_by_box[name]})
            continue
        if name == 'GLOBAL':
            prefix = list(refs)
            if '__SUB_GROUPS__' not in prefix:
                prefix.append('__SUB_GROUPS__')
            group_tpls.append({'def': base, 'fill': 'global', 'prefix': prefix})
            continue
        region = classify(name)
        if region and gtype in ('url-test', 'fallback', 'load-balance'):
            gt = {'def': base, 'fill': 'region', 'region': region}
        elif proxies and len(refs) == len(proxies):
            base['proxies'] = proxies
            group_tpls.append({'def': base, 'fill': 'static'})
            continue
        else:
            gt = {'def': base, 'fill': 'all'}
        if refs:
            gt['refs'] = refs
        group_tpls.append(gt)
    bundled = json.load(open(os.path.join(HERE, 'template.json'), encoding='utf-8'))
    tpl = {k: v for k, v in bundled.items() if k != '__groups__'}
    for k, v in data.items():
        if k in ('proxies', 'proxy-groups'):
            continue
        tpl[k] = v
    tpl['__groups__'] = group_tpls
    return tpl


def load_template(labels):
    url = os.environ.get('TEMPLATE_URL', '').strip()
    bundled_path = os.path.join(HERE, 'template.json')
    if not url:
        return json.load(open(bundled_path, encoding='utf-8'))
    try:
        text = fetch(url).decode('utf-8', 'replace').strip()
        if text.startswith('{'):
            tpl = json.loads(text)
            if '__groups__' not in tpl:
                raise ValueError('JSON template has no __groups__')
            print(f'template: using JSON template from TEMPLATE_URL', file=sys.stderr)
            return tpl
        import yaml
        data = yaml.safe_load(text)
        if not isinstance(data, dict) or 'proxy-groups' not in data:
            raise ValueError('YAML template has no proxy-groups')
        print('template: using YAML config as template from TEMPLATE_URL', file=sys.stderr)
        return convert_yaml_template(data, labels)
    except Exception as e:
        print(f'WARN: TEMPLATE_URL failed ({e}); using bundled template', file=sys.stderr)
        return json.load(open(bundled_path, encoding='utf-8'))


def build_config(proxies, per_sub, regions, labels, tpl):
    group_tpls = tpl.pop('__groups__')
    all_names = [p['name'] for p in proxies]
    sub_group_names = [f'📦 {label}' for label in labels]
    existing_names = {gt['def'].get('name') for gt in group_tpls}
    groups = []
    sub_groups_inserted = False

    def insert_sub_groups():
        nonlocal sub_groups_inserted
        for label in labels:
            gname = f'📦 {label}'
            if gname not in existing_names:
                groups.append({'name': gname, 'type': 'select',
                               'proxies': per_sub.get(label, [])})
        sub_groups_inserted = True

    for gt in group_tpls:
        if gt['fill'] == 'global':
            if not sub_groups_inserted:
                insert_sub_groups()
            g = dict(gt['def'])
            prefix = []
            for item in gt['prefix']:
                if item == '__SUB_GROUPS__':
                    prefix.extend(sub_group_names)
                else:
                    prefix.append(item)
            g['proxies'] = prefix + all_names
            groups.append(g)
            continue
        g = dict(gt['def'])
        fill = gt['fill']
        if fill == 'static':
            pass
        elif fill == 'sub':
            g['proxies'] = per_sub.get(gt['sub'], [])
        elif fill in ('all', 'region'):
            filled = all_names if fill == 'all' else regions.get(gt['region'], [])
            refs = gt.get('refs', [])
            if refs:
                merged = list(refs)
                for n in filled:
                    if n not in merged:
                        merged.append(n)
                g['proxies'] = merged
            else:
                g['proxies'] = filled
        groups.append(g)
        if gt['fill'] == 'region' and gt['region'] == '其他-自动':
            insert_sub_groups()
    cfg = {}
    for k, v in tpl.items():
        cfg[k] = v
        if k == 'dns':
            cfg['proxies'] = proxies
            cfg['proxy-groups'] = groups
    if 'proxies' not in cfg:
        cfg['proxies'] = proxies
        cfg['proxy-groups'] = groups
    return cfg


def apply_extra_rules(cfg):
    raw = os.environ.get('EXTRA_RULES', '')
    if not raw.strip():
        return
    group_names = {g['name'] for g in cfg['proxy-groups']} | {'DIRECT', 'REJECT'}
    extra = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = [p.strip() for p in line.split(',')]
        if parts[0].upper() == 'MATCH' and len(parts) >= 2:
            target = parts[1]
        elif len(parts) >= 3:
            target = parts[2]
        else:
            print(f'WARN: EXTRA_RULES line skipped (bad format): {line}', file=sys.stderr)
            continue
        if target not in group_names:
            print(f'WARN: EXTRA_RULES line skipped (unknown target "{target}"): {line}',
                  file=sys.stderr)
            continue
        extra.append(line)
    if not extra:
        return
    rules = cfg['rules']
    idx = len(rules)
    if rules and rules[-1].strip().upper().startswith('MATCH'):
        idx = len(rules) - 1
    cfg['rules'] = rules[:idx] + extra + rules[idx:]
    print(f'EXTRA_RULES: inserted {len(extra)} rule(s)', file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--from-raw', default=None)
    ap.add_argument('--out', default=os.path.join(HERE, 'out'))
    args = ap.parse_args()

    proxies, per_sub, regions, labels = collect(args.from_raw)
    total = len(proxies)
    print(f'total: {total} nodes', file=sys.stderr)
    min_total = int(os.environ.get('MIN_TOTAL_NODES', '10'))
    if total < min_total:
        raise SystemExit(f'validation failed: only {total} nodes (< {min_total})')
    required_labels = labels if not os.environ.get('EXTRA_NODES') else labels[:-1] \
        if not args.from_raw else labels
    empty_subs = [l for l in required_labels if len(per_sub.get(l, [])) == 0]
    if empty_subs:
        raise SystemExit(f'validation failed: subscriptions with 0 nodes: {empty_subs}')

    import yaml
    tpl = load_template(labels)
    cfg = build_config(proxies, per_sub, regions, labels, tpl)
    apply_extra_rules(cfg)
    os.makedirs(args.out, exist_ok=True)
    text = yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False,
                          default_flow_style=False, width=4096)
    for fn in ('openclash.yaml', 'flclash.yaml'):
        with open(os.path.join(args.out, fn), 'w', encoding='utf-8') as f:
            f.write(text)
    stats = {'total': total,
             'per_sub': {k: len(v) for k, v in per_sub.items()},
             'regions': {k: len(v) for k, v in regions.items()},
             'groups': len(cfg['proxy-groups']), 'rules': len(cfg['rules'])}
    print(json.dumps(stats, ensure_ascii=False))


if __name__ == '__main__':
    main()
