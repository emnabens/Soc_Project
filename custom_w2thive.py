#!/var/ossec/framework/python/bin/python3
import json
import sys
import os
import re
import logging
import uuid
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, Case

# ========================
# USER CONFIG
# ========================
lvl_threshold = 8
suricata_lvl_threshold = 3
debug_enabled = False
info_enabled = True

# local map: one grouping key -> one case id
case_map_file = '/var/ossec/integrations/thehive_case_map.json'

# ========================
# LOGGER CONFIG
# ========================
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = '{0}/logs/integrations.log'.format(pwd)
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)
if info_enabled:
    logger.setLevel(logging.INFO)
if debug_enabled:
    logger.setLevel(logging.DEBUG)

if not logger.handlers:
    fh = logging.FileHandler(log_file)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

# ========================
# MAIN FUNCTION
# ========================
def main(args):
    logger.debug('#start main')

    if len(args) < 4:
        logger.error('Usage: python script.py alert.json API_KEY THEHIVE_URL')
        sys.exit(1)

    alert_file_location = args[1]
    thehive_api_key = args[2]
    thehive_url = args[3]

    thive_api = TheHiveApi(thehive_url, thehive_api_key)

    with open(alert_file_location) as f:
        w_alert = json.load(f)

    alt = pr(w_alert, '', [])
    format_alt = md_format(alt)
    artifacts_dict = artifact_detect(format_alt)
    alert = generate_alert(format_alt, artifacts_dict, w_alert)

    # Threshold filtering
    if w_alert['rule'].get('groups', []) == ['ids', 'suricata']:
        if 'data' in w_alert and 'alert' in w_alert['data']:
            if int(w_alert['data']['alert'].get('severity', 0)) >= suricata_lvl_threshold:
                send_alert(alert, thive_api, w_alert)
    elif int(w_alert['rule'].get('level', 0)) >= lvl_threshold:
        send_alert(alert, thive_api, w_alert)

# ========================
# FORMAT ALERT TO DOT-KEY
# ========================
def pr(data, prefix, alt):
    for key, value in data.items():
        if isinstance(value, dict):
            pr(value, prefix + '.' + str(key), alt=alt)
        else:
            alt.append(prefix + '.' + str(key) + '|||' + str(value))
    return alt

def md_format(alt, format_alt=''):
    md_title_dict = {}
    for now in alt:
        now = now[1:]
        dot = now.split('|||')[0].find('.')
        if dot == -1:
            md_title_dict[now.split('|||')[0]] = [now]
        else:
            key_root = now[0:dot]
            md_title_dict.setdefault(key_root, []).append(now)

    for key in md_title_dict.keys():
        format_alt += f'### {key.capitalize()}\n| key | val |\n| ------ | ------ |\n'
        for item in md_title_dict[key]:
            k, v = item.split('|||', 1)
            format_alt += f'| **{k}** | {v} |\n'

    return format_alt

# ========================
# ARTIFACT DETECTION
# ========================
def artifact_detect(format_alt):
    artifacts_dict = {}
    artifacts_dict['ip'] = list(set(re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', format_alt)))
    artifacts_dict['url'] = list(set(re.findall(r'http[s]?://[^\s]+', format_alt)))
    artifacts_dict['domain'] = list(set([url.split('//')[1].split('/')[0] for url in artifacts_dict['url']]))
    return artifacts_dict

# ========================
# HELPERS
# ========================
def normalize_text(value):
    return re.sub(r'\s+', ' ', str(value or '')).strip()

def get_src_ip(w_alert):
    data = w_alert.get('data', {})
    return str(
        data.get('srcip') or
        data.get('src_ip') or
        data.get('src') or
        ''
    )

def get_dst_ip(w_alert):
    data = w_alert.get('data', {})
    return str(
        data.get('dstip') or
        data.get('dst_ip') or
        data.get('dest_ip') or
        data.get('destination') or
        ''
    )

def get_file_path(w_alert):
    data = w_alert.get('data', {})
    return str(
        data.get('file') or
        data.get('path') or
        data.get('filename') or
        data.get('win', {}).get('eventdata', {}).get('targetFilename') or
        data.get('win', {}).get('eventdata', {}).get('image') or
        ''
    )

def build_group_key(w_alert):
    rule = w_alert.get('rule', {})
    agent = w_alert.get('agent', {})

    rule_id = str(rule.get('id', 'no-rule'))
    agent_name = normalize_text(agent.get('name', 'no-agent'))
    file_path = normalize_text(get_file_path(w_alert))
    src_ip = normalize_text(get_src_ip(w_alert))
    dst_ip = normalize_text(get_dst_ip(w_alert))

    parts = [
        f'rule_id={rule_id}',
        f'agent={agent_name}'
    ]

    if file_path:
        parts.append(f'file={file_path}')
    elif src_ip:
        parts.append(f'src={src_ip}')
        if dst_ip:
            parts.append(f'dst={dst_ip}')

    return ' | '.join(parts)

def build_case_title(w_alert):
    rule_desc = normalize_text(w_alert.get('rule', {}).get('description', 'No description'))
    return f'{rule_desc} | {build_group_key(w_alert)}'

def load_case_map():
    if not os.path.exists(case_map_file):
        return {}

    try:
        with open(case_map_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f'Could not read case map file: {str(e)}')
        return {}

def save_case_map(case_map):
    try:
        folder = os.path.dirname(case_map_file)
        if folder and not os.path.exists(folder):
            os.makedirs(folder)
        with open(case_map_file, 'w') as f:
            json.dump(case_map, f, indent=2)
    except Exception as e:
        logger.error(f'Could not save case map file: {str(e)}')

def get_obj_id(obj):
    if not isinstance(obj, dict):
        return None
    return obj.get('_id') or obj.get('id')

# ========================
# ALERT GENERATION
# ========================
def generate_alert(format_alt, artifacts_dict, w_alert):
    event_id = str(w_alert.get('id', uuid.uuid4()))
    sourceRef = f'wazuh-{event_id}'

    artifacts = []
    seen_artifacts = set()

    agent = w_alert.get('agent', {})
    agent.setdefault('id', 'no agent id')
    agent.setdefault('name', 'no agent name')
    agent.setdefault('ip', 'no agent ip')

    rule_id = str(w_alert.get('rule', {}).get('id', 'no-rule'))
    alert_title = build_case_title(w_alert)

    for key, values in artifacts_dict.items():
        for val in values:
            if (key, val) not in seen_artifacts:
                seen_artifacts.add((key, val))
                artifacts.append(AlertArtifact(dataType=key, data=val, tags=['to-analyze']))

    alert = Alert(
        title=alert_title,
        tlp=2,
        tags=[
            'wazuh',
            f'rule_id={rule_id}',
            f'agent_name={agent["name"]}',
            f'agent_id={agent["id"]}',
            f'agent_ip={agent["ip"]}'
        ],
        description=format_alt,
        type='wazuh_alert',
        source='wazuh',
        sourceRef=sourceRef,
        artifacts=artifacts
    )
    return alert

# ========================
# CASE CREATION
# ========================
def create_case_for_group(thive_api, w_alert):
    agent = w_alert.get('agent', {})
    rule_id = str(w_alert.get('rule', {}).get('id', 'no-rule'))
    case_title = build_case_title(w_alert)

    case = Case(
        title=case_title,
        tlp=2,
        tags=[
            'wazuh',
            f'rule_id={rule_id}',
            f'agent_name={agent.get("name", "no-agent")}',
            f'agent_id={agent.get("id", "no-agent-id")}',
            f'agent_ip={agent.get("ip", "no-agent-ip")}'
        ],
        description='Auto-created case for Wazuh alert grouping'
    )

    response = thive_api.create_case(case)
    if response.status_code == 201:
        return response.json()

    logger.error(f'Case creation failed: {response.status_code}/{response.text}')
    return None

# ========================
# SEND ALERT & CASE LOGIC
# ========================
def send_alert(alert, thive_api, w_alert):
    group_key = build_group_key(w_alert)
    case_map = load_case_map()

    # 1) create alert
    response = thive_api.create_alert(alert)
    if response.status_code != 201:
        logger.error(f'Alert creation failed: {response.status_code}/{response.text}')
        return

    created_alert = response.json()
    alert_id = get_obj_id(created_alert)

    if not alert_id:
        logger.error(f'Alert created but no alert id found: {created_alert}')
        return

    logger.info(f'Create TheHive alert: {alert_id}')

    # 2) resolve or create case
    case_id = case_map.get(group_key)

    if not case_id:
        new_case = create_case_for_group(thive_api, w_alert)
        if not new_case:
            logger.error('Could not create case for alert merge')
            return

        case_id = get_obj_id(new_case)
        if not case_id:
            logger.error(f'Case created but no case id found: {new_case}')
            return

        case_map[group_key] = case_id
        save_case_map(case_map)
        logger.info(f'Created new case {case_id} for key {group_key}')
    else:
        logger.info(f'Reusing existing case {case_id} for key {group_key}')

    # 3) merge alert into case
    try:
        merge_response = thive_api.merge_alert_into_case(alert_id, case_id)
    except Exception as e:
        logger.error(f'Merge call failed: {str(e)}')
        return

    if getattr(merge_response, 'status_code', None) in (200, 201):
        logger.info(f'Alert {alert_id} merged into case {case_id}')
    else:
        logger.error(f'Merge failed: {merge_response.status_code}/{merge_response.text}')

# ========================
# ENTRY POINT
# ========================
if __name__ == "__main__":
    try:
        logger.debug('debug mode')
        main(sys.argv)
    except Exception:
        logger.exception('Unexpected error')