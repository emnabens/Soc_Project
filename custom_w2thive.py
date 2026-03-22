#!/var/ossec/framework/python/bin/python3
import json
import sys
import os
import re
import logging
import uuid
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert

# ========================
# USER CONFIG
# ========================
lvl_threshold = 8
suricata_lvl_threshold = 3
debug_enabled = True
info_enabled = True

# ========================
# ENV CONFIG
# ========================
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "***********************")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
CORTEX_ID = os.getenv("CORTEX_ID", "cortex_server")

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
JOB_POLL_INTERVAL = int(os.getenv("JOB_POLL_INTERVAL", "8"))
JOB_POLL_MAX_ROUNDS = int(os.getenv("JOB_POLL_MAX_ROUNDS", "30"))
CONFIDENCE_THRESHOLD = int(os.getenv("CONFIDENCE_THRESHOLD", "70"))
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"

if not GEMINI_API_KEY:
    raise RuntimeError("Missing GEMINI_API_KEY environment variable")

# ========================
# LOGGER CONFIG
# ========================
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = "{0}/logs/integrations.log".format(pwd)
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)
if info_enabled:
    logger.setLevel(logging.INFO)
if debug_enabled:
    logger.setLevel(logging.DEBUG)

if not logger.handlers:
    fh = logging.FileHandler(log_file)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

# ========================
# GLOBALS
# ========================
THEHIVE_URL = None
THEHIVE_API_KEY = None
HEADERS = {}

FINAL_JOB_STATUSES = {"success", "failure", "deleted", "cancelled"}

ALLOWED_ALERT_STATUSES = {
    "New",
    "Ignored",
    "Imported",
    "InProgress",
    "Pending",
    "Duplicate",
    "FalsePositive",
}
ALERT_STATUS_MAP = {
    "TruePositive": "Imported",
    "FalsePositive": "FalsePositive",
    "Indeterminate": "Pending",
    "Suspicious": "New",
}

ALLOWED_CASE_STATUSES = {
    "New",
    "InProgress",
    "TruePositive",
    "FalsePositive",
    "Indeterminate",
    "Duplicated",
    "Other",
}

DEFAULT_ANALYZERS = {
    "url": ["VirusTotal_GetReport_3_1", "MISP_2_1"],
    "uri": ["VirusTotal_GetReport_3_1", "MISP_2_1"],
    "domain": ["VirusTotal_GetReport_3_1", "MISP_2_1"],
    "fqdn": ["VirusTotal_GetReport_3_1", "MISP_2_1"],
    "ip": ["AbuseIPDB_2_0"],
    "ip_address": ["AbuseIPDB_2_0"],
    "hash": ["VirusTotal_GetReport_3_1", "MISP_2_1"],
    "md5": ["MalwareBazaar_1_0", "MISP_2_1"],
    "sha1": ["MalwareBazaar_1_0", "MISP_2_1"],
    "sha256": ["MalwareBazaar_1_0", "MISP_2_1"],
    "file": ["VirusTotal_GetReport_3_1", "MISP_2_1"],
    "filename": ["MISP_2_1"],
}

# ========================
# HELPERS
# ========================
def normalize_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()

def trim_json(value: Any, max_len: int = 12000) -> str:
    try:
        text = json.dumps(value, ensure_ascii=False, indent=2, default=str)
    except Exception:
        text = str(value)
    return text[:max_len]

def get_obj_id(obj: Any) -> Optional[str]:
    if not isinstance(obj, dict):
        return None
    return obj.get("_id") or obj.get("id")

def safe_json(res: Optional[requests.Response], default: Any) -> Any:
    if not res:
        return default
    try:
        return res.json()
    except Exception:
        return default

def api_url(path: str) -> str:
    return f"{THEHIVE_URL}/{path.lstrip('/')}"

def verdict_to_case_status(verdict: str) -> str:
    if verdict == "TruePositive":
        return "TruePositive"
    if verdict == "FalsePositive":
        return "FalsePositive"
    return "Indeterminate"

def pr(data, prefix, alt):
    for key, value in data.items():
        if isinstance(value, dict):
            pr(value, prefix + "." + str(key), alt=alt)
        else:
            alt.append(prefix + "." + str(key) + "|||" + str(value))
    return alt

def md_format(alt, format_alt=""):
    md_title_dict = {}
    for now in alt:
        now = now[1:]
        dot = now.split("|||")[0].find(".")
        if dot == -1:
            md_title_dict[now.split("|||")[0]] = [now]
        else:
            key_root = now[0:dot]
            md_title_dict.setdefault(key_root, []).append(now)

    for key in md_title_dict.keys():
        format_alt += f"### {key.capitalize()}\n| key | val |\n| ------ | ------ |\n"
        for item in md_title_dict[key]:
            k, v = item.split("|||", 1)
            format_alt += f"| **{k}** | {v} |\n"

    return format_alt

def artifact_detect(format_alt: str) -> List[Dict[str, str]]:
    artifacts: List[Dict[str, str]] = []
    seen = set()

    def add(dtype: str, value: str):
        key = (dtype, value)
        if value and key not in seen:
            seen.add(key)
            artifacts.append({"dataType": dtype, "data": value})

    for ip in set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", format_alt)):
        add("ip", ip)

    for url in set(re.findall(r"http[s]?://[^\s|)]+", format_alt)):
        add("url", url)
        try:
            host = url.split("//", 1)[1].split("/", 1)[0]
            add("domain", host)
        except Exception:
            pass

    for md5 in set(re.findall(r"\b[a-fA-F0-9]{32}\b", format_alt)):
        add("md5", md5)
    for sha1 in set(re.findall(r"\b[a-fA-F0-9]{40}\b", format_alt)):
        add("sha1", sha1)
    for sha256 in set(re.findall(r"\b[a-fA-F0-9]{64}\b", format_alt)):
        add("sha256", sha256)

    return artifacts

# ========================
# HTTP
# ========================
def request_any(
    method: str,
    paths: List[str],
    *,
    payload: Optional[Dict[str, Any]] = None,
    expected: Tuple[int, ...] = (200, 201, 204),
) -> Tuple[Optional[requests.Response], str]:
    last_error = "no response"

    for path in paths:
        url = api_url(path)
        try:
            logger.debug(f"HTTP {method} {url} payload={trim_json(payload, 1800) if payload else None}")

            if method == "GET":
                res = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
            elif method == "POST":
                res = requests.post(url, headers=HEADERS, json=payload, timeout=REQUEST_TIMEOUT)
            elif method == "PATCH":
                res = requests.patch(url, headers=HEADERS, json=payload, timeout=REQUEST_TIMEOUT)
            else:
                raise ValueError(f"Unsupported method: {method}")

            logger.debug(f"HTTP {method} {url} -> {res.status_code} body={res.text[:3000]}")

            if res.status_code in expected:
                return res, path

            last_error = f"{path} -> HTTP {res.status_code}: {res.text[:3000]}"
        except Exception as e:
            last_error = f"{path} -> {e}"

    return None, last_error

def get_json(paths: List[str], *, expected: Tuple[int, ...] = (200,)) -> Any:
    res, err = request_any("GET", paths, expected=expected)
    if not res:
        raise RuntimeError(err)
    return safe_json(res, {})

def post_json(paths: List[str], payload: Dict[str, Any], *, expected: Tuple[int, ...] = (200, 201)) -> Any:
    res, err = request_any("POST", paths, payload=payload, expected=expected)
    if not res:
        raise RuntimeError(err)
    return safe_json(res, {})

def patch_ok(paths: List[str], payload: Dict[str, Any], *, expected: Tuple[int, ...] = (200, 201, 204)) -> bool:
    if DRY_RUN:
        logger.info(f"[DRY_RUN] PATCH {paths[0]} payload={trim_json(payload, 1000)}")
        return True
    res, err = request_any("PATCH", paths, payload=payload, expected=expected)
    if not res:
        logger.error(f"PATCH failed: {err}")
        return False
    return True

# ========================
# THEHIVE ALERT/OBSERVABLE
# ========================
def generate_alert(format_alt: str, w_alert: Dict[str, Any]) -> Alert:
    event_id = str(w_alert.get("id", uuid.uuid4()))
    source_ref = f"wazuh-{event_id}"

    agent = w_alert.get("agent", {}) or {}
    agent.setdefault("id", "no agent id")
    agent.setdefault("name", "no agent name")
    agent.setdefault("ip", "no agent ip")

    rule_id = str(w_alert.get("rule", {}).get("id", "no-rule"))
    rule_desc = normalize_text(w_alert.get("rule", {}).get("description", "No description"))
    alert_title = f'{rule_desc} | rule_id={rule_id} | agent={agent["name"]}'

    return Alert(
        title=alert_title,
        tlp=2,
        tags=[
            "wazuh",
            f"rule_id={rule_id}",
            f"agent_name={agent['name']}",
            f"agent_id={agent['id']}",
            f"agent_ip={agent['ip']}",
        ],
        description=format_alt,
        type="wazuh_alert",
        source="wazuh",
        sourceRef=source_ref,
    )

def extract_observable_from_response(data: Any, alert_id: str, expected_data_type: str, expected_value: str) -> Dict[str, Any]:
    candidates: List[Dict[str, Any]] = []

    if isinstance(data, dict):
        if isinstance(data.get("data"), dict):
            candidates.append(data["data"])
        elif isinstance(data.get("data"), list):
            candidates.extend([x for x in data["data"] if isinstance(x, dict)])
        else:
            candidates.append(data)
    elif isinstance(data, list):
        candidates.extend([x for x in data if isinstance(x, dict)])

    if not candidates:
        raise RuntimeError(f"No observable candidates found in response: {trim_json(data, 4000)}")

    for item in candidates:
        obs_id = get_obj_id(item)
        if obs_id and str(obs_id) != str(alert_id):
            if item.get("dataType") == expected_data_type and str(item.get("data")) == str(expected_value):
                return item

    for item in candidates:
        obs_id = get_obj_id(item)
        if obs_id and str(obs_id) != str(alert_id):
            return item

    raise RuntimeError(f"Could not extract observable object. alert_id={alert_id} response={trim_json(data, 4000)}")

def create_alert_observable_raw(alert_id: str, data_type: str, value: str) -> Dict[str, Any]:
    payload = {
        "dataType": data_type,
        "data": value,
        "tags": ["to-analyze"],
        "ioc": False,
    }

    if DRY_RUN:
        return {
            "_id": f"dryrun-{data_type}-{uuid.uuid4()}",
            "dataType": data_type,
            "data": value,
            "tags": ["to-analyze"],
        }

    raw = post_json(
        [
            f"/api/v1/alert/{alert_id}/artifact",
            f"/api/alert/{alert_id}/artifact",
        ],
        payload,
        expected=(200, 201),
    )
    logger.info(f"Raw observable creation response: {trim_json(raw, 4000)}")

    created_obs = extract_observable_from_response(raw, alert_id, data_type, value)
    obs_id = get_obj_id(created_obs)

    if not obs_id:
        raise RuntimeError(f"Observable id missing after extraction: {trim_json(created_obs, 2500)}")
    if str(obs_id) == str(alert_id):
        raise RuntimeError(f"Observable id equals alert id ({obs_id})")

    logger.info(f"Real observable extracted: obs_id={obs_id} type={created_obs.get('dataType')} data={created_obs.get('data')}")
    return created_obs

def get_alert_details(alert_id: str) -> Dict[str, Any]:
    data = get_json([f"/api/v1/alert/{alert_id}", f"/api/alert/{alert_id}"])
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        return data["data"]
    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected alert details shape: {type(data).__name__}")
    return data

def add_alert_comment(alert_id: str, message: str) -> bool:
    payload = {"message": message}
    res, err = request_any(
        "POST",
        [f"/api/v1/alert/{alert_id}/comment", f"/api/alert/{alert_id}/comment"],
        payload=payload,
        expected=(200, 201),
    )
    if not res:
        logger.error(f"Failed to add alert comment: {err}")
        return False
    return True

def update_alert_status(alert_id: str, new_status: str) -> bool:
    if new_status not in ALLOWED_ALERT_STATUSES:
        logger.warning(f"Unsupported alert status '{new_status}'")
        return False
    return patch_ok(
        [f"/api/v1/alert/{alert_id}", f"/api/alert/{alert_id}"],
        {"status": new_status},
    )

def update_alert_tags(alert_id: str, existing_tags: List[str], verdict: str, confidence: int) -> bool:
    tags = list(existing_tags or [])
    for tag in ["llm-reviewed", "auto-triaged", f"llm:{verdict}"]:
        if tag not in tags:
            tags.append(tag)
    tags = [t for t in tags if not str(t).startswith("llm-confidence:")]
    tags.append(f"llm-confidence:{confidence}")

    return patch_ok(
        [f"/api/v1/alert/{alert_id}", f"/api/alert/{alert_id}"],
        {"tags": tags},
    )

def update_alert_summary(alert_id: str, summary: str) -> bool:
    return patch_ok(
        [f"/api/v1/alert/{alert_id}", f"/api/alert/{alert_id}"],
        {"summary": summary},
    )

def update_observable_tags(obs_id: str, existing_tags: List[str], verdict: str, confidence: int) -> bool:
    tags = [t for t in (existing_tags or []) if t != "to-analyze"]
    for tag in ["llm-reviewed", "observable-reviewed", f"llm:{verdict}"]:
        if tag not in tags:
            tags.append(tag)
    tags = [t for t in tags if not str(t).startswith("llm-confidence:")]
    tags.append(f"llm-confidence:{confidence}")

    return patch_ok(
        [f"/api/v1/observable/{obs_id}", f"/api/case/artifact/{obs_id}"],
        {"tags": tags},
    )

# ========================
# CASE
# ========================
def update_case_status(case_id: str, new_status: str) -> bool:
    if new_status not in ALLOWED_CASE_STATUSES:
        logger.warning(f"Unsupported case status '{new_status}'")
        return False
    return patch_ok(
        [f"/api/v1/case/{case_id}", f"/api/case/{case_id}"],
        {"status": new_status},
    )

def update_case_summary(case_id: str, summary: str) -> bool:
    return patch_ok(
        [f"/api/v1/case/{case_id}", f"/api/case/{case_id}"],
        {"summary": summary, "description": summary},
    )

def add_case_comment(case_id: str, message: str) -> bool:
    payload = {"message": message}
    res, err = request_any(
        "POST",
        [f"/api/v1/case/{case_id}/comment", f"/api/case/{case_id}/comment"],
        payload=payload,
        expected=(200, 201),
    )
    if not res:
        logger.error(f"Failed to add case comment: {err}")
        return False
    return True

def promote_alert_to_case(thive_api, alert_id: str) -> Optional[Dict[str, Any]]:
    if DRY_RUN:
        return {"id": "~dry-run-case"}

    try:
        if hasattr(thive_api, "promote_alert_to_case"):
            res = thive_api.promote_alert_to_case(alert_id)
            if getattr(res, "status_code", None) in (200, 201):
                return res.json()
    except Exception as e:
        logger.warning(f"thehive4py promote failed: {e}")

    for path in [
        f"/api/v1/alert/{alert_id}/case",
        f"/api/alert/{alert_id}/case",
        f"/api/v1/alert/{alert_id}/createCase",
        f"/api/alert/{alert_id}/createCase",
    ]:
        try:
            data = post_json([path], {}, expected=(200, 201))
            if isinstance(data, dict):
                return data
        except Exception:
            continue
    return None

# ========================
# CORTEX
# ========================
def list_available_analyzers() -> List[Dict[str, Any]]:
    try:
        data = get_json(
            ["/api/v1/connector/cortex/analyzer", "/api/connector/cortex/analyzer"],
            expected=(200,),
        )
        logger.info(f"Raw analyzers response: {trim_json(data, 6000)}")

        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]

        if isinstance(data, dict):
            if isinstance(data.get("data"), list):
                return [x for x in data["data"] if isinstance(x, dict)]
            if isinstance(data.get("analyzers"), list):
                return [x for x in data["analyzers"] if isinstance(x, dict)]

        return []
    except Exception as e:
        logger.error(f"Error listing analyzers: {e}")
        return []

def get_enabled_analyzers_for_type(data_type: Optional[str]) -> List[str]:
    dt = str(data_type or "").lower().strip()
    available = list_available_analyzers()

    if not available:
        logger.warning("No analyzers returned from TheHive/Cortex")
        return []

    matched: List[str] = []

    for item in available:
        analyzer_id = item.get("id") or item.get("analyzerDefinitionId") or item.get("name")
        if not analyzer_id:
            continue

        supported_types = (
            item.get("dataTypeList")
            or item.get("dataTypes")
            or item.get("supportedTypes")
            or item.get("artifactTypes")
            or []
        )

        if isinstance(supported_types, str):
            supported_types = [supported_types]

        supported_types = [str(x).lower() for x in supported_types]

        if dt in supported_types:
            matched.append(str(analyzer_id))
            continue

        if dt == "ip" and any(x in supported_types for x in ["ip", "ip_address", "ipaddress"]):
            matched.append(str(analyzer_id))
            continue

        if dt in ["domain", "fqdn"] and any(x in supported_types for x in ["domain", "fqdn", "hostname"]):
            matched.append(str(analyzer_id))
            continue

        if dt in ["url", "uri"] and any(x in supported_types for x in ["url", "uri"]):
            matched.append(str(analyzer_id))
            continue

    if not matched:
        desired = DEFAULT_ANALYZERS.get(dt, ["MISP_2_1"])
        available_ids = {
            str(item.get("id") or item.get("analyzerDefinitionId") or item.get("name"))
            for item in available
            if item.get("id") or item.get("analyzerDefinitionId") or item.get("name")
        }
        matched = [x for x in desired if x in available_ids]

    logger.info(f"Analyzer selection for data_type={dt}: matched={matched}")
    return list(dict.fromkeys(matched))

def launch_analyzer(observable_id: str, analyzer: str) -> Optional[str]:
    payload = {
        "analyzerId": analyzer,
        "cortexId": CORTEX_ID,
        "artifactId": observable_id,
    }

    logger.info(f"Launching analyzer {analyzer} on observable {observable_id}")

    try:
        data = post_json(
            ["/api/v1/connector/cortex/job", "/api/connector/cortex/job"],
            payload,
            expected=(200, 201),
        )
        if isinstance(data, dict):
            return data.get("id") or data.get("_id")
        return None
    except Exception as e:
        logger.error(f"Failed to launch analyzer {analyzer} for observable {observable_id}: {e}")
        return None

def get_job_details(job_id: str) -> Dict[str, Any]:
    data = get_json(
        [f"/api/v1/connector/cortex/job/{job_id}", f"/api/connector/cortex/job/{job_id}"],
        expected=(200,),
    )
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        return data["data"]
    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected job details shape: {type(data).__name__}")
    return data

def poll_jobs(job_ids: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}

    for _ in range(JOB_POLL_MAX_ROUNDS):
        all_done = True

        for analyzer_name, job_id in job_ids.items():
            existing = results.get(analyzer_name)
            if existing and str(existing.get("status", "")).lower() in FINAL_JOB_STATUSES:
                continue

            try:
                job = get_job_details(job_id)
                results[analyzer_name] = job
                if str(job.get("status", "")).lower() not in FINAL_JOB_STATUSES:
                    all_done = False
            except Exception as e:
                logger.error(f"Failed reading job {job_id} ({analyzer_name}): {e}")
                all_done = False

        if all_done:
            return results
        time.sleep(JOB_POLL_INTERVAL)

    return results

def extract_job_report(job: Dict[str, Any]) -> Dict[str, Any]:
    extra_data = job.get("extraData", {})
    report_from_extra = extra_data.get("report", {}) if isinstance(extra_data, dict) else {}

    return {
        "job_id": job.get("id") or job.get("_id"),
        "analyzer": job.get("analyzerId") or job.get("analyzerName") or job.get("analyzerDefinitionId"),
        "status": job.get("status"),
        "summary": job.get("summary"),
        "taxonomies": job.get("taxonomies", []),
        "operations": job.get("operations", []),
        "report": job.get("report") or job.get("full") or job.get("fullReport") or report_from_extra or {},
        "short_report": job.get("short") or job.get("shortReport") or {},
    }

# ========================
# GEMINI
# ========================
def ask_gemini_for_observable_verdict(observable: Dict[str, Any], reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    prompt = f"""
You are a SOC triage assistant.

Review ONE observable and its analyzer reports.
Decide whether the observable is:
- TruePositive
- FalsePositive
- Suspicious

Rules:
- TruePositive: strong evidence the observable is malicious or part of a real security event.
- FalsePositive: strong evidence the observable is benign, test data, noise, or a harmless artifact.
- Suspicious: evidence is mixed, incomplete, or inconclusive.

Be conservative:
- If unsure, choose Suspicious.
- Do not choose FalsePositive unless the evidence is clearly benign.

Return only JSON with:
{{
  "verdict": "TruePositive" | "FalsePositive" | "Suspicious",
  "confidence": 0,
  "summary": "one short conclusion",
  "why": "clear analyst explanation"
}}

Observable:
{trim_json(observable, 3000)}

Analyzer reports:
{trim_json(reports, 16000)}
""".strip()

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
            "responseSchema": {
                "type": "object",
                "properties": {
                    "verdict": {"type": "string", "enum": ["TruePositive", "FalsePositive", "Suspicious"]},
                    "confidence": {"type": "integer"},
                    "summary": {"type": "string"},
                    "why": {"type": "string"}
                },
                "required": ["verdict", "confidence", "summary", "why"]
            }
        }
    }

    res = requests.post(url, json=payload, timeout=90)
    if res.status_code != 200:
        raise RuntimeError(f"Gemini API error {res.status_code}: {res.text[:1200]}")

    data = res.json()
    text = (
        data.get("candidates", [{}])[0]
        .get("content", {})
        .get("parts", [{}])[0]
        .get("text", "")
        .strip()
    )

    if not text:
        raise RuntimeError(f"Gemini returned empty content: {trim_json(data, 1200)}")

    result = json.loads(text)
    verdict = result.get("verdict", "Suspicious")
    try:
        confidence = int(result.get("confidence", 50))
    except Exception:
        confidence = 50

    if verdict not in {"TruePositive", "FalsePositive", "Suspicious"}:
        verdict = "Suspicious"

    return {
        "verdict": verdict,
        "confidence": max(0, min(confidence, 100)),
        "summary": str(result.get("summary", "No summary provided.")),
        "why": str(result.get("why", "No explanation provided.")),
    }

def ask_gemini_for_alert_summary(
    w_alert: Dict[str, Any],
    observable_results: List[Dict[str, Any]],
    final_result: Dict[str, Any],
    promoted: bool,
) -> str:
    prompt = f"""
You are a SOC analyst assistant.

Write a concise professional alert summary in English for TheHive.
The summary will be shown in the alert or case summary field.

Requirements:
- Write in clear analyst style.
- Keep it concise but informative.
- Explain what triggered the alert.
- Summarize the observable analysis results.
- Explain why the final verdict was reached.
- State whether the alert was promoted to a case or not.
- End with a short recommended action.
- Do not use markdown.
- Do not use bullet points.
- Output plain text only.

Alert source data:
{trim_json(w_alert, 6000)}

Observable-level results:
{trim_json(observable_results, 8000)}

Final alert result:
{trim_json(final_result, 3000)}

Promotion decision:
{"Promoted to case" if promoted else "Not promoted to case"}
""".strip()

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "responseMimeType": "text/plain",
        }
    }

    res = requests.post(url, json=payload, timeout=90)
    if res.status_code != 200:
        raise RuntimeError(f"Gemini API error {res.status_code}: {res.text[:1200]}")

    data = res.json()
    text = (
        data.get("candidates", [{}])[0]
        .get("content", {})
        .get("parts", [{}])[0]
        .get("text", "")
        .strip()
    )

    if not text:
        raise RuntimeError(f"Gemini returned empty alert summary: {trim_json(data, 1200)}")

    return text[:4000]

# ========================
# TRIAGE
# ========================
def analyze_one_alert_observable(obs: Dict[str, Any]) -> Dict[str, Any]:
    obs_id = get_obj_id(obs)
    if not obs_id:
        return {
            "observable_id": None,
            "dataType": obs.get("dataType"),
            "data": obs.get("data"),
            "verdict": "Suspicious",
            "confidence": 0,
            "summary": "Observable has no id; analyzer run skipped.",
            "why": "The observable could not be resolved to a valid TheHive artifact id.",
            "reports": [],
        }

    data_type = obs.get("dataType")
    analyzers = get_enabled_analyzers_for_type(data_type)
    logger.info(f"Analyzing observable {obs_id} type={data_type} analyzers={analyzers}")

    if not analyzers:
        return {
            "observable_id": obs_id,
            "dataType": obs.get("dataType"),
            "data": obs.get("data"),
            "verdict": "Suspicious",
            "confidence": 0,
            "summary": "No enabled analyzers available.",
            "why": f"No enabled Cortex analyzers were found for observable type '{data_type}'.",
            "reports": [],
        }

    launched_jobs: Dict[str, str] = {}
    for analyzer in analyzers:
        job_id = launch_analyzer(obs_id, analyzer)
        if job_id:
            launched_jobs[analyzer] = job_id
            logger.info(f"Launched {analyzer} job={job_id}")
        else:
            logger.warning(f"Failed to launch {analyzer} for observable {obs_id}")

    if not launched_jobs:
        return {
            "observable_id": obs_id,
            "dataType": obs.get("dataType"),
            "data": obs.get("data"),
            "verdict": "Suspicious",
            "confidence": 0,
            "summary": "No analyzers launched.",
            "why": "No Cortex analyzer job could be started for this observable.",
            "reports": [],
        }

    jobs = poll_jobs(launched_jobs)
    reports: List[Dict[str, Any]] = []

    for analyzer_name, job in jobs.items():
        entry = extract_job_report(job)
        entry["analyzer"] = analyzer_name
        reports.append(entry)

    llm_result = ask_gemini_for_observable_verdict(obs, reports)

    return {
        "observable_id": obs_id,
        "dataType": obs.get("dataType"),
        "data": obs.get("data"),
        "verdict": llm_result["verdict"],
        "confidence": llm_result["confidence"],
        "summary": llm_result["summary"],
        "why": llm_result["why"],
        "reports": reports,
    }

def aggregate_alert_verdict(observable_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not observable_results:
        return {
            "verdict": "Suspicious",
            "confidence": 0,
            "summary": "No observables were analyzed.",
            "why": "The alert ended up with no observable-level analysis results."
        }

    tp_results = [r for r in observable_results if r.get("verdict") == "TruePositive"]
    fp_results = [r for r in observable_results if r.get("verdict") == "FalsePositive"]
    suspicious_results = [r for r in observable_results if r.get("verdict") == "Suspicious"]

    max_tp = max([int(r.get("confidence", 0)) for r in tp_results], default=0)
    min_fp = min([int(r.get("confidence", 0)) for r in fp_results], default=0)
    max_susp = max([int(r.get("confidence", 0)) for r in suspicious_results], default=0)

    if max_tp >= CONFIDENCE_THRESHOLD:
        strongest = max(tp_results, key=lambda x: int(x.get("confidence", 0)))
        return {
            "verdict": "TruePositive",
            "confidence": int(strongest.get("confidence", 0)),
            "summary": strongest.get("summary", "At least one observable is strongly malicious."),
            "why": strongest.get("why", "A high-confidence malicious observable was found in this alert.")
        }

    if fp_results and len(fp_results) == len(observable_results) and min_fp >= CONFIDENCE_THRESHOLD:
        return {
            "verdict": "FalsePositive",
            "confidence": min_fp,
            "summary": "All analyzed observables appear benign.",
            "why": "Each observable reviewed for this alert was classified as benign with high confidence."
        }

    return {
        "verdict": "Suspicious",
        "confidence": max(max_tp, max_susp, min_fp),
        "summary": "Observable analysis was incomplete or inconclusive.",
        "why": "No high-confidence malicious or benign conclusion was reached from observable analysis."
    }

def build_alert_llm_comment(
    alert_id: str,
    alert_title: str,
    observable_results: List[Dict[str, Any]],
    final_result: Dict[str, Any],
    promoted: bool,
) -> str:
    lines = [
        "### LLM Alert Triage Result",
        "",
        f"**Alert ID:** {alert_id}",
        f"**Alert Title:** {alert_title}",
        f"**Final Alert Verdict:** {final_result['verdict']}",
        f"**Confidence:** {final_result['confidence']}%",
        f"**Summary:** {final_result['summary']}",
        "",
        f"**Why:** {final_result['why']}",
        "",
        "### Observable Results",
        "",
    ]

    if not observable_results:
        lines.append("- No observables were available for analysis.")
    else:
        for idx, r in enumerate(observable_results, start=1):
            lines.extend([
                f"**{idx}. Observable**",
                f"- ID: {r.get('observable_id')}",
                f"- Type: {r.get('dataType')}",
                f"- Data: `{r.get('data')}`",
                f"- Verdict: {r.get('verdict')}",
                f"- Confidence: {r.get('confidence')}%",
                f"- Summary: {r.get('summary')}",
                f"- Why: {r.get('why')}",
                "",
            ])

    lines.extend([
        "### Promotion Decision",
        "",
        (
            f"This alert was promoted to a case because the LLM judged it as "
            f"'{final_result['verdict']}' with confidence {final_result['confidence']}%."
        ) if promoted else (
            f"This alert was not promoted to a case because the LLM judged it as "
            f"'{final_result['verdict']}' with confidence {final_result['confidence']}%. "
            f"Promotion requires a TruePositive verdict with confidence >= {CONFIDENCE_THRESHOLD}%."
        ),
    ])
    return "\n".join(lines)

# ========================
# PIPELINE
# ========================
def send_and_analyze_alert(alert, thive_api, observables_payload: List[Dict[str, str]], w_alert: Dict[str, Any]):
    response = thive_api.create_alert(alert)
    if response.status_code != 201:
        logger.error(f"Alert creation failed: {response.status_code}/{response.text}")
        return

    created_alert = response.json()
    alert_id = get_obj_id(created_alert)
    if not alert_id:
        logger.error(f"Alert created but no alert id found: {created_alert}")
        return

    logger.info(f"Created TheHive alert: {alert_id}")

    try:
        alert_details = get_alert_details(alert_id)
    except Exception as e:
        logger.error(f"Failed to fetch alert details for {alert_id}: {e}")
        alert_details = dict(created_alert)

    existing_tags = alert_details.get("tags", []) or []
    alert_title = alert_details.get("title", created_alert.get("title", "Untitled Alert"))
    observable_results: List[Dict[str, Any]] = []

    for obs in observables_payload:
        try:
            created_obs = create_alert_observable_raw(alert_id, obs["dataType"], obs["data"])
            logger.info(f"Alert ID: {alert_id}")
            logger.info(f"Observable ID: {get_obj_id(created_obs)}")
            logger.info(f"Created observable object: {trim_json(created_obs, 2500)}")

            result = analyze_one_alert_observable(created_obs)
            observable_results.append(result)

            obs_id = get_obj_id(created_obs)
            if obs_id:
                update_observable_tags(
                    obs_id,
                    created_obs.get("tags", []) or [],
                    verdict=result["verdict"],
                    confidence=result["confidence"],
                )

        except Exception as e:
            logger.exception(f"Observable create/analyze failed for {obs}")
            observable_results.append({
                "observable_id": None,
                "dataType": obs.get("dataType"),
                "data": obs.get("data"),
                "verdict": "Suspicious",
                "confidence": 0,
                "summary": "Observable creation or analysis failed.",
                "why": str(e),
                "reports": [],
            })

    final_result = aggregate_alert_verdict(observable_results)
    final_verdict = final_result["verdict"]
    final_confidence = int(final_result["confidence"])

    should_promote = final_verdict == "TruePositive" and final_confidence >= CONFIDENCE_THRESHOLD

    try:
        alert_summary = ask_gemini_for_alert_summary(
            w_alert,
            observable_results,
            final_result,
            should_promote,
        )
    except Exception as e:
        logger.error(f"Failed to generate LLM alert summary: {e}")
        alert_summary = (
            f"Final verdict: {final_result['verdict']} ({final_result['confidence']}%). "
            f"{final_result['summary']} "
            f"Promotion decision: {'Promoted to case' if should_promote else 'Not promoted to case'}."
        )[:4000]

    update_alert_summary(alert_id, alert_summary)

    add_alert_comment(
        alert_id,
        build_alert_llm_comment(
            alert_id,
            alert_title,
            observable_results,
            final_result,
            should_promote,
        ),
    )

    update_alert_status(alert_id, ALERT_STATUS_MAP.get(final_verdict, "New"))
    update_alert_tags(alert_id, existing_tags, final_verdict, final_confidence)

    if should_promote:
        promoted_case = promote_alert_to_case(thive_api, alert_id)
        if promoted_case:
            case_id = get_obj_id(promoted_case)
            if case_id:
                try:
                    case_summary = ask_gemini_for_alert_summary(
                        w_alert,
                        observable_results,
                        final_result,
                        True,
                    )
                except Exception as e:
                    logger.error(f"Failed to generate LLM case summary: {e}")
                    case_summary = (
                        f"LLM promoted this alert to a case. "
                        f"Verdict: {final_verdict} ({final_confidence}%). "
                        f"Reason: {normalize_text(final_result['summary'])}"
                    )[:4000]

                update_case_summary(case_id, case_summary)
                update_case_status(case_id, verdict_to_case_status(final_verdict))
                add_case_comment(
                    case_id,
                    (
                        "### Alert Promoted By LLM Triage\n\n"
                        f"**Source Alert ID:** {alert_id}\n"
                        f"**Final Alert Verdict:** {final_verdict}\n"
                        f"**Confidence:** {final_confidence}%\n"
                        f"**Promotion Decision:** Promoted to case\n"
                        f"**Reason:** {final_result['why']}\n"
                    ),
                )

# ========================
# ENTRYPOINT
# ========================
def main(args):
    global THEHIVE_URL, THEHIVE_API_KEY, HEADERS

    logger.debug("#start main")

    if len(args) < 4:
        logger.error("Usage: python script.py alert.json API_KEY THEHIVE_URL")
        sys.exit(1)

    alert_file_location = args[1]
    THEHIVE_API_KEY = args[2]
    THEHIVE_URL = args[3].rstrip("/")

    HEADERS = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    with open(alert_file_location, "r", encoding="utf-8") as f:
        w_alert = json.load(f)

    if w_alert.get("rule", {}).get("groups", []) == ["ids", "suricata"]:
        if int(w_alert.get("data", {}).get("alert", {}).get("severity", 0)) < suricata_lvl_threshold:
            logger.info("Suricata alert below threshold")
            return
    elif int(w_alert.get("rule", {}).get("level", 0)) < lvl_threshold:
        logger.info("Alert below threshold")
        return

    alt = pr(w_alert, "", [])
    format_alt = md_format(alt)
    observables_payload = artifact_detect(format_alt)
    logger.info(f"Detected observables: {observables_payload}")

    alert = generate_alert(format_alt, w_alert)
    thive_api = TheHiveApi(THEHIVE_URL, THEHIVE_API_KEY)

    send_and_analyze_alert(alert, thive_api, observables_payload, w_alert)

if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception:
        logger.exception("Unexpected error")
        raise
