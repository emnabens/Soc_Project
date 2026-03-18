#!/usr/bin/env python3
import os
import time
import json
import requests
from typing import Any, Dict, List, Optional, Tuple

# =========================
# CONFIGURATION
# =========================
BASE_URL = os.getenv("THEHIVE_URL", "http://thehive:9000/thehive").rstrip("/")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY")
CORTEX_NAME = os.getenv("CORTEX_NAME", "cortex_server")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
JOB_POLL_INTERVAL = int(os.getenv("JOB_POLL_INTERVAL", "8"))
JOB_POLL_MAX_ROUNDS = int(os.getenv("JOB_POLL_MAX_ROUNDS", "30"))

CASE_RESOLUTION_RETRIES = int(os.getenv("CASE_RESOLUTION_RETRIES", "3"))
CASE_RESOLUTION_DELAY = int(os.getenv("CASE_RESOLUTION_DELAY", "3"))

CONFIDENCE_THRESHOLD = int(os.getenv("CONFIDENCE_THRESHOLD", "70"))
RECENT_CASE_LOOKBACK = int(os.getenv("RECENT_CASE_LOOKBACK", "100"))
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"

if not THEHIVE_API_KEY:
    raise RuntimeError("Missing THEHIVE_API_KEY environment variable")

if not GEMINI_API_KEY:
    raise RuntimeError("Missing GEMINI_API_KEY environment variable")

HEADERS = {
    "Authorization": f"Bearer {THEHIVE_API_KEY}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

FINAL_JOB_STATUSES = {"success", "failure", "deleted", "cancelled"}

ALLOWED_CASE_STATUSES = {
    "New",
    "InProgress",
    "TruePositive",
    "FalsePositive",
    "Indeterminate",
    "Duplicated",
    "Other",
}

ANALYZERS = {
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

DEFAULT_ANALYZERS = ["MISP_2_1"]

# case status priority: higher wins, prevents bad downgrades
CASE_STATUS_PRIORITY = {
    "New": 0,
    "InProgress": 1,
    "FalsePositive": 2,
    "Indeterminate": 3,
    "TruePositive": 4,
    "Other": 1,
    "Duplicated": 5,
}

CASE_MAP_CACHE: Dict[str, str] = {}


# =========================
# UTIL
# =========================
def log(msg: str) -> None:
    print(msg, flush=True)


def api_url(path: str) -> str:
    return f"{BASE_URL}/{path.lstrip('/')}"


def safe_json(res: Optional[requests.Response], default: Any) -> Any:
    if not res:
        return default
    try:
        return res.json()
    except Exception:
        return default


def trim_json(value: Any, max_len: int = 12000) -> str:
    try:
        text = json.dumps(value, ensure_ascii=False, indent=2, default=str)
    except Exception:
        text = str(value)
    return text[:max_len]


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).lower()


def get_analyzers(data_type: Optional[str]) -> List[str]:
    if not data_type:
        return DEFAULT_ANALYZERS
    return ANALYZERS.get(str(data_type).lower(), DEFAULT_ANALYZERS)


def verdict_to_case_status(verdict: str) -> str:
    if verdict == "TruePositive":
        return "TruePositive"
    if verdict == "FalsePositive":
        return "FalsePositive"
    return "Indeterminate"


def should_update_case_status(current_status: str, new_status: str) -> bool:
    if new_status not in CASE_STATUS_PRIORITY:
        return False
    if current_status not in CASE_STATUS_PRIORITY:
        return True
    return CASE_STATUS_PRIORITY[new_status] > CASE_STATUS_PRIORITY[current_status]


# =========================
# HTTP
# =========================
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
            if method == "GET":
                res = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
            elif method == "POST":
                res = requests.post(url, headers=HEADERS, json=payload, timeout=REQUEST_TIMEOUT)
            elif method == "PATCH":
                res = requests.patch(url, headers=HEADERS, json=payload, timeout=REQUEST_TIMEOUT)
            else:
                raise ValueError(f"Unsupported method: {method}")

            if res.status_code in expected:
                return res, path

            last_error = f"{path} -> HTTP {res.status_code}: {res.text[:500]}"
        except Exception as e:
            last_error = f"{path} -> {e}"

    return None, last_error


def get_json(paths: List[str], *, expected: Tuple[int, ...] = (200,)) -> Dict[str, Any]:
    res, err = request_any("GET", paths, expected=expected)
    if not res:
        raise RuntimeError(err)
    data = safe_json(res, {})
    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected JSON shape from {paths}: {type(data).__name__}")
    return data


def get_json_list(paths: List[str], *, expected: Tuple[int, ...] = (200,)) -> List[Dict[str, Any]]:
    res, err = request_any("GET", paths, expected=expected)
    if not res:
        raise RuntimeError(err)
    data = safe_json(res, [])
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    raise RuntimeError(f"Unexpected JSON list shape from {paths}: {type(data).__name__}")


def post_json(paths: List[str], payload: Dict[str, Any], *, expected: Tuple[int, ...] = (200, 201)) -> Dict[str, Any]:
    res, err = request_any("POST", paths, payload=payload, expected=expected)
    if not res:
        raise RuntimeError(err)
    data = safe_json(res, {})
    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected JSON shape from {paths}: {type(data).__name__}")
    return data


def post_list(paths: List[str], payload: Dict[str, Any], *, expected: Tuple[int, ...] = (200,)) -> List[Dict[str, Any]]:
    res, err = request_any("POST", paths, payload=payload, expected=expected)
    if not res:
        raise RuntimeError(err)
    data = safe_json(res, [])
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        return [x for x in data["data"] if isinstance(x, dict)]
    raise RuntimeError(f"Unexpected JSON list shape from {paths}: {type(data).__name__}")


def patch_ok(paths: List[str], payload: Dict[str, Any], *, expected: Tuple[int, ...] = (200, 201, 204)) -> bool:
    if DRY_RUN:
        log(f"[DRY_RUN] PATCH {paths[0]} payload={trim_json(payload, 800)}")
        return True

    res, err = request_any("PATCH", paths, payload=payload, expected=expected)
    if not res:
        log(f"[!] PATCH failed: {err}")
        return False
    return True


# =========================
# THEHIVE OBJECTS
# =========================
def search_observables_with_tag(tag: str = "to-analyze") -> List[Dict[str, Any]]:
    query = {
        "query": {
            "_and": [
                {"_field": "tags", "_value": tag}
            ]
        }
    }
    return post_list(
        ["/api/case/artifact/_search"],
        query,
        expected=(200,)
    )


def get_observable_details(obs_id: str) -> Dict[str, Any]:
    return get_json([
        f"/api/v1/observable/{obs_id}",
        f"/api/case/artifact/{obs_id}",
    ])


def get_case_details(case_id: str) -> Dict[str, Any]:
    return get_json([
        f"/api/v1/case/{case_id}",
        f"/api/case/{case_id}",
    ])


def get_alert_details(alert_id: str) -> Dict[str, Any]:
    return get_json([
        f"/api/v1/alert/{alert_id}",
        f"/api/alert/{alert_id}",
    ])


def add_case_comment(case_id: str, message: str) -> bool:
    if DRY_RUN:
        log(f"[DRY_RUN] Would add comment to case {case_id}")
        return True

    payload = {"message": message}
    res, err = request_any(
        "POST",
        [f"/api/v1/case/{case_id}/comment", f"/api/case/{case_id}/comment"],
        payload=payload,
        expected=(200, 201),
    )
    if not res:
        log(f"[!] Failed to add case comment for {case_id}: {err}")
        return False
    return True


def update_case_status(case_id: str, new_status: str) -> bool:
    if new_status not in ALLOWED_CASE_STATUSES:
        log(f"[!] Unsupported status '{new_status}' for case {case_id}")
        return False

    if DRY_RUN:
        log(f"[DRY_RUN] Would update case {case_id} -> {new_status}")
        return True

    payload = {"status": new_status}
    res, err = request_any(
        "PATCH",
        [f"/api/v1/case/{case_id}", f"/api/case/{case_id}"],
        payload=payload,
        expected=(200, 201, 204),
    )
    if not res:
        log(f"[!] Failed to update case status for {case_id}: {err}")
        return False
    return True


def update_observable_tags(obs_id: str, existing_tags: List[str], verdict: Optional[str] = None, confidence: Optional[int] = None) -> bool:
    tags = [t for t in (existing_tags or []) if t != "to-analyze"]

    for tag in ["auto-dispatched", "llm-reviewed"]:
        if tag not in tags:
            tags.append(tag)

    if verdict:
        verdict_tag = f"llm:{verdict}"
        if verdict_tag not in tags:
            tags.append(verdict_tag)

    if confidence is not None:
        confidence_prefix = "llm-confidence:"
        tags = [t for t in tags if not str(t).startswith(confidence_prefix)]
        tags.append(f"llm-confidence:{confidence}")

    return patch_ok(
        [f"/api/v1/observable/{obs_id}", f"/api/case/artifact/{obs_id}"],
        {"tags": tags},
    )


# =========================
# CASE RESOLUTION
# =========================
def extract_case_id(obj: Dict[str, Any]) -> Optional[str]:
    candidates: List[Optional[str]] = []

    case_val = obj.get("case")
    if isinstance(case_val, dict):
        candidates.extend([case_val.get("id"), case_val.get("_id")])
    elif isinstance(case_val, str):
        candidates.append(case_val)

    parent_val = obj.get("parent")
    if isinstance(parent_val, dict):
        candidates.extend([parent_val.get("id"), parent_val.get("_id"), parent_val.get("caseId")])

    candidates.extend([
        obj.get("caseId"),
        obj.get("_parent"),
        obj.get("_parentId"),
        obj.get("parentId"),
        obj.get("relatedId"),
        obj.get("message"),
    ])

    for value in candidates:
        if isinstance(value, str) and value.startswith("~"):
            return value

    return None


def extract_alert_id(obj: Dict[str, Any]) -> Optional[str]:
    candidates: List[Optional[str]] = []

    alert_val = obj.get("alert")
    if isinstance(alert_val, dict):
        candidates.extend([alert_val.get("id"), alert_val.get("_id")])
    elif isinstance(alert_val, str):
        candidates.append(alert_val)

    candidates.extend([
        obj.get("alertId"),
    ])

    for value in candidates:
        if isinstance(value, str) and value.startswith("~"):
            return value

    return None


def search_recent_cases(limit: int = 50) -> List[Dict[str, Any]]:
    query = {
        "query": {"_and": []},
        "sort": "-createdAt",
        "range": f"0-{max(0, limit - 1)}"
    }
    return post_list(
        ["/api/case/_search"],
        query,
        expected=(200,)
    )


def resolve_case_by_content(obs: Dict[str, Any], recent_cases: List[Dict[str, Any]]) -> Optional[str]:
    obs_data = normalize_text(obs.get("data"))
    obs_type = normalize_text(obs.get("dataType"))

    if not obs_data:
        return None

    matches: List[Tuple[int, Dict[str, Any]]] = []

    for case_obj in recent_cases:
        case_id = case_obj.get("id") or case_obj.get("_id")
        if not case_id:
            continue

        haystack = " ".join([
            normalize_text(case_obj.get("title")),
            normalize_text(case_obj.get("description")),
        ])

        score = 0

        if obs_data in haystack:
            score += 10

        if obs_type == "ip" and "agent.ip" in haystack and obs_data in haystack:
            score += 5
        elif obs_type in {"domain", "url"} and obs_data in haystack:
            score += 4
        elif obs_type in {"file", "filename", "hash", "md5", "sha1", "sha256"} and obs_data in haystack:
            score += 4

        if score > 0:
            matches.append((score, case_obj))

    if not matches:
        return None

    matches.sort(key=lambda x: x[0], reverse=True)
    best_case = matches[0][1]
    return best_case.get("id") or best_case.get("_id")


def resolve_observable_to_case(obs_id: str, search_obs: Optional[Dict[str, Any]] = None) -> Optional[str]:
    if obs_id in CASE_MAP_CACHE:
        return CASE_MAP_CACHE[obs_id]

    full_obs: Dict[str, Any] = {}

    for attempt in range(1, CASE_RESOLUTION_RETRIES + 1):
        try:
            full_obs = get_observable_details(obs_id)
        except Exception as e:
            log(f"[!] Failed to fetch observable {obs_id}: {e}")
            full_obs = {}

        if full_obs:
            case_id = extract_case_id(full_obs)
            if case_id:
                CASE_MAP_CACHE[obs_id] = case_id
                return case_id

            alert_id = extract_alert_id(full_obs)
            if alert_id:
                try:
                    alert = get_alert_details(alert_id)
                    case_id = extract_case_id(alert)
                    if case_id:
                        CASE_MAP_CACHE[obs_id] = case_id
                        return case_id
                except Exception:
                    pass

        if attempt < CASE_RESOLUTION_RETRIES:
            log(f"[!] Observable {obs_id} not directly linked to a case, retry {attempt}/{CASE_RESOLUTION_RETRIES}")
            time.sleep(CASE_RESOLUTION_DELAY)

    try:
        recent_cases = search_recent_cases(limit=RECENT_CASE_LOOKBACK)
    except Exception as e:
        log(f"[!] Failed recent case search for observable {obs_id}: {e}")
        recent_cases = []

    obs_for_match = full_obs or search_obs or {"id": obs_id}
    case_id = resolve_case_by_content(obs_for_match, recent_cases)
    if case_id:
        CASE_MAP_CACHE[obs_id] = case_id
        log(f"[+] Resolved observable {obs_id} to case {case_id} via content match")
        return case_id

    return None


# =========================
# CORTEX JOBS
# =========================
def launch_analyzer(observable_id: str, analyzer: str) -> Optional[str]:
    payload = {
        "analyzerId": analyzer,
        "cortexId": CORTEX_NAME,
        "artifactId": observable_id,
    }

    try:
        data = post_json(
            ["/api/v1/connector/cortex/job", "/api/connector/cortex/job"],
            payload,
            expected=(200, 201),
        )
        return data.get("id")
    except Exception as e:
        log(f"[!] Failed to launch analyzer {analyzer} for observable {observable_id}: {e}")
        return None


def get_job_details(job_id: str) -> Dict[str, Any]:
    return get_json([
        f"/api/v1/connector/cortex/job/{job_id}",
        f"/api/connector/cortex/job/{job_id}",
    ])


def poll_jobs(job_ids: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}

    for _ in range(JOB_POLL_MAX_ROUNDS):
        all_done = True

        for analyzer_name, job_id in job_ids.items():
            existing = results.get(analyzer_name)
            if existing:
                status = str(existing.get("status", "")).lower()
                if status in FINAL_JOB_STATUSES:
                    continue

            try:
                job = get_job_details(job_id)
                results[analyzer_name] = job
                status = str(job.get("status", "")).lower()
                if status not in FINAL_JOB_STATUSES:
                    all_done = False
            except Exception as e:
                log(f"[!] Failed reading job {job_id} ({analyzer_name}): {e}")
                all_done = False

        if all_done:
            return results

        time.sleep(JOB_POLL_INTERVAL)

    return results


def extract_job_report(job: Dict[str, Any]) -> Dict[str, Any]:
    extra_data = job.get("extraData", {})
    report_from_extra = extra_data.get("report", {}) if isinstance(extra_data, dict) else {}

    return {
        "job_id": job.get("id"),
        "analyzer": job.get("analyzerId") or job.get("analyzerName") or job.get("analyzerDefinitionId"),
        "status": job.get("status"),
        "summary": job.get("summary"),
        "taxonomies": job.get("taxonomies", []),
        "operations": job.get("operations", []),
        "report": job.get("report") or job.get("full") or job.get("fullReport") or report_from_extra or {},
        "short_report": job.get("short") or job.get("shortReport") or {},
    }


# =========================
# GEMINI
# =========================
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
{trim_json(observable, 4000)}

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
                    "verdict": {
                        "type": "string",
                        "enum": ["TruePositive", "FalsePositive", "Suspicious"]
                    },
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
        raise RuntimeError(f"Gemini API error {res.status_code}: {res.text[:1000]}")

    data = res.json()
    text = (
        data.get("candidates", [{}])[0]
        .get("content", {})
        .get("parts", [{}])[0]
        .get("text", "")
        .strip()
    )

    if not text:
        raise RuntimeError(f"Gemini returned empty content: {json.dumps(data)[:1000]}")

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


# =========================
# PROCESSING
# =========================
def process_observable(search_obs: Dict[str, Any]) -> None:
    obs_id = search_obs.get("id") or search_obs.get("_id")
    if not obs_id:
        log("[!] Observable without id, skipping")
        return

    log(f"\n[*] Processing observable {obs_id}")

    try:
        obs = get_observable_details(obs_id)
    except Exception as e:
        log(f"[!] Failed to fetch observable details for {obs_id}: {e}")
        obs = dict(search_obs)

    data_type = obs.get("dataType")
    analyzers = get_analyzers(data_type)
    log(f"    [-] dataType={data_type}, analyzers={analyzers}")

    launched_jobs: Dict[str, str] = {}
    for analyzer in analyzers:
        job_id = launch_analyzer(obs_id, analyzer)
        if job_id:
            launched_jobs[analyzer] = job_id
            log(f"        [+] Launched {analyzer} job={job_id}")
        else:
            log(f"        [!] Failed to launch {analyzer}")

    if not launched_jobs:
        log(f"[!] No analyzers launched for observable {obs_id}")
        return

    jobs = poll_jobs(launched_jobs)

    reports: List[Dict[str, Any]] = []
    for analyzer_name, job in jobs.items():
        entry = extract_job_report(job)
        entry["analyzer"] = analyzer_name
        reports.append(entry)

    llm_result = ask_gemini_for_observable_verdict(obs, reports)
    verdict = llm_result["verdict"]
    confidence = llm_result["confidence"]
    proposed_case_status = verdict_to_case_status(verdict)

    log(f"    [+] Gemini verdict: {verdict} ({confidence}%)")
    log(f"    [+] Summary: {llm_result['summary']}")

    case_id = resolve_observable_to_case(obs_id, search_obs=obs)
    if not case_id:
        log(f"[!] Could not resolve parent case for observable {obs_id}")
        tag_ok = update_observable_tags(obs_id, obs.get("tags", []) or [], verdict, confidence)
        log(f"    [+] Observable retagged without case update: {tag_ok}")
        return

    case_data = get_case_details(case_id)
    current_status = str(case_data.get("status", "New"))

    comment = (
        "### LLM Observable Triage Result\n\n"
        f"**Observable ID:** {obs_id}\n"
        f"**Observable Type:** {obs.get('dataType')}\n"
        f"**Observable Data:** `{obs.get('data')}`\n"
        f"**LLM Verdict:** {verdict}\n"
        f"**Proposed Case Status:** {proposed_case_status}\n"
        f"**Confidence:** {confidence}%\n"
        f"**Summary:** {llm_result['summary']}\n\n"
        f"**Why:**\n{llm_result['why']}\n"
    )

    comment_ok = add_case_comment(case_id, comment)
    log(f"    [+] Case comment added to {case_id}: {comment_ok}")

    status_ok = False
    if confidence >= CONFIDENCE_THRESHOLD:
        if should_update_case_status(current_status, proposed_case_status):
            status_ok = update_case_status(case_id, proposed_case_status)
            log(f"    [+] Case status updated {current_status} -> {proposed_case_status}: {status_ok}")
        else:
            log(f"    [-] Case status kept as {current_status}; not downgrading with {proposed_case_status}")
    else:
        log(f"    [-] Confidence below threshold ({CONFIDENCE_THRESHOLD}); case status not changed")

    tag_ok = update_observable_tags(obs_id, obs.get("tags", []) or [], verdict, confidence)
    log(f"    [+] Observable retagged: {tag_ok}")


def run_automation() -> None:
    observables = search_observables_with_tag("to-analyze")
    log(f"Found {len(observables)} observables tagged 'to-analyze'")

    if observables:
        log("Sample observable from search:")
        log(trim_json(observables[0], 1200))

    for obs in observables:
        try:
            process_observable(obs)
        except Exception as e:
            obs_id = obs.get("id") or obs.get("_id")
            log(f"[!] Error while processing observable {obs_id}: {e}")


if __name__ == "__main__":
    try:
        run_automation()
    except Exception as e:
        log(f"[!] Critical Error: {e}")
        raise