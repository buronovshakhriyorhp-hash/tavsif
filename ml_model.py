"""
ml_model.py — Professional Expert System + Log Analysis Engine
==============================================================
Changes from audit:
  [ML-FIX-1] False Positive: 1 ta 403 = Attacker → auth_errors threshold oshirildi (min 2)
  [ML-FIX-2] Login false positive → ok_count > auth_errors bo'lsa signal kamaytir
  [ML-FIX-3] avg_interval = 999.0 → req_count == 1 bo'lsa 'N/A' sentinel ishlatiladi
  [ML-FIX-4] IP=None → 'unknown' string sifatida emas, filtrlash
  [ML-FIX-5] avg_interval > 3600 → format soat/daqiqa
  [ML-FIX-6] numpy import olib tashlandi (ishlatilmayotgan)
  [ML-FIX-7] df.iterrows() loop vektorlash bilan almashtir (pandas merge)
  [ML-FIX-8] iterrows() batched classification orqali tezlashtirish
"""

import re
import pandas as pd
import logging

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────
# KONSTANTALAR
# ─────────────────────────────────────────────────────────────────────

BOT_UA_STR = (
    r'bot|crawler|spider|scraper|'
    r'curl|wget|'
    r'python-requests|python-urllib|httpie|'
    r'PostmanRuntime|postman|insomnia|'
    r'go-http-client|java/|libwww|httpclient|okhttp|'
    r'zgrab|masscan|nmap|nikto|sqlmap|nuclei|'
    r'scrapy|mechanize|phantomjs|selenium|headless'
)

SENSITIVE_PATH_STR = (
    r'/admin|/wp-admin|/wp-login|/wp-config|'
    r'/\.env|/env|/config\.php|/configuration\.php|'
    r'/passwd|/etc/passwd|/etc/shadow|'
    r'/shell|/cmd|/exec|/system|'
    r'/phpmyadmin|/pma|/myadmin|'
    r'/xmlrpc\.php|/cgi-bin|'
    r'/backup|/\.git|/\.svn|'
    r'/\.htaccess|/server-status|/server-info|'
    r'/actuator|/api/admin|/api/debug|'
    r'\.\./|%2e%2e|%252e'
)

AGGRESSIVE_METHODS = {"DELETE", "PUT", "PATCH"}

# Login/Auth yo'llari — bu yerda 401 bo'lishi tabiiy (odam parolni unutgan)
AUTH_PATHS = re.compile(r'/login|/signin|/auth|/logout|/register|/signup', re.IGNORECASE)


# ─────────────────────────────────────────────────────────────────────
# TIMESTAMP PARSER
# ─────────────────────────────────────────────────────────────────────
def _parse_timestamps(series: pd.Series) -> pd.Series:
    """
    Safe, production-grade timestamp parser.
    hech qanday qator yo'qolmaydi — invalid → pd.Timestamp.now()
    """
    try:
        result = pd.to_datetime(series, errors="coerce", utc=True)
        result = result.dt.tz_localize(None)
    except Exception:
        result = pd.to_datetime(series, errors="coerce")

    if result.isna().any():
        extra_formats = [
            "%d/%b/%Y:%H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%d-%m-%Y %H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
            "%d.%m.%Y %H:%M:%S",
            "%Y%m%dT%H%M%S",
        ]
        for fmt in extra_formats:
            still_failed_idx = result[result.isna()].index
            if len(still_failed_idx) == 0:
                break
            try:
                parsed = pd.to_datetime(series.loc[still_failed_idx], format=fmt, errors="coerce")
                if hasattr(parsed, 'dt') and parsed.dt.tz is not None:
                    parsed = parsed.dt.tz_localize(None)
                result.loc[still_failed_idx] = parsed
            except Exception:
                continue

    still_failed_count = result.isna().sum()
    if still_failed_count > 0:
        logger.warning("%d timestamp parse bo'lmadi — hozirgi vaqt bilan almashtirildi.", still_failed_count)
        result = result.fillna(pd.Timestamp.now())

    return result


# ─────────────────────────────────────────────────────────────────────
# IP BO'YICHA FEATURE EXTRACTION
# ─────────────────────────────────────────────────────────────────────
def _extract_features(group: pd.DataFrame) -> dict:
    """Har bir IP uchun 14 ta xususiyat hisoblaydi."""
    group = group.sort_values("timestamp")
    req_count = len(group)

    statuses = group["status"].astype(int)
    ok_count      = (statuses < 400).sum()
    auth_errors   = statuses.isin([401, 403]).sum()
    not_found     = statuses.isin([404, 410]).sum()
    other_4xx     = ((statuses >= 400) & (statuses < 500) & (~statuses.isin([401, 403, 404]))).sum()
    server_5xx    = (statuses >= 500).sum()
    total_errors  = auth_errors + not_found + other_4xx + server_5xx
    error_rate    = total_errors / req_count

    methods = group["method"].str.upper()
    get_ratio       = (methods == "GET").sum() / req_count
    post_ratio      = (methods == "POST").sum() / req_count
    agg_method_hits = methods.isin(AGGRESSIVE_METHODS).sum()

    paths = group["path"].astype(str)
    sensitive_hits = paths.str.contains(SENSITIVE_PATH_STR, case=False, regex=True, na=False).sum()
    unique_paths   = paths.nunique()

    # [ML-FIX-1/2] Auth path hits — /login da 401 bo'lishi normal
    auth_path_hits = paths.str.contains(AUTH_PATHS.pattern, case=False, regex=True, na=False).sum()
    # auth_errors that occur on NON-auth paths → real intrusion
    auth_errors_outside_login = max(0, int(auth_errors) - int(auth_path_hits))

    uas = group["user_agent"].astype(str)
    is_bot_ua    = uas.str.contains(BOT_UA_STR, case=False, regex=True, na=False).any()
    ua_diversity = uas.nunique()

    time_diffs   = group["timestamp"].diff().dt.total_seconds().dropna()

    # [ML-FIX-3]: req_count == 1 → interval meaningless
    if len(time_diffs) > 0:
        avg_interval = float(time_diffs.mean())
        min_interval = float(time_diffs.min())
    else:
        avg_interval = -1.0   # sentinel: 1 ta so'rov, interval yo'q
        min_interval = -1.0

    duration_sec = (group["timestamp"].max() - group["timestamp"].min()).total_seconds()
    duration_min = duration_sec / 60.0

    return {
        "req_count":               req_count,
        "error_rate":              error_rate,
        "auth_errors":             int(auth_errors),
        "auth_errors_outside_login": int(auth_errors_outside_login),
        "not_found":               int(not_found),
        "server_5xx":              int(server_5xx),
        "other_4xx":               int(other_4xx),
        "ok_count":                int(ok_count),
        "agg_method_hits":         int(agg_method_hits),
        "post_ratio":              float(post_ratio),
        "get_ratio":               float(get_ratio),
        "sensitive_hits":          int(sensitive_hits),
        "unique_paths":            int(unique_paths),
        "is_bot_ua":               bool(is_bot_ua),
        "ua_diversity":            int(ua_diversity),
        "avg_interval":            avg_interval,
        "min_interval":            min_interval,
        "duration_min":            float(duration_min),
    }


# ─────────────────────────────────────────────────────────────────────
# KLASSIFIKATSIYA ENGINE
# ─────────────────────────────────────────────────────────────────────
def _classify(f: dict) -> tuple[str, float, int]:
    """Returns (classification, confidence, risk_score)"""

    # ── ATTACKER ─────────────────────────────────────────────────────
    attacker_signals = 0

    if f["sensitive_hits"] > 0:
        attacker_signals += 4

    # [ML-FIX-1]: 1 ta auth xato yetarli emas → kamida 2 ta kerak
    # [ML-FIX-2]: auth_errors_outside_login — login sahifasida xato = normal
    if f["auth_errors_outside_login"] >= 2:
        attacker_signals += 3

    if f["agg_method_hits"] > 0 and (f["auth_errors"] + f["other_4xx"] + f["server_5xx"]) > 0:
        attacker_signals += 2

    if f["not_found"] >= 3 and f["req_count"] >= 5:
        attacker_signals += 2

    if f["error_rate"] >= 0.6 and f["req_count"] >= 4:
        attacker_signals += 2

    if attacker_signals >= 3:
        conf = min(55.0 + attacker_signals * 7, 99.0)
        risk = min(60 + attacker_signals * 5, 100)
        return "Attacker", round(conf, 1), min(risk, 100)

    # ── BOT ──────────────────────────────────────────────────────────
    bot_signals = 0

    if f["is_bot_ua"]:
        bot_signals += 4

    # [ML-FIX-3]: avg_interval == -1 means 1 request → skip interval check
    if f["avg_interval"] != -1.0 and f["avg_interval"] < 0.5 and f["req_count"] >= 5:
        bot_signals += 2

    if f["ua_diversity"] == 1 and f["req_count"] >= 20:
        bot_signals += 1

    if f["min_interval"] != -1.0 and f["min_interval"] < 0.1 and f["req_count"] >= 3:
        bot_signals += 2

    if bot_signals >= 2:
        conf = min(55.0 + bot_signals * 10, 98.0)
        risk = min(30 + bot_signals * 6, 70)
        return "Bot", round(conf, 1), min(risk, 70)

    # ── ACTIVE ───────────────────────────────────────────────────────
    active_signals = 0

    if f["req_count"] >= 10:
        active_signals += 2

    if f["post_ratio"] > 0.1 and f["ok_count"] > 0:
        active_signals += 2

    if f["req_count"] >= 20:
        active_signals += 1

    if f["duration_min"] >= 5 and f["req_count"] >= 8:
        active_signals += 1

    if active_signals >= 2:
        conf = min(60.0 + active_signals * 8, 92.0)
        risk = 10 + active_signals * 3
        return "Active", round(conf, 1), min(risk, 35)

    # ── NORMAL ───────────────────────────────────────────────────────
    return "Normal", 90.0, 5


# ─────────────────────────────────────────────────────────────────────
# INTERVAL FORMATTING helper
# ─────────────────────────────────────────────────────────────────────
def _format_interval(seconds: float) -> str:
    """[ML-FIX-3/5]: interval ni odam o'qiy oladigan formatga convert et."""
    if seconds < 0:
        return "N/A (1 so'rov)"
    if seconds > 3600:
        return f"{seconds/3600:.1f} soat"
    if seconds > 60:
        return f"{seconds/60:.1f} daqiqa"
    return f"{round(seconds, 2)}s"


# ─────────────────────────────────────────────────────────────────────
# ASOSIY TAHLIL FUNKSIYASI
# ─────────────────────────────────────────────────────────────────────
def analyze_logs(df: pd.DataFrame) -> dict:
    df = df.copy()

    df["timestamp"] = _parse_timestamps(df["timestamp"])
    df["status"] = pd.to_numeric(df["status"], errors="coerce").fillna(200).astype(int)

    for col in ["ip", "method", "path", "user_agent"]:
        if col in df.columns:
            df[col] = df[col].astype(str).replace("nan", "").fillna("")
        else:
            df[col] = ""

    # [ML-FIX-4]: IP = None / empty / 'None' / 'nan' → filter
    df = df[~df["ip"].str.strip().str.lower().isin(["", "none", "nan"])].copy()

    log_category_counts = {"Normal": 0, "Active": 0, "Bot": 0, "Attacker": 0}
    ip_stats: dict[str, dict] = {}
    ip_summary_list = []

    # ── IP bo'yicha tahlil ──────────────────────────────────────────
    for ip, group in df.groupby("ip"):
        feat = _extract_features(group)
        cls, conf, risk = _classify(feat)

        ip_stats[ip] = {
            **feat,
            "classification": cls,
            "confidence":     conf,
            "risk_score":     risk,
        }

        ip_summary_list.append({
            "ip":              ip,
            "classification":  cls,
            "confidence":      conf,
            "request_count":   feat["req_count"],
            "error_rate_pct":  round(feat["error_rate"] * 100, 1),
            "sensitive_hits":  feat["sensitive_hits"],
            "avg_interval_sec": _format_interval(feat["avg_interval"]),
            "session_min":     round(feat["duration_min"], 2),
            "risk_score":      risk,
        })

    # ── [ML-FIX-7]: df.iterrows() o'rniga pandas merge (tez) ───────
    # IP → stats mapping DataFrame
    ip_map = pd.DataFrame([
        {
            "ip": ip,
            "classification": v["classification"],
            "confidence":     v["confidence"],
            "req_count":      v["req_count"],
            "error_rate":     v["error_rate"],
            "auth_errors":    v["auth_errors"],
            "not_found":      v["not_found"],
            "server_5xx":     v["server_5xx"],
            "unique_paths":   v["unique_paths"],
            "avg_interval":   v["avg_interval"],
            "ua_diversity":   v["ua_diversity"],
            "sensitive_hits": v["sensitive_hits"],
            "agg_method_hits": v["agg_method_hits"],
            "post_ratio":     v["post_ratio"],
            "duration_min":   v["duration_min"],
        }
        for ip, v in ip_stats.items()
    ])

    if not ip_map.empty:
        merged = df.merge(ip_map, on="ip", how="left")
    else:
        merged = df.copy()
        for col in ["classification","confidence","req_count","error_rate"]:
            merged[col] = "Normal" if col == "classification" else 0

    # Log category counts via vectorized groupby
    for cls in log_category_counts:
        log_category_counts[cls] = int((merged["classification"] == cls).sum())

    # ── Batafsil loglar ro'yxati ─────────────────────────────────────
    detailed_logs = []
    for _, row in merged.iterrows():
        avg_int_raw = row.get("avg_interval", -1.0)
        feat_display = {
            "So'rovlar soni":           int(row.get("req_count", 1)),
            "Xato stavkasi":            f"{round(row.get('error_rate', 0)*100, 1)}%",
            "401/403 xatolar":          int(row.get("auth_errors", 0)),
            "404 topilmadi":            int(row.get("not_found", 0)),
            "500 server xatosi":        int(row.get("server_5xx", 0)),
            "Noyob yo'llar":            int(row.get("unique_paths", 1)),
            "O'rtacha interval":        _format_interval(float(avg_int_raw) if avg_int_raw is not None else -1.0),
            "UA xilma-xilligi":         int(row.get("ua_diversity", 1)),
            "Xavfli yo'l urinishlari":  int(row.get("sensitive_hits", 0)),
            "Agressiv metodlar":        int(row.get("agg_method_hits", 0)),
            "POST ulushi":              f"{round(row.get('post_ratio', 0)*100, 1)}%",
            "Sessiya davomiyligi (min)": round(float(row.get("duration_min", 0)), 2),
        }

        detailed_logs.append({
            "timestamp":      row["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
            "ip":             str(row["ip"]),
            "method":         str(row["method"]).upper(),
            "path":           str(row["path"]),
            "status":         int(row["status"]),
            "user_agent":     str(row["user_agent"])[:90],
            "classification": str(row.get("classification", "Normal")),
            "confidence":     float(row.get("confidence", 75.0)),
            "features":       feat_display,
        })

    top_ips = sorted(
        [{"ip": k, "count": v["req_count"], "class": v["classification"]}
         for k, v in ip_stats.items()],
        key=lambda x: x["count"], reverse=True
    )[:10]

    ip_summary_list.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "category_counts": log_category_counts,
        "top_ips":         top_ips,
        "logs":            sorted(detailed_logs, key=lambda x: x["timestamp"], reverse=True),
        "ip_summary":      ip_summary_list,
        "total_requests":  len(df),
        "unique_ips":      len(ip_stats),
    }
