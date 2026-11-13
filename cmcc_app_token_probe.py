#!/usr/bin/env python3
"""app_token 单独存活探针（独立于主签到/保活流程）。

背景
----
服务端「jwt 单独续期」的口子会开开关关，而主保活第一档是「jwt+app_token」，
口子开着时第一档必然成功，永远走不到纯 app_token 档，于是测不出 app_token
自身什么时候死。而「app_token 是空闲超时还是绝对过期」直接决定保活间隔
该设 15 分钟还是 2 小时。

本脚本补上这一侧：**只发纯 app_token，完全不带 jwt（jwtToken 置空）**，
独立记录每次结果。它不参与主保活、不影响保活成功率，只是旁路采集数据。

用法（cron）::

    python cmcc_app_token_probe.py --config config.json
    0 * * * *  python cmcc_app_token_probe.py --config /path/to/config.json

输出
----
- 结果 append 到 `$CMCC_DATA_DIR/.cmcc_app_token_probe.jsonl`（每行一条 JSON，
  已 gitignore；未设置 CMCC_DATA_DIR 时落在当前目录）
- 成功：静默
- 连续失败 3 次：推送通知，因为通常意味着 app_token 真的到期了，需要在 App 内重新抓包
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import re
import sys
import time
from pathlib import Path

import cmcc_keepalive as cs_keepalive
import cmcc_sign as cs

log = logging.getLogger("cmcc_app_token_probe")

FAIL_ALERT_THRESHOLD = 3


def probe_log_path() -> Path:
    data_dir = os.environ.get("CMCC_DATA_DIR")
    return Path(data_dir) if data_dir else Path.cwd()


def _probe(cfg) -> dict:
    """发一次纯 app_token 请求（jwtToken 置空），返回结果字典。"""
    s = cs_keepalive.new_session()
    r = s.get(cs.SSO_LOGIN, params={"dlwmh": "true", "actUrl": cfg.act_url}, timeout=30)
    r.raise_for_status()
    m = re.search(r"loginPath\s*=\s*'([^']+)'", r.text)
    if not m:
        return {"ok": False, "err": "SSO 入口未返回 loginPath（入口可能已变更）"}
    login_url = cs.BASE + "/qwhdsso" + m.group(1)
    sid = m.group(1)

    body = {
        "provinceCode": cfg.province_code,
        "cityCode": cfg.city_code,
        "userCheckId": format(int(cfg.phone), "x"),
        "carrierOperator": cfg.carrier_operator,
        "appVersionCode": cfg.app_version_code,
        "took": random.randint(120, 900),
    }
    # 关键：jwtToken 置空、token 只带 app_token —— 测的是 app_token 自身
    payload = {**body, "jwtToken": "", "token": cfg.app_token}

    r = s.post(login_url, json=payload, timeout=30)
    try:
        cand = r.json()
    except ValueError:
        return {"ok": False, "err": f"响应非 JSON (HTTP {r.status_code})", "sid": sid}

    if not isinstance(cand, dict):
        return {"ok": False, "err": f"响应非对象 {type(cand).__name__}", "sid": sid,
                "raw": str(cand)[:160]}

    out = {"ok": cand.get("code") == "SUCCESS", "code": cand.get("code"),
           "msg": (cand.get("msg") or "")[:160], "sid": sid}
    d = cand.get("data")
    out["jwt_issued"] = bool(d.get("jwt")) if isinstance(d, dict) else False
    return out


def _read_history(limit: int = 200) -> list[dict]:
    path = probe_log_path() / ".cmcc_app_token_probe.jsonl"
    if not path.exists():
        return []
    rows: list[dict] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    except OSError:
        return []
    return rows[-limit:]


def _consecutive_failures() -> int:
    n = 0
    for row in reversed(_read_history()):
        if row.get("ok"):
            break
        n += 1
    return n


def _notify(cfg, text: str) -> None:
    """复用 cmcc_sign.notify（自带 URL 校验与异常兜底）。失败不影响脚本退出码。"""
    try:
        cs.notify(cfg, "中国移动 app_token 探针", text)
    except Exception as e:
        log.warning("推送失败: %s", e)


def main() -> int:
    parser = argparse.ArgumentParser(description="app_token 单独存活探针（旁路诊断工具）")
    parser.add_argument("--config", default="config.json", help="配置文件路径（默认 config.json）")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    cfg = cs.Config(args.config)
    err = cfg.validate()
    if err:
        log.error("配置不完整: %s", err)
        return 1

    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        res = _probe(cfg)
    except Exception as e:
        res = {"ok": False, "err": f"{type(e).__name__}: {e}"}

    cached = cs.load_jwt_cache(cfg)
    chain = round((time.time() - cached[1]) / 86400, 2) if cached else None

    row = {"ts": ts, "mode": "app_token_only", "chain_days": chain, **res}
    with (probe_log_path() / ".cmcc_app_token_probe.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")

    if res.get("ok"):
        return 0  # 成功时静默，避免每小时刷屏

    fails = _consecutive_failures()
    log.warning("app_token 单独探测失败(%s) 连续第 %d 次: %s",
                ts, fails, res.get("msg") or res.get("err"))
    if fails >= FAIL_ALERT_THRESHOLD:
        _notify(cfg, f"app_token 单独探测连续 {fails} 次失败，疑似已到期。\n"
                     f"最后一次: {res.get('msg') or res.get('err')}\n"
                     f"请在 App 内重新抓包更新 config.json 的 app_token。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
