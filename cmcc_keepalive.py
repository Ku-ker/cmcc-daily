#!/usr/bin/env python3
"""中国移动统一认证会话保活（keepalive）。

背景
----
`appTokenLogin` 的 `token` 字段是一个统一认证会话 cookie，空闲一段时间就会被服务端
回收；而主签到脚本一天只跑一次，两次运行之间会话早已失效，只能重新抓包。
本脚本高频（建议 15 分钟）发起一次 auth 兑换，让统一认证会话保持活跃、jwt 始终最新。
只做 auth，不签到、不领奖、不碰任何业务接口。

独立运行（cron）::

    python cmcc_keepalive.py --config config.json
    */15 * * * *  python cmcc_keepalive.py --config /path/to/config.json

Web 应用（cmcc_app）也会复用本模块的 keepalive() 做后台保活。

行为
----
- 三档凭证（jwt+app_token / jwt 单独 / 纯 app_token）依次尝试，命中即止；
- 上游偶发返回裸 JSON 字符串（非对象）时不算凭证失效，换下一档继续试；
- 成功：静默（--verbose 可看到命中的档位）；
- 全部失败：推送通知（沿用配置里的 Bark / Server酱 / Webhook）并返回退出码 1，
  这是唯一需要人重新抓包的场景。
"""

from __future__ import annotations

import argparse
import logging
import random
import re
import sys

import cmcc_sign as cs

log = logging.getLogger("cmcc_keepalive")


def new_session():
    s = cs.requests.Session()
    # 直连：不继承系统/环境变量代理，避免本机抓包工具的 MITM 证书干扰 SSL 验证
    s.trust_env = False
    s.mount("https://", cs.LegacyTLSAdapter())
    s.headers.update({"user-agent": cs.USER_AGENT, "accept-language": "zh-CN,zh-Hans;q=0.9"})
    return s


def keepalive(cfg, verbose: bool = False) -> tuple[bool, str]:
    """发一次 auth 兑换保持会话活跃，返回 (是否成功, 命中的档位/失败原因)。

    cfg 只要求具备 act_url/phone/province_code/city_code/carrier_operator/
    app_version_code/app_token 属性（cmcc_sign.Config 或等价对象均可）。
    成功时会用响应里的最新 jwt 回写缓存。
    """
    s = new_session()
    r = s.get(cs.SSO_LOGIN, params={"dlwmh": "true", "actUrl": cfg.act_url}, timeout=30)
    r.raise_for_status()
    m = re.search(r"loginPath\s*=\s*'([^']+)'", r.text)
    if not m:
        return False, "登录页未返回 sid（SSO 入口可能已变更）"
    login_url = cs.BASE + "/qwhdsso" + m.group(1)

    body = {
        "provinceCode": cfg.province_code,
        "cityCode": cfg.city_code,
        "userCheckId": format(int(cfg.phone), "x"),
        "carrierOperator": cfg.carrier_operator,
        "appVersionCode": cfg.app_version_code,
        "took": random.randint(120, 900),
    }

    attempts: list[tuple[str, str | None]] = []
    cached = cs.load_jwt_cache(cfg)
    if cached:
        attempts.append(("jwt+app_token", cached[0]))
        attempts.append(("jwt 单独", cached[0]))
    attempts.append(("app_token 引导", None))

    last_err = ""
    for label, jwt_str in attempts:
        token = cfg.app_token if label != "jwt 单独" else ""
        payload = {**body, "jwtToken": jwt_str, "token": token}
        try:
            r = s.post(login_url, json=payload, timeout=30)
            cand = r.json()
        except Exception as e:  # 网络/解析异常：换下一档
            last_err = f"{label}: {type(e).__name__}: {e}"
            if verbose:
                log.warning("保活尝试失败 %s", last_err)
            continue
        # 上游偶发返回裸 JSON 字符串（非对象），此时不能按 code 判定，
        # 也不算凭证失效——换下一档继续试。
        if not isinstance(cand, dict):
            last_err = f"{label}: 响应非对象 {type(cand).__name__} {str(cand)[:120]!r}"
            if verbose:
                log.warning("保活尝试响应非对象 %s", last_err)
            continue
        if cand.get("code") == "SUCCESS":
            data = cand.get("data")
            data = data if isinstance(data, dict) else {}
            cs.save_jwt_cache(cfg, data.get("jwt"))
            return True, label
        last_err = f"{label}: {cand.get('code')} {cand.get('msg')}"
        if verbose:
            log.info("保活尝试未通过 %s", last_err)

    return False, last_err


def main() -> int:
    parser = argparse.ArgumentParser(description="中国移动统一认证会话保活")
    parser.add_argument("--config", default="config.json", help="配置文件路径（默认 config.json）")
    parser.add_argument("--verbose", action="store_true", help="输出命中的保活档位等细节")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    cfg = cs.Config(args.config)
    err = cfg.validate()
    if err:
        log.error("配置不完整: %s", err)
        return 1

    try:
        ok, detail = keepalive(cfg, verbose=args.verbose)
    except Exception as e:
        ok, detail = False, f"{type(e).__name__}: {e}"

    if ok:
        if args.verbose:
            log.info("保活成功（%s）", detail)
        print("keepalive ok")
        return 0

    log.error("保活失败：三档凭证全部被拒 —— %s", detail)
    try:
        cs.notify(cfg, "中国移动凭证已失效",
                  f"保活失败：{detail}\n需要在 App 内重新抓包更新 config.json 的 app_token")
    except Exception as e:
        log.warning("通知推送失败: %s", e)
    return 1


if __name__ == "__main__":
    sys.exit(main())
