import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import cmcc_fee
import cmcc_rate
import cmcc_seckill
import cmcc_sign


class UpstreamAdaptationTests(unittest.TestCase):
    def test_cache_persists_and_full_phone_is_checked(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {"CMCC_DATA_DIR": root}):
            first = SimpleNamespace(phone="13800001234")
            second = SimpleNamespace(phone="13900001234")
            cmcc_sign.save_jwt_cache(first, "first-jwt")
            cmcc_sign.save_jwt_cache(second, "second-jwt")
            self.assertEqual(cmcc_sign.load_jwt_cache(first)[0], "first-jwt")
            self.assertEqual(cmcc_sign.load_jwt_cache(second)[0], "second-jwt")
            initial = json.loads(cmcc_sign.jwt_cache_file(first).read_text())
            cmcc_sign.save_jwt_cache(first, "renewed")
            updated = json.loads(cmcc_sign.jwt_cache_file(first).read_text())
            self.assertEqual(initial["first_seen"], updated["first_seen"])
            self.assertEqual(updated["jwt"], "renewed")
            updated["phone"] = second.phone
            cmcc_sign.jwt_cache_file(first).write_text(json.dumps(updated))
            self.assertIsNone(cmcc_sign.load_jwt_cache(first))

    def test_expired_or_corrupt_cache_is_ignored(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {"CMCC_DATA_DIR": root}):
            cfg = SimpleNamespace(phone="13800001234")
            cmcc_sign.save_jwt_cache(cfg, "jwt")
            path = cmcc_sign.jwt_cache_file(cfg)
            path.write_text(json.dumps({"phone": cfg.phone, "jwt": "old", "saved_at": time.time() - 31 * 86400}))
            self.assertIsNone(cmcc_sign.load_jwt_cache(cfg))
            path.write_text("invalid-json")
            self.assertIsNone(cmcc_sign.load_jwt_cache(cfg))

    def test_fee_env_overrides_file_without_requiring_app_token(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "config.json"
            path.write_text(json.dumps({"phone": "13800001234", "fee_session_cookie": "from-file"}), encoding="utf-8-sig")
            with patch.dict(os.environ, {"CMCC_FEE_SESSION": "from-env"}, clear=True), \
                 patch.object(cmcc_fee, "query_fee", return_value={}) as query, \
                 patch.object(cmcc_fee, "notify"):
                self.assertEqual(cmcc_fee.run(str(path)), 0)
                self.assertEqual(query.call_args.args[1], "from-env")

    def test_seckill_dry_run_never_supplements_checkin(self):
        now = time.time() * 1000
        zone = {"id": 1, "startTime": now + 60000, "endTime": now + 600000,
                "prize": {"id": 2, "name": "test"}}
        def response(_session, _referer, url, payload=None):
            if url == cmcc_seckill.SECCONFIG_URL:
                return {"data": {"secKillData": {"secKillZones": [zone]}}}
            if url == cmcc_seckill.TODAY_MARK_URL:
                return {"data": {"markStatus": "unmarked"}}
            self.fail("dry-run attempted a mutation")
        with patch.object(cmcc_seckill, "exchange_session", return_value=(Mock(), "https://example.com")), \
             patch.object(cmcc_seckill, "server_now_ms", return_value=int(now)), \
             patch.object(cmcc_seckill, "api_post", side_effect=response), \
             patch.object(cmcc_seckill, "ensure_eligible") as eligible, \
             patch.object(cmcc_seckill, "do_mark") as mark:
            result = cmcc_seckill.run(SimpleNamespace(phone="13800001234"), True, False, None, .35, .4, 120)
            self.assertEqual(result, 1)
            eligible.assert_not_called()
            mark.assert_not_called()

    def test_rating_query_failure_is_not_reported_as_success(self):
        with patch.object(cmcc_rate, "exchange_session", return_value=(Mock(), "https://example.com")), \
             patch.object(cmcc_rate, "_request", return_value={"code": "NETWORK_ERROR", "msg": "offline"}):
            with self.assertRaises(RuntimeError):
                cmcc_rate.run(SimpleNamespace(phone="13800001234"), True, None)

    def test_json_obj_guard_blocks_degraded_responses(self):
        for payload in ("系统繁忙", 42, ["系统繁忙"]):
            r = Mock(status_code=503, text="系统繁忙", headers={"Content-Type": "text/html"})
            r.json.return_value = payload
            with self.assertRaises(RuntimeError) as ctx:
                cmcc_sign.json_obj(r, "markstatus")
            self.assertIn("markstatus", str(ctx.exception))
            self.assertIn("非对象", str(ctx.exception))
        r = Mock(status_code=503, text="系统繁忙", headers={})
        r.json.return_value = "系统繁忙"
        with self.assertRaises(RuntimeError) as ctx:
            cmcc_sign.json_obj(r, "markstatus")
        self.assertIn("系统繁忙", str(ctx.exception), "报错要带原始响应片段")
        r = Mock(status_code=502, text="<html>bad gateway</html>", headers={})
        r.json.side_effect = ValueError("Expecting value")
        with self.assertRaises(RuntimeError) as ctx:
            cmcc_sign.json_obj(r, "domark")
        self.assertIn("domark", str(ctx.exception))
        self.assertIn("bad gateway", str(ctx.exception))
        r = Mock(status_code=200)
        r.json.return_value = {"code": "SUCCESS"}
        self.assertEqual(cmcc_sign.json_obj(r, "markstatus"), {"code": "SUCCESS"})

    def test_markstatus_bare_string_response_is_contextual(self):
        session = Mock()
        r = Mock(status_code=200, headers={})
        r.json.return_value = "系统繁忙"
        session.post.return_value = r
        with self.assertRaises(RuntimeError) as ctx:
            cmcc_sign.query_markstatus(session, "https://example.com")
        self.assertIn("markstatus", str(ctx.exception))

    def test_task_award_bare_string_response_is_contextual(self):
        session = Mock()
        r = Mock(status_code=200, headers={})
        r.json.return_value = "系统繁忙"
        session.post.return_value = r
        with self.assertRaises(RuntimeError) as ctx:
            cmcc_sign.claim_task_awards(session, "https://example.com", {"taskAwardChance": [{"id": "1001"}]})
        self.assertIn("taskAward/1001", str(ctx.exception))

    def exchange_session_with_replies(self, reply, seed_jwt=None):
        posts = []

        def post(url, json=None, timeout=None):
            posts.append(json)
            return reply(json)

        session = Mock()
        session.get.return_value.text = "loginPath = '/appTokenLogin?sid=preview'"
        session.cookies.keys.return_value = ["QWHD_SESSION_TOKEN"]
        session.post.side_effect = post
        cfg = SimpleNamespace(phone="13800000011", app_token="preview-token", act_url="https://example.com",
                              province_code="731", city_code="0731", carrier_operator="002", app_version_code="12.5.2")
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {"CMCC_DATA_DIR": root}), \
                patch.object(cmcc_sign.requests, "Session", return_value=session), \
                patch.object(cmcc_sign, "assert_safe_url"):
            if seed_jwt:
                cmcc_sign.save_jwt_cache(SimpleNamespace(phone="13800000011"), seed_jwt)
            cmcc_sign.exchange_session(cfg)
        return posts

    def test_renewal_sends_jwt_plus_app_token_before_jwt_only(self):
        def reply(payload):
            if payload["token"] == "":
                return Mock(json=Mock(return_value={"code": "SUCCESS", "data": {"jwt": "preview-jwt2", "url": "https://example.com"}}))
            return Mock(json=Mock(return_value={"code": "FAILED", "msg": "校验失败"}))

        posts = self.exchange_session_with_replies(reply, seed_jwt="preview-jwt")
        self.assertEqual([p["token"] for p in posts], ["preview-token", ""], "先带 app_token 续期，被拒后 jwt 单独重试")
        self.assertEqual([p["jwtToken"] for p in posts], ["preview-jwt", "preview-jwt"])

    def test_bootstrap_uses_app_token_when_no_cached_jwt(self):
        def reply(payload):
            self.assertIsNone(payload["jwtToken"])
            return Mock(json=Mock(return_value={"code": "SUCCESS", "data": {"jwt": "preview-jwt3", "url": "https://example.com"}}))

        posts = self.exchange_session_with_replies(reply)
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0]["token"], "preview-token")


if __name__ == "__main__":
    unittest.main()
