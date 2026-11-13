import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import cmcc_keepalive
import cmcc_sign
from cmcc_app.models import Store, normalize_account
from cmcc_app.runner import Manager
from cmcc_app.settings import Settings


def fake_session(replies):
    """按 POST 调用顺序回放响应；replies 为响应对象或返回响应对象的函数。"""
    session = Mock()
    session.get.return_value.text = "loginPath = '/appTokenLogin?sid=preview'"
    session.post.side_effect = list(replies)
    return session


def make_response(payload):
    return Mock(json=Mock(return_value=payload))


def probe_config(phone="13800000011"):
    return SimpleNamespace(phone=phone, app_token="preview-token", act_url="https://example.com",
                           province_code="731", city_code="0731", carrier_operator="002",
                           app_version_code="12.5.2")


class KeepaliveScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        env = patch.dict("os.environ", {"CMCC_DATA_DIR": self.temp.name})
        env.start()
        self.addCleanup(env.stop)

    def test_three_tiers_in_order_and_stop_on_success(self):
        posts = []

        def reply(url, json=None, timeout=None):
            posts.append(json)
            if json["token"] == "":
                return make_response({"code": "FAILED", "msg": "APP登录状态已过期"})
            return make_response({"code": "SUCCESS", "data": {"jwt": "preview-jwt-new"}})

        session = fake_session([])
        session.post.side_effect = reply
        cfg = probe_config()
        cmcc_sign.save_jwt_cache(cfg, "preview-jwt")
        with patch.object(cmcc_sign.requests, "Session", return_value=session):
            ok, detail = cmcc_keepalive.keepalive(cfg, verbose=True)
        self.assertTrue(ok)
        self.assertEqual(detail, "jwt+app_token")
        self.assertEqual([p["token"] for p in posts], ["preview-token"])
        self.assertEqual(posts[0]["jwtToken"], "preview-jwt")
        self.assertEqual(cmcc_sign.load_jwt_cache(cfg)[0], "preview-jwt-new")

    def test_second_tier_uses_jwt_only_when_app_token_is_rejected(self):
        posts = []

        def reply(url, json=None, timeout=None):
            posts.append(json)
            if json["token"] != "" or json["jwtToken"] == "":
                return make_response({"code": "FAILED", "msg": "校验失败"})
            return make_response({"code": "SUCCESS", "data": {"jwt": "preview-jwt-jwt"}})

        session = fake_session([])
        session.post.side_effect = reply
        cfg = probe_config()
        cmcc_sign.save_jwt_cache(cfg, "preview-jwt")
        with patch.object(cmcc_sign.requests, "Session", return_value=session):
            ok, detail = cmcc_keepalive.keepalive(cfg)
        self.assertTrue(ok)
        self.assertEqual(detail, "jwt 单独")
        self.assertEqual([p["token"] for p in posts], ["preview-token", ""])

    def test_bare_string_response_falls_through_to_next_tier(self):
        session = fake_session([
            make_response("系统繁忙"),
            make_response({"code": "FAILED", "msg": "APP登录状态已过期"}),
            make_response({"code": "SUCCESS", "data": {"jwt": "preview-jwt-guide"}}),
        ])
        cfg = probe_config()
        cmcc_sign.save_jwt_cache(cfg, "preview-jwt")
        with patch.object(cmcc_sign.requests, "Session", return_value=session):
            ok, detail = cmcc_keepalive.keepalive(cfg)
        self.assertTrue(ok, "裸字符串响应不算凭证失效，应继续走下一档")
        self.assertEqual(detail, "app_token 引导")
        self.assertEqual(cmcc_sign.load_jwt_cache(cfg)[0], "preview-jwt-guide")

    def test_all_tiers_rejected_reports_last_error(self):
        session = fake_session([
            make_response({"code": "FAILED", "msg": "APP登录状态已过期"}),
            make_response({"code": "FAILED", "msg": "APP登录状态已过期"}),
            make_response({"code": "FAILED", "msg": "token失效"}),
        ])
        cfg = probe_config()
        cmcc_sign.save_jwt_cache(cfg, "preview-jwt")
        with patch.object(cmcc_sign.requests, "Session", return_value=session):
            ok, detail = cmcc_keepalive.keepalive(cfg)
        self.assertFalse(ok)
        self.assertIn("token失效", detail)


class InstantThread:
    def __init__(self, target=None, args=(), **kwargs):
        self._target, self._args = target, args

    def start(self):
        self._target(*self._args)


class ManagerKeepaliveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        env = patch.dict("os.environ", {"CMCC_DATA_DIR": str(self.root)})
        env.start()
        self.addCleanup(env.stop)
        self.store = Store(self.root)
        data = {"name": "保活账号", "config": {"phone": "13800000011", "app_token": "preview-token"},
                "keepalive": {"enabled": False, "minutes": 15}}
        self.account = normalize_account(data)
        self.store.save(self.account)
        self.settings = Settings(self.root, "test-password-only")
        self.manager = Manager(self.store, self.settings)

    def enable_keepalive(self, minutes=15, at=None, state=""):
        self.store.set_keepalive_result(self.account["id"], state, at or "", "")
        saved = self.store.account(self.account["id"])
        saved["keepalive"]["enabled"] = True
        saved["keepalive"]["minutes"] = minutes
        self.store.save(saved)
        return saved

    def test_success_is_recorded_without_notification(self):
        account = self.enable_keepalive()
        with patch.object(cmcc_keepalive, "keepalive", return_value=(True, "jwt+app_token")) as ka, \
                patch.object(cmcc_sign, "notify") as notify:
            self.manager._keepalive_body(account, self.root / "runtime" / "preview.json")
        saved = self.store.account(self.account["id"])["keepalive"]
        self.assertEqual((saved["state"], saved["detail"]), ("success", "jwt+app_token"))
        self.assertTrue(saved["at"])
        ka.assert_called_once()
        notify.assert_not_called()

    def test_failure_notifies_once_until_recovered(self):
        account = self.enable_keepalive()
        with patch.object(cmcc_keepalive, "keepalive", return_value=(False, "jwt+app_token: FAILED token失效")), \
                patch.object(cmcc_sign, "notify") as notify:
            self.manager._keepalive_body(account, self.root / "runtime" / "preview.json")
            self.assertEqual(notify.call_count, 1, "首次失败要推送通知")
            # 调度器每次扫描都会重读账号，已 failed 的状态不会再推送。
            stale = self.store.account(self.account["id"])
            self.manager._keepalive_body(stale, self.root / "runtime" / "preview.json")
            self.assertEqual(notify.call_count, 1, "持续失败不重复推送")
            saved = self.store.account(self.account["id"])["keepalive"]
            self.assertEqual(saved["state"], "failed")
            self.assertIn("token失效", saved["detail"])
        with patch.object(cmcc_keepalive, "keepalive", return_value=(True, "jwt+app_token")), \
                patch.object(cmcc_sign, "notify") as notify:
            self.manager._keepalive_body(account, self.root / "runtime" / "preview.json")
            notify.assert_not_called()
        self.assertEqual(self.store.account(self.account["id"])["keepalive"]["state"], "success")

    def test_keepalive_body_removes_runtime_config(self):
        account = self.enable_keepalive()
        path = self.root / "runtime" / "keepalive-preview.json"
        path.write_text("{}", encoding="utf-8")
        with patch.object(cmcc_keepalive, "keepalive", return_value=(True, "jwt+app_token")):
            self.manager._keepalive_body(account, path)
        self.assertFalse(path.exists(), "含凭证的运行配置用完即删")

    def test_due_scan_runs_only_due_accounts(self):
        now = datetime.now(timezone.utc)
        self.enable_keepalive(minutes=15, at=(now - timedelta(minutes=2)).isoformat(), state="success")
        with patch("cmcc_app.runner.threading.Thread", InstantThread), \
                patch.object(cmcc_keepalive, "keepalive", return_value=(True, "jwt+app_token")) as ka:
            self.manager.run_keepalives_due()
        ka.assert_not_called()  # 距上次保活仅 2 分钟，未到 15 分钟间隔不应执行

        self.enable_keepalive(minutes=15, at=(now - timedelta(minutes=16)).isoformat(), state="success")
        with patch("cmcc_app.runner.threading.Thread", InstantThread), \
                patch.object(cmcc_keepalive, "keepalive", return_value=(True, "jwt+app_token")) as ka:
            self.manager.run_keepalives_due()
        ka.assert_called_once()
        saved = self.store.account(self.account["id"])["keepalive"]
        self.assertEqual(saved["state"], "success")
        self.assertEqual(list(self.store.runs()), [], "保活不进入执行记录")

    def test_scan_skips_disabled_and_running_accounts(self):
        with patch("cmcc_app.runner.threading.Thread", InstantThread), \
                patch.object(cmcc_keepalive, "keepalive", return_value=(True, "jwt+app_token")) as ka:
            self.manager.run_keepalives_due()
        ka.assert_not_called()  # 未开启保活的账号不参与扫描

        self.enable_keepalive(at=datetime.now(timezone.utc).isoformat(), state="success")
        with patch.object(cmcc_keepalive, "keepalive", return_value=(True, "jwt+app_token")) as ka:
            self.manager.keepalive_running.add(self.account["id"])
            self.manager.run_keepalives_due()
            ka.assert_not_called()  # 同一账号同时只允许一个保活线程


if __name__ == "__main__":
    unittest.main()
