# -*- coding: utf-8 -*-
"""微信客服（微信 + 企业微信用户）自动接待服务端。

流程：微信客服回调只推事件（MsgType=event / kv_msg_or_event，带 Token 游标 + OpenKfId），
      本服务 5 秒内回包，异步用 Token 调 sync_msg 拉正文，再调 send_msg 回复。

环境变量（见 .env.example）
"""
import base64
import hashlib
import logging
import os
import struct
import threading
import time
import xml.etree.ElementTree as ET
from collections import OrderedDict, deque
from http import HTTPStatus

import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, request

CORP_ID = os.environ["KF_CORP_ID"]
KF_SECRET = os.environ["KF_SECRET"]
CALLBACK_TOKEN = os.environ["KF_TOKEN"]
AES_KEY = os.environ["KF_AES_KEY"]
AI_URL = os.environ.get("AI_URL", "").strip()
PORT = int(os.environ.get("PORT", "8001"))
API = "https://qyapi.weixin.qq.com/cgi-bin"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("kf")

app = Flask(__name__)


# ---------------------------------------------------------------- 加解密
def _key_bytes() -> bytes:
    return base64.b64decode(AES_KEY + "=")


def verify_signature(signature: str, timestamp: str, nonce: str, encrypted: str) -> bool:
    raw = "".join(sorted([CALLBACK_TOKEN, timestamp, nonce, encrypted]))
    return hashlib.sha1(raw.encode()).hexdigest() == signature


def decrypt(encrypted: str) -> str:
    """企业微信 AES-256-CBC 解包：16字节随机 + 4字节长度 + 明文 + corpid。"""
    key = _key_bytes()
    if len(key) != 32:
        raise ValueError("EncodingAESKey 长度不对，必须是 43 位字符串")
    raw = base64.b64decode(encrypted)
    dec = Cipher(algorithms.AES(key), modes.CBC(key[:16])).decryptor()
    plain = dec.update(raw) + dec.finalize()

    pad = plain[-1]
    if pad < 1 or pad > 32 or plain[-pad:] != bytes([pad]) * pad:
        raise ValueError("PKCS7 填充非法")
    plain = plain[:-pad]

    msg_len = struct.unpack(">I", plain[16:20])[0]
    msg = plain[20 : 20 + msg_len]
    if plain[20 + msg_len :].decode("utf-8", "ignore") not in (CORP_ID, ""):
        log.warning("回调 corpid 不匹配，请检查 KF_CORP_ID")
    return msg.decode("utf-8")


# ---------------------------------------------------------------- access_token
_token_cache = {"value": "", "expire_at": 0.0}
_token_lock = threading.Lock()


def access_token() -> str:
    with _token_lock:
        if _token_cache["value"] and time.time() < _token_cache["expire_at"]:
            return _token_cache["value"]
        resp = requests.get(
            f"{API}/gettoken",
            params={"corpid": CORP_ID, "corpsecret": KF_SECRET},
            timeout=5,
        ).json()
        if resp.get("errcode", 0) != 0:
            raise RuntimeError(f"gettoken 失败: {resp}")
        _token_cache["value"] = resp["access_token"]
        _token_cache["expire_at"] = time.time() + resp["expires_in"] - 120
        return _token_cache["value"]


def call(path: str, payload: dict) -> dict:
    resp = requests.post(
        f"{API}/{path}",
        params={"access_token": access_token()},
        json=payload,
        timeout=8,
    ).json()
    if resp.get("errcode", 0) != 0:
        log.error("%s 失败 %s", path, resp)
    return resp


# ---------------------------------------------------------------- 去重
_seen: OrderedDict[str, float] = OrderedDict()
_seen_lock = threading.Lock()
SEEN_MAX = 5000


def first_time(msgid: str) -> bool:
    """微信会重推回调，同一条消息按 msgid 只处理一次。"""
    with _seen_lock:
        now = time.time()
        while _seen and now - next(iter(_seen.values())) > 1800:
            _seen.popitem(last=False)
        if msgid in _seen:
            return False
        _seen[msgid] = now
        while len(_seen) > SEEN_MAX:
            _seen.popitem(last=False)
        return True


# ---------------------------------------------------------------- 回调入口
@app.get("/kf")
def verify_url():
    """后台点「保存」时微信会来这里验一次，要把 echostr 解密后原样返回。"""
    args = request.args
    encrypted = args.get("echostr", "")
    if not encrypted or not verify_signature(
        args.get("msg_signature", ""), args.get("timestamp", ""), args.get("nonce", ""), encrypted
    ):
        return "invalid signature", HTTPStatus.FORBIDDEN
    return decrypt(encrypted), HTTPStatus.OK, {"Content-Type": "text/plain; charset=utf-8"}


@app.post("/kf")
def receive_event():
    args = request.args
    root = ET.fromstring(request.get_data())
    encrypted = root.findtext("Encrypt") or ""
    if not verify_signature(
        args.get("msg_signature", ""), args.get("timestamp", ""), args.get("nonce", ""), encrypted
    ):
        return "invalid signature", HTTPStatus.FORBIDDEN

    event = ET.fromstring(decrypt(encrypted))
    cursor = event.findtext("Token") or ""
    open_kfid = event.findtext("OpenKfId") or ""
    log.info("收到事件 %s open_kfid=%s", event.findtext("Event"), open_kfid)

    threading.Thread(target=pull_messages, args=(cursor, open_kfid), daemon=True).start()
    return "success"  # 必须快速回包，实际业务放到线程里做


@app.get("/healthz")
def healthz():
    return {"ok": True, "ts": int(time.time())}


# ---------------------------------------------------------------- 拉消息
def pull_messages(cursor: str, open_kfid: str) -> None:
    guard = 0
    while guard < 30:
        guard += 1
        resp = call("kf/sync_msg", {"token": cursor, "open_kfid": open_kfid, "limit": 100})
        if resp.get("errcode", 0) != 0:
            return
        for msg in resp.get("msg_list", []):
            try:
                handle(msg)
            except Exception:  # 单条出错不影响后续
                log.exception("处理单条消息失败: %s", msg.get("msgid"))
        cursor = resp.get("next_cursor") or cursor
        if not resp.get("has_more"):
            break


# ---------------------------------------------------------------- 单条处理
def handle(msg: dict) -> None:
    # origin: 3=客户发送  4=系统推送通知  5=接待人员发送
    if msg.get("origin") != 3:
        return
    if not first_time(msg.get("msgid", "")):
        return

    user = msg.get("external_userid", "")
    open_kfid = msg.get("open_kfid", "")
    msgtype = msg.get("msgtype", "")

    if msgtype == "text":
        answer = reply_text(msg["text"]["content"])
    elif msgtype in {"image", "voice", "video", "file"}:
        answer = "图片和文件这边暂时看不了，麻烦用文字描述一下您的问题～"
    else:
        answer = "收到，正在为您处理，稍等一下。"
    send_text(user, open_kfid, answer)


def reply_text(question: str) -> str:
    question = (question or "").strip()
    if AI_URL:
        try:
            resp = requests.post(
                AI_URL,
                json={"question": question, "source": "wechat_kf"},
                timeout=15,
            ).json()
            text = resp.get("answer") or resp.get("text")
            if text:
                return clip(text)
        except Exception:
            log.exception("AI 接口调用失败，走兜底方案")
    return clip(f"收到您的咨询：{question}\n我们已记录，会尽快由人工跟进。")



def clip(text: str, limit: int = 2000) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def send_text(user: str, open_kfid: str, content: str) -> None:
    """注意：用户发一条消息后 48 小时内最多发 5 条，超限报 95001。"""
    resp = call(
        "kf/send_msg",
        {
            "touser": user,
            "open_kfid": open_kfid,
            "msgtype": "text",
            "text": {"content": content},
        },
    )
    code = resp.get("errcode", 0)
    if code == 95001:
        log.warning("发送次数超限（5 条用完），等待用户再次发言")
    elif code in (95002, 95024):
        log.warning("已超 48 小时会话窗口，需要用户重新发起咨询")
    elif code != 0:
        log.error("发送失败: %s", resp)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
