#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
pokerdom.py — базовый инспектор APK
-----------------------------------
Скрипт анализирует APK-файл (по умолчанию pokerdom.apk в текущей директории)
и формирует текстовый отчёт (по умолчанию pokerdom_info.txt).
Можно также экспортировать JSON.
"""

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path
from datetime import datetime

try:
    from apkutils2 import APK
except ImportError:
    print("❌ Библиотека apkutils2 не найдена. Установите её:\n   pip install apkutils2")
    input("Нажмите Enter, чтобы закрыть окно...")
    sys.exit(1)

# -----------------------------
# Список dangerous permissions
# -----------------------------
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
}


# -----------------------------
# Хелперы
# -----------------------------
def compute_hashes(path: Path):
    """Вычислить размер файла, MD5 и SHA256"""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    total = 0
    with path.open("rb") as f:
        while True:
            buf = f.read(8 * 1024 * 1024)
            if not buf:
                break
            total += len(buf)
            md5.update(buf)
            sha256.update(buf)
    return {
        "size_bytes": total,
        "size_human": f"{total/1024/1024:.2f} MB",
        "md5": md5.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def extract_manifest_info(apk: APK):
    """Извлечь основные данные из манифеста"""
    info = {}
    try:
        info["package_name"] = apk.get_package()
    except Exception:
        info["package_name"] = "Unknown"
    try:
        info["app_label"] = apk.get_app_name()
    except Exception:
        info["app_label"] = "Unknown"
    try:
        info["version_name"] = apk.get_version_name()
    except Exception:
        info["version_name"] = "Unknown"
    try:
        info["version_code"] = apk.get_version_code()
    except Exception:
        info["version_code"] = "Unknown"

    # SDK
    sdk = apk.get_manifest().get("uses-sdk", {})
    info["minSdkVersion"] = sdk.get("@android:minSdkVersion", "Unknown")
    info["targetSdkVersion"] = sdk.get("@android:targetSdkVersion", "Unknown")

    # Permissions
    perms = []
    for item in apk.get_manifest().get("uses-permission", []):
        name = item.get("@android:name", "Unknown")
        dangerous = name in DANGEROUS_PERMISSIONS
        perms.append({"name": name, "dangerous": dangerous})
    info["permissions"] = perms

    return info


def detect_launchable_activity(apk: APK):
    """Найти LAUNCHER Activity"""
    acts = []
    try:
        manifest = apk.get_manifest()
        app = manifest.get("application", {})
        activity_nodes = []
        if isinstance(app.get("activity"), list):
            activity_nodes = app["activity"]
        elif isinstance(app.get("activity"), dict):
            activity_nodes = [app["activity"]]

        for act in activity_nodes:
            name = act.get("@android:name", "Unknown")
            filters = act.get("intent-filter", [])
            if isinstance(filters, dict):
                filters = [filters]
            for flt in filters:
                actions = flt.get("action", [])
                categories = flt.get("category", [])
                if isinstance(actions, dict):
                    actions = [actions]
                if isinstance(categories, dict):
                    categories = [categories]
                actions = {a.get("@android:name") for a in actions}
                categories = {c.get("@android:name") for c in categories}
                if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories:
                    acts.append(name)
    except Exception:
        pass
    return acts


def format_report(path: Path, hashes: dict, info: dict, launchable: list):
    """Сформировать текстовый отчёт"""
    now = datetime.now().isoformat(timespec="seconds")

    lines = []
    lines.append(f"=== APK Report: {path.name} ===")
    lines.append(f"Generated: {now}\n")

    # File
    lines.append("[File]")
    lines.append(f"Path: {path}")
    lines.append(f"Size: {hashes['size_bytes']} bytes ({hashes['size_human']})")
    lines.append(f"SHA256: {hashes['sha256']}")
    lines.append(f"MD5:    {hashes['md5']}\n")

    # Package
    lines.append("[Package]")
    lines.append(f"Package name: {info['package_name']}")
    lines.append(f"App label: {info['app_label']}")
    lines.append(f"Version name: {info['version_name']}")
    lines.append(f"Version code: {info['version_code']}\n")

    # SDK
    lines.append("[SDK]")
    lines.append(f"minSdkVersion: {info['minSdkVersion']}")
    lines.append(f"targetSdkVersion: {info['targetSdkVersion']}\n")

    # Manifest
    lines.append("[Manifest]")
    if launchable:
        lines.append("Launchable activity: " + ", ".join(launchable))
    else:
        lines.append("Launchable activity: Unknown")
    lines.append(f"Permissions ({len(info['permissions'])}):")
    for p in info["permissions"]:
        if p["dangerous"]:
            lines.append(f"  - {p['name']} (DANGEROUS)")
        else:
            lines.append(f"  - {p['name']}")
    lines.append("")

    # Footer
    lines.append("=== End of report ===")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="APK inspector (pokerdom)")
    parser.add_argument("--apk", type=str, default="pokerdom.apk", help="путь к APK-файлу")
    parser.add_argument("--out", type=str, default="pokerdom_info.txt", help="путь к .txt отчёту")
    parser.add_argument("--json", type=str, help="путь к JSON-отчёту (опц.)")
    args = parser.parse_args()

    apk_path = Path(args.apk)
    if not apk_path.exists():
        print(f"❌ APK-файл не найден: {apk_path}")
        sys.exit(1)

    # Хэши
    hashes = compute_hashes(apk_path)

    # Парсинг
    try:
        apk = APK(apk_path.read_bytes())
    except Exception as e:
        print(f"❌ Ошибка чтения APK: {e}")
        sys.exit(1)

    info = extract_manifest_info(apk)
    launchable = detect_launchable_activity(apk)

    # Формируем отчёт
    report_text = format_report(apk_path, hashes, info, launchable)
    Path(args.out).write_text(report_text, encoding="utf-8")
    print(f"✅ Отчёт сохранён: {args.out}")

    if args.json:
        out_json = {
            "file": hashes,
            "package": {
                "package_name": info["package_name"],
                "app_label": info["app_label"],
                "version_name": info["version_name"],
                "version_code": info["version_code"],
            },
            "sdk": {
                "minSdkVersion": info["minSdkVersion"],
                "targetSdkVersion": info["targetSdkVersion"],
            },
            "manifest": {
                "launchable_activity": launchable,
                "permissions": info["permissions"],
            },
            "generated": datetime.now().isoformat(timespec="seconds"),
        }
        Path(args.json).write_text(json.dumps(out_json, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"✅ JSON сохранён: {args.json}")


if __name__ == "__main__":
    main()