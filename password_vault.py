#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
命令行密码保险箱 - 本地 CLI 密码管理工具
"""

import sqlite3
import base64
import hashlib
import os
import argparse
import sys
import getpass
import random
import string
import csv
import re
from datetime import datetime, timedelta


VAULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "password_vault.db")
WEAK_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "password1",
    "123456789", "1234567", "12345", "1234567890", "admin", "letmein",
    "welcome", "monkey", "dragon", "master", "111111", "iloveyou",
    "sunshine", "princess"
}
PASSWORD_EXPIRE_DAYS = 90


def derive_key(master_password: str) -> bytes:
    return hashlib.sha256(master_password.encode("utf-8")).digest()


def encrypt(plain_text: str, key: bytes) -> str:
    if not plain_text:
        return ""
    plain_bytes = plain_text.encode("utf-8")
    encrypted = bytearray()
    key_len = len(key)
    for i, byte in enumerate(plain_bytes):
        encrypted.append(byte ^ key[i % key_len])
    return base64.b64encode(encrypted).decode("utf-8")


def decrypt(cipher_text: str, key: bytes) -> str:
    if not cipher_text:
        return ""
    encrypted = base64.b64decode(cipher_text.encode("utf-8"))
    decrypted = bytearray()
    key_len = len(key)
    for i, byte in enumerate(encrypted):
        decrypted.append(byte ^ key[i % key_len])
    return decrypted.decode("utf-8")


def init_db(master_password: str) -> bool:
    if os.path.exists(VAULT_FILE):
        print("错误：密码保险箱已存在！如需重新初始化，请先删除数据库文件。")
        return False

    key = derive_key(master_password)
    check_value = encrypt("VAULT_INIT_CHECK", key)

    conn = sqlite3.connect(VAULT_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault_meta (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            check_value TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            note TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    cursor.execute(
        "INSERT INTO vault_meta (check_value, created_at) VALUES (?, ?)",
        (check_value, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )

    conn.commit()
    conn.close()

    print("密码保险箱初始化成功！")
    return True


def verify_master_password(master_password: str) -> bool:
    if not os.path.exists(VAULT_FILE):
        print("错误：密码保险箱不存在，请先使用 init 命令初始化。")
        return False

    key = derive_key(master_password)

    conn = sqlite3.connect(VAULT_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT check_value FROM vault_meta WHERE id = 1")
    row = cursor.fetchone()
    conn.close()

    if not row:
        return False

    try:
        decrypted = decrypt(row[0], key)
        return decrypted == "VAULT_INIT_CHECK"
    except Exception:
        return False


def get_master_password(prompt: str = "请输入主密码: ") -> str:
    env_pwd = os.environ.get("VAULT_MASTER_PASSWORD")
    if env_pwd:
        return env_pwd
    cli_pwd = sys.argv
    for i, arg in enumerate(sys.argv):
        if arg in ("--master-password", "-mp") and i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return getpass.getpass(prompt)


def generate_password(length: int = 16, use_upper: bool = True, use_lower: bool = True,
                   use_digits: bool = True, use_special: bool = True) -> str:
    if length < 4:
        length = 4
    chars = ""
    required = []
    if use_upper:
        chars += string.ascii_uppercase
        required.append(random.choice(string.ascii_uppercase))
    if use_lower:
        chars += string.ascii_lowercase
        required.append(random.choice(string.ascii_lowercase))
    if use_digits:
        chars += string.digits
        required.append(random.choice(string.digits))
    if use_special:
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        chars += special_chars
        required.append(random.choice(special_chars))
    if not chars:
        chars = string.ascii_letters
        required = [random.choice(string.ascii_letters)]

    remaining = length - len(required)
    if remaining < 0:
        remaining = 0
    password_chars = required + [random.choice(chars) for _ in range(remaining)]
    random.shuffle(password_chars)
    return "".join(password_chars)


def assess_password_strength(password: str) -> dict:
    result = {
        "score": 0,
        "level": "低",
        "issues": []
    }
    if not password:
        result["issues"].append("密码为空")
        return result

    if len(password) < 8:
        result["issues"].append(f"密码长度仅 {len(password)} 位，建议至少 8 位")
    elif len(password) >= 12:
        result["score"] += 1

    if password.lower() in WEAK_PASSWORDS:
        result["issues"].append("属于常见弱密码")

    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", password))

    char_types = sum([has_upper, has_lower, has_digit, has_special])
    if char_types < 3:
        result["issues"].append(f"仅包含 {char_types} 种字符类型，建议至少 3 种")
    else:
        result["score"] += 1

    if not has_upper:
        result["issues"].append("缺少大写字母")
    if not has_lower:
        result["issues"].append("缺少小写字母")
    if not has_digit:
        result["issues"].append("缺少数字")
    if not has_special:
        result["issues"].append("缺少特殊字符")

    if re.search(r"(.)\1{2,}", password):
        result["issues"].append("包含连续重复字符")

    if result["score"] >= 2 and not result["issues"]:
        result["level"] = "高"
    elif result["score"] >= 1 or len(result["issues"]) <= 1:
        result["level"] = "中"
    else:
        result["level"] = "低"

    return result


def get_risk_level(password: str, created_at: str, updated_at: str, note: str,
                   all_records: list, current_record: dict) -> tuple:
    risks = []
    risk_level = "低"

    strength = assess_password_strength(password)
    if strength["level"] == "低":
        risks.append("弱密码")
    if strength["level"] == "中":
        risk_level = "中"

    password_count = sum(1 for r in all_records if r["password"] == password)
    if password_count > 1:
        risks.append(f"密码与其他 {password_count - 1} 条记录重复")
        risk_level = "高"

    try:
        update_dt = datetime.strptime(updated_at, "%Y-%m-%d %H:%M:%S")
        if datetime.now() - update_dt > timedelta(days=PASSWORD_EXPIRE_DAYS):
            risks.append(f"密码超过 {PASSWORD_EXPIRE_DAYS} 天未更新")
            if risk_level != "高":
                risk_level = "中"
    except Exception:
        pass

    if not note or not note.strip():
        risks.append("缺少备注")

    if "高" in risks or len(risks) >= 3:
        risk_level = "高"
    elif "中" in risks or len(risks) >= 1:
        if risk_level != "高":
            risk_level = "中"
    else:
        risk_level = "低"

    return risk_level, risks


def add_password(site: str, username: str, password: str, note: str, key: bytes) -> bool:
    encrypted_site = encrypt(site, key)
    encrypted_username = encrypt(username, key)
    encrypted_password = encrypt(password, key)
    encrypted_note = encrypt(note, key)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect(VAULT_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO passwords (site, username, password, note, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (encrypted_site, encrypted_username, encrypted_password, encrypted_note, now, now)
    )
    conn.commit()
    conn.close()

    print(f"已添加密码记录：{site} / {username}")
    return True


def mask_password(password: str) -> str:
    if not password:
        return ""
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]


def list_passwords(key: bytes, show_password: bool = False) -> None:
    conn = sqlite3.connect(VAULT_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, site, username, password, note, created_at, updated_at FROM passwords ORDER BY id")
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print("暂无密码记录。")
        return

    print(f"\n共 {len(rows)} 条密码记录：")
    print("-" * 80)
    for row in rows:
        pid = row[0]
        site = decrypt(row[1], key)
        username = decrypt(row[2], key)
        password = decrypt(row[3], key)
        note = decrypt(row[4], key)
        created_at = row[5]
        updated_at = row[6]

        display_pwd = password if show_password else mask_password(password)

        print(f"ID: {pid}")
        print(f"  站点:   {site}")
        print(f"  用户名: {username}")
        print(f"  密码:   {display_pwd}" + ("" if show_password else " (使用 --show-password 查看明文)"))
        print(f"  备注:   {note}")
        print(f"  创建:   {created_at}")
        print(f"  更新:   {updated_at}")
        print("-" * 80)


def search_passwords(keyword: str, key: bytes, show_password: bool = False) -> None:
    conn = sqlite3.connect(VAULT_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, site, username, password, note, created_at, updated_at FROM passwords")
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print("暂无密码记录。")
        return

    keyword_lower = keyword.lower()
    results = []
    for row in rows:
        site = decrypt(row[1], key)
        username = decrypt(row[2], key)
        note = decrypt(row[4], key)

        if (keyword_lower in site.lower() or
            keyword_lower in username.lower() or
            keyword_lower in note.lower()):
            results.append((row, site, username, decrypt(row[3], key), note))

    if not results:
        print(f"未找到包含 '{keyword}' 的密码记录。")
        return

    print(f"\n找到 {len(results)} 条匹配的密码记录：")
    print("-" * 80)
    for row, site, username, password, note in results:
        pid = row[0]
        created_at = row[5]
        updated_at = row[6]

        display_pwd = password if show_password else mask_password(password)

        print(f"ID: {pid}")
        print(f"  站点:   {site}")
        print(f"  用户名: {username}")
        print(f"  密码:   {display_pwd}" + ("" if show_password else " (使用 --show-password 查看明文)"))
        print(f"  备注:   {note}")
        print(f"  创建:   {created_at}")
        print(f"  更新:   {updated_at}")
        print("-" * 80)


def find_record_by_site_username(site: str, username: str, key: bytes) -> int:
    conn = sqlite3.connect(VAULT_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, site, username FROM passwords")
    rows = cursor.fetchall()
    conn.close()

    for row in rows:
        decrypted_site = decrypt(row[1], key)
        decrypted_username = decrypt(row[2], key)
        if decrypted_site == site and decrypted_username == username:
            return row[0]
    return None


def update_password(record_id: int = None, site: str = None, username: str = None,
                    password: str = None, note: str = None, key: bytes = None) -> bool:
    conn = sqlite3.connect(VAULT_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT site, username, password, note FROM passwords WHERE id = ?", (record_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        print(f"错误：ID 为 {record_id} 的记录不存在。")
        return False

    current_site = decrypt(row[0], key)
    current_username = decrypt(row[1], key)
    current_password = decrypt(row[2], key)
    current_note = decrypt(row[3], key)

    new_site = site if site is not None else current_site
    new_username = username if username is not None else current_username
    new_password = password if password is not None else current_password
    new_note = note if note is not None else current_note

    enc_site = encrypt(new_site, key)
    enc_username = encrypt(new_username, key)
    enc_password = encrypt(new_password, key)
    enc_note = encrypt(new_note, key)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        "UPDATE passwords SET site = ?, username = ?, password = ?, note = ?, updated_at = ? WHERE id = ?",
        (enc_site, enc_username, enc_password, enc_note, now, record_id)
    )
    conn.commit()
    conn.close()

    print(f"已更新 ID 为 {record_id} 的密码记录。")
    return True


def delete_password(record_id: int, key: bytes) -> bool:
    conn = sqlite3.connect(VAULT_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT site, username FROM passwords WHERE id = ?", (record_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        print(f"错误：ID 为 {record_id} 的记录不存在。")
        return False

    site = decrypt(row[0], key)
    username = decrypt(row[1], key)

    cursor.execute("DELETE FROM passwords WHERE id = ?", (record_id,))
    conn.commit()
    conn.close()

    print(f"已删除记录：{site} / {username}")
    return True


def audit_passwords(key: bytes) -> None:
    conn = sqlite3.connect(VAULT_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, site, username, password, note, created_at, updated_at FROM passwords")
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print("暂无密码记录。")
        return

    records = []
    for row in rows:
        records.append({
            "id": row[0],
            "site": decrypt(row[1], key),
            "username": decrypt(row[2], key),
            "password": decrypt(row[3], key),
            "note": decrypt(row[4], key),
            "created_at": row[5],
            "updated_at": row[6]
        })

    high_risk = []
    medium_risk = []
    low_risk = []

    print("\n" + "=" * 80)
    print("密码安全体检报告")
    print("=" * 80)

    for rec in records:
        risk_level, risks = get_risk_level(
            rec["password"], rec["created_at"], rec["updated_at"],
            rec["note"], records, rec
        )

        rec["risk_level"] = risk_level
        rec["risks"] = risks

        if risk_level == "高":
            high_risk.append(rec)
        elif risk_level == "中":
            medium_risk.append(rec)
        else:
            low_risk.append(rec)

    print(f"\n总计: {len(records)} 条记录")
    print(f"  高风险: {len(high_risk)} 条")
    print(f"  中风险: {len(medium_risk)} 条")
    print(f"  低风险: {len(low_risk)} 条")

    def print_risk_group(title, group, level_symbol):
        if not group:
            return
        print(f"\n{'-' * 80}")
        print(f"【{title}】共 {len(group)} 条")
        print(f"{'-' * 80}")
        for rec in group:
            print(f"\n  ID: {rec['id']} | {rec['site']} / {rec['username']}")
            print(f"  风险等级: {level_symbol} {rec['risk_level']}")
            print(f"  问题:")
            for r in rec["risks"]:
                print(f"    - {r}")
            print(f"  建议:")
            strength = assess_password_strength(rec["password"])
            if "弱密码" in rec["risks"]:
                print(f"    - 更换为强度更高的密码，建议至少 12 位以上，包含大小写字母、数字和特殊字符")
            if any("重复" in r for r in rec["risks"]):
                print(f"    - 为该账户设置独立的唯一密码")
            if any("未更新" in r for r in rec["risks"]):
                print(f"    - 定期更换密码，建议每 {PASSWORD_EXPIRE_DAYS} 天更换一次")
            if any("缺少备注" in r for r in rec["risks"]):
                print(f"    - 添加备注信息，方便记忆密码用途")
            print()

    print_risk_group("高风险记录", high_risk, "[高]")
    print_risk_group("中风险记录", medium_risk, "[中]")
    print_risk_group("低风险记录", low_risk, "[低]")

    if high_risk:
        print("\n" + "=" * 80)
        print("总体评价：存在高风险记录，建议立即整改！")
    elif medium_risk:
        print("\n" + "=" * 80)
        print("总体评价：存在中风险记录，建议尽快优化。")
    else:
        print("\n" + "=" * 80)
        print("总体评价：密码状态良好，请继续保持。")
    print("=" * 80)


def export_passwords(key: bytes, output_file: str) -> None:
    conn = sqlite3.connect(VAULT_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, site, username, password, note, created_at, updated_at FROM passwords")
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print("暂无密码记录。")
        return

    records = []
    for row in rows:
        records.append({
            "id": row[0],
            "site": decrypt(row[1], key),
            "username": decrypt(row[2], key),
            "password": decrypt(row[3], key),
            "note": decrypt(row[4], key),
            "created_at": row[5],
            "updated_at": row[6]
        })

    with open(output_file, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["站点", "用户名", "备注", "创建时间", "更新时间", "安全风险等级"])
        for rec in records:
            risk_level, _ = get_risk_level(
                rec["password"], rec["created_at"], rec["updated_at"],
                rec["note"], records, rec
            )
            writer.writerow([
                rec["site"],
                rec["username"],
                rec["note"],
                rec["created_at"],
                rec["updated_at"],
                risk_level
            ])

    print(f"已成功导出 {len(records)} 条记录到 {output_file}")
    print("提示：导出文件为脱敏格式，不包含明文密码。")


def import_passwords(key: bytes, input_file: str, overwrite: bool = False) -> None:
    if not os.path.exists(input_file):
        print(f"错误：文件 {input_file} 不存在。")
        return

    conn = sqlite3.connect(VAULT_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, site, username, password, note, created_at, updated_at FROM passwords")
    rows = cursor.fetchall()
    conn.close()

    existing = {}
    for row in rows:
        s = decrypt(row[1], key)
        u = decrypt(row[2], key)
        existing[(s, u)] = row[0]

    imported = 0
    skipped = 0
    overwritten = 0
    errors = 0

    with open(input_file, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        required_fields = ["站点", "用户名"]
        for field in required_fields:
            if field not in reader.fieldnames:
                print(f"错误：CSV 文件缺少必填字段 '{field}'")
                return

        for line_num, row in enumerate(reader, start=2):
            site = (row.get("站点") or "").strip()
            username = (row.get("用户名") or "").strip()
            note = (row.get("备注") or "").strip()
            password = (row.get("密码") or "").strip()

            if not site or not username:
                print(f"第 {line_num} 行：站点和用户名为必填项，已跳过。")
                errors += 1
                continue

            if not password:
                print(f"第 {line_num} 行：密码字段为空，将使用默认生成的随机密码。")
                password = generate_password(16)

            key_tuple = (site, username)
            if key_tuple in existing:
                if overwrite:
                    update_password(
                        record_id=existing[key_tuple],
                        note=note, password=password,
                        key=key
                    )
                    overwritten += 1
                    print(f"第 {line_num} 行：{site} / {username} 已存在，已覆盖。")
                else:
                    print(f"第 {line_num} 行：{site} / {username} 已存在，已跳过（使用 --overwrite 覆盖）。")
                    skipped += 1
            else:
                add_password(site, username, password, note, key)
                imported += 1

    print(f"\n导入完成：")
    print(f"  新增: {imported} 条")
    print(f"  覆盖: {overwritten} 条")
    print(f"  跳过: {skipped} 条")
    print(f"  错误: {errors} 条")


def cmd_init(args):
    env_pwd = os.environ.get("VAULT_MASTER_PASSWORD")
    if env_pwd:
        master_password = env_pwd
    else:
        master_password = getpass.getpass("请设置主密码: ")
        confirm_password = getpass.getpass("请确认主密码: ")
        if master_password != confirm_password:
            print("错误：两次输入的主密码不一致！")
            sys.exit(1)

    if not master_password:
        print("错误：主密码不能为空！")
        sys.exit(1)

    init_db(master_password)


def cmd_add(args):
    master_password = get_master_password()
    if not verify_master_password(master_password):
        print("错误：主密码不正确！")
        sys.exit(1)

    key = derive_key(master_password)

    site = args.site
    username = args.username
    password = args.password if args.password else getpass.getpass("请输入密码: ")
    note = args.note if args.note else ""

    add_password(site, username, password, note, key)


def cmd_list(args):
    master_password = get_master_password()
    if not verify_master_password(master_password):
        print("错误：主密码不正确！")
        sys.exit(1)

    key = derive_key(master_password)
    show_pwd = getattr(args, 'show_password', False)
    list_passwords(key, show_password=show_pwd)


def cmd_search(args):
    master_password = get_master_password()
    if not verify_master_password(master_password):
        print("错误：主密码不正确！")
        sys.exit(1)

    key = derive_key(master_password)
    show_pwd = getattr(args, 'show_password', False)
    search_passwords(args.keyword, key, show_password=show_pwd)


def cmd_update(args):
    master_password = get_master_password()
    if not verify_master_password(master_password):
        print("错误：主密码不正确！")
        sys.exit(1)

    key = derive_key(master_password)

    record_id = None
    if hasattr(args, 'id') and args.id:
        record_id = args.id
    elif hasattr(args, 'site') and args.site and hasattr(args, 'username') and args.username:
        record_id = find_record_by_site_username(args.site, args.username, key)
        if not record_id:
            print(f"错误：未找到站点 '{args.site}' 用户名为 '{args.username}' 的记录。")
            sys.exit(1)
    else:
        print("错误：请指定记录 ID (-i/--id) 或同时指定站点 (-s/--site) 和用户名 (-u/--username)")
        sys.exit(1)

    site = args.site if hasattr(args, 'site') and args.site else None
    username = args.username if hasattr(args, 'username') and args.username else None
    password = args.password if hasattr(args, 'password') and args.password else None
    note = args.note if hasattr(args, 'note') and args.note else None

    if not update_password(record_id, site=site, username=username, password=password, note=note, key=key):
        sys.exit(1)


def cmd_delete(args):
    master_password = get_master_password()
    if not verify_master_password(master_password):
        print("错误：主密码不正确！")
        sys.exit(1)

    key = derive_key(master_password)

    confirm = input(f"确定要删除 ID 为 {args.id} 的记录吗？(y/N): ")
    if confirm.lower() == 'y':
        delete_password(args.id, key)
    else:
        print("已取消删除。")


def cmd_generate(args):
    length = args.length if args.length else 16
    use_upper = not args.no_upper
    use_lower = not args.no_lower
    use_digits = not args.no_digits
    use_special = not args.no_special

    password = generate_password(
        length=length,
        use_upper=use_upper,
        use_lower=use_lower,
        use_digits=use_digits,
        use_special=use_special
    )

    print(f"生成的密码: {password}")

    strength = assess_password_strength(password)
    print(f"密码强度: {strength['level']}")
    if strength["issues"]:
        print("提示:")
        for issue in strength["issues"]:
            print(f"  - {issue}")

    if args.save:
        if not args.site or not args.username:
            print("错误：保存为记录需指定 --site 和 --username")
            sys.exit(1)
        master_password = get_master_password()
        if not verify_master_password(master_password):
            print("错误：主密码不正确！")
            sys.exit(1)
        key = derive_key(master_password)
        note = args.note if args.note else ""
        add_password(args.site, args.username, password, note, key)


def cmd_audit(args):
    master_password = get_master_password()
    if not verify_master_password(master_password):
        print("错误：主密码不正确！")
        sys.exit(1)

    key = derive_key(master_password)
    audit_passwords(key)


def cmd_export(args):
    master_password = get_master_password()
    if not verify_master_password(master_password):
        print("错误：主密码不正确！")
        sys.exit(1)

    key = derive_key(master_password)
    output_file = args.output if args.output else "passwords_export.csv"
    export_passwords(key, output_file)


def cmd_import(args):
    master_password = get_master_password()
    if not verify_master_password(master_password):
        print("错误：主密码不正确！")
        sys.exit(1)

    key = derive_key(master_password)
    overwrite = args.overwrite if hasattr(args, 'overwrite') and args.overwrite else False
    import_passwords(key, args.file, overwrite=overwrite)


def cmd_test_auth(args):
    master_password = get_master_password()
    if verify_master_password(master_password):
        print("主密码验证成功！")
    else:
        print("主密码验证失败！")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="命令行密码保险箱 - 本地 CLI 密码管理工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例命令：
  初始化:    python password_vault.py init
  添加记录:  python password_vault.py add -s "GitHub" -u "myuser" -p "mypass" -n "工作账号"
  列表查看:  python password_vault.py list
  查看明文:  python password_vault.py list --show-password
  关键词搜索: python password_vault.py search -k "GitHub"
  修改记录:  python password_vault.py update -i 1 -p "newpassword"
  按站点修改: python password_vault.py update -s "GitHub" -u "myuser" -p "newpassword"
  删除记录:  python password_vault.py delete -i 1
  生成密码:  python password_vault.py generate -l 16 --save -s "test.com" -u "testuser"
  安全体检:  python password_vault.py audit
  导出CSV:   python password_vault.py export -o passwords.csv
  导入CSV:   python password_vault.py import -f passwords.csv
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    subparsers.add_parser("init", help="初始化密码保险箱")

    parser_add = subparsers.add_parser("add", help="添加密码记录")
    parser_add.add_argument("-s", "--site", required=True, help="站点名称")
    parser_add.add_argument("-u", "--username", required=True, help="用户名")
    parser_add.add_argument("-p", "--password", help="密码（不指定则交互式输入）")
    parser_add.add_argument("-n", "--note", help="备注信息")

    parser_list = subparsers.add_parser("list", help="列出所有密码记录")
    parser_list.add_argument("--show-password", action="store_true", help="显示明文密码")

    parser_search = subparsers.add_parser("search", help="搜索密码记录")
    parser_search.add_argument("-k", "--keyword", required=True, help="搜索关键词")
    parser_search.add_argument("--show-password", action="store_true", help="显示明文密码")

    parser_update = subparsers.add_parser("update", help="修改密码记录")
    parser_update.add_argument("-i", "--id", type=int, help="记录 ID")
    parser_update.add_argument("-s", "--site", help="站点名称（与用户名配合使用）")
    parser_update.add_argument("-u", "--username", help="用户名（与站点配合使用）")
    parser_update.add_argument("-p", "--password", help="新的密码")
    parser_update.add_argument("-n", "--note", help="新的备注信息")

    parser_delete = subparsers.add_parser("delete", help="删除密码记录")
    parser_delete.add_argument("-i", "--id", type=int, required=True, help="记录 ID")

    parser_generate = subparsers.add_parser("generate", help="生成随机密码")
    parser_generate.add_argument("-l", "--length", type=int, help="密码长度（默认16）")
    parser_generate.add_argument("--no-upper", action="store_true", help="不包含大写字母")
    parser_generate.add_argument("--no-lower", action="store_true", help="不包含小写字母")
    parser_generate.add_argument("--no-digits", action="store_true", help="不包含数字")
    parser_generate.add_argument("--no-special", action="store_true", help="不包含特殊字符")
    parser_generate.add_argument("--save", action="store_true", help="生成后直接保存为记录")
    parser_generate.add_argument("-s", "--site", help="保存时的站点名称")
    parser_generate.add_argument("-u", "--username", help="保存时的用户名")
    parser_generate.add_argument("-n", "--note", help="保存时的备注信息")

    subparsers.add_parser("audit", help="密码安全体检")

    parser_export = subparsers.add_parser("export", help="导出脱敏 CSV（不含明文密码）")
    parser_export.add_argument("-o", "--output", help="输出文件路径")

    parser_import = subparsers.add_parser("import", help="从 CSV 批量导入记录")
    parser_import.add_argument("-f", "--file", required=True, help="CSV 文件路径")
    parser_import.add_argument("--overwrite", action="store_true", help="重复记录时覆盖已有记录")

    subparsers.add_parser("test-auth", help="测试主密码验证（支持非交互模式）")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    commands = {
        "init": cmd_init,
        "add": cmd_add,
        "list": cmd_list,
        "search": cmd_search,
        "update": cmd_update,
        "delete": cmd_delete,
        "generate": cmd_generate,
        "audit": cmd_audit,
        "export": cmd_export,
        "import": cmd_import,
        "test-auth": cmd_test_auth,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
