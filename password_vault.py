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
from datetime import datetime


VAULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "password_vault.db")


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


def list_passwords(key: bytes) -> None:
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

        print(f"ID: {pid}")
        print(f"  站点:   {site}")
        print(f"  用户名: {username}")
        print(f"  密码:   {password}")
        print(f"  备注:   {note}")
        print(f"  创建:   {created_at}")
        print(f"  更新:   {updated_at}")
        print("-" * 80)


def search_passwords(keyword: str, key: bytes) -> None:
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

        print(f"ID: {pid}")
        print(f"  站点:   {site}")
        print(f"  用户名: {username}")
        print(f"  密码:   {password}")
        print(f"  备注:   {note}")
        print(f"  创建:   {created_at}")
        print(f"  更新:   {updated_at}")
        print("-" * 80)


def update_password(record_id: int, site: str = None, username: str = None,
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


def cmd_init(args):
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
    master_password = getpass.getpass("请输入主密码: ")
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
    master_password = getpass.getpass("请输入主密码: ")
    if not verify_master_password(master_password):
        print("错误：主密码不正确！")
        sys.exit(1)

    key = derive_key(master_password)
    list_passwords(key)


def cmd_search(args):
    master_password = getpass.getpass("请输入主密码: ")
    if not verify_master_password(master_password):
        print("错误：主密码不正确！")
        sys.exit(1)

    key = derive_key(master_password)
    search_passwords(args.keyword, key)


def cmd_update(args):
    master_password = getpass.getpass("请输入主密码: ")
    if not verify_master_password(master_password):
        print("错误：主密码不正确！")
        sys.exit(1)

    key = derive_key(master_password)

    site = args.site if hasattr(args, 'site') and args.site else None
    username = args.username if hasattr(args, 'username') and args.username else None
    password = args.password if hasattr(args, 'password') and args.password else None
    note = args.note if hasattr(args, 'note') and args.note else None

    update_password(args.id, site=site, username=username, password=password, note=note, key=key)


def cmd_delete(args):
    master_password = getpass.getpass("请输入主密码: ")
    if not verify_master_password(master_password):
        print("错误：主密码不正确！")
        sys.exit(1)

    key = derive_key(master_password)

    confirm = input(f"确定要删除 ID 为 {args.id} 的记录吗？(y/N): ")
    if confirm.lower() == 'y':
        delete_password(args.id, key)
    else:
        print("已取消删除。")


def main():
    parser = argparse.ArgumentParser(
        description="命令行密码保险箱 - 本地 CLI 密码管理工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例命令：
  初始化:    python password_vault.py init
  添加记录:  python password_vault.py add -s "GitHub" -u "myuser" -p "mypass" -n "工作账号"
  列表查看:  python password_vault.py list
  关键词搜索: python password_vault.py search -k "GitHub"
  修改记录:  python password_vault.py update -i 1 -p "newpassword"
  删除记录:  python password_vault.py delete -i 1
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    subparsers.add_parser("init", help="初始化密码保险箱")

    parser_add = subparsers.add_parser("add", help="添加密码记录")
    parser_add.add_argument("-s", "--site", required=True, help="站点名称")
    parser_add.add_argument("-u", "--username", required=True, help="用户名")
    parser_add.add_argument("-p", "--password", help="密码（不指定则交互式输入）")
    parser_add.add_argument("-n", "--note", help="备注信息")

    subparsers.add_parser("list", help="列出所有密码记录")

    parser_search = subparsers.add_parser("search", help="搜索密码记录")
    parser_search.add_argument("-k", "--keyword", required=True, help="搜索关键词")

    parser_update = subparsers.add_parser("update", help="修改密码记录")
    parser_update.add_argument("-i", "--id", type=int, required=True, help="记录 ID")
    parser_update.add_argument("-s", "--site", help="新的站点名称")
    parser_update.add_argument("-u", "--username", help="新的用户名")
    parser_update.add_argument("-p", "--password", help="新的密码")
    parser_update.add_argument("-n", "--note", help="新的备注信息")

    parser_delete = subparsers.add_parser("delete", help="删除密码记录")
    parser_delete.add_argument("-i", "--id", type=int, required=True, help="记录 ID")

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
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
