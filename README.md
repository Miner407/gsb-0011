# 命令行密码保险箱

本地 CLI 密码管理工具，使用 Python 开发，支持密码加密存储、密码生成、安全体检、导入导出等功能。

## 环境要求

- Python 3.6+
- 无需额外依赖（仅使用标准库）

## 快速开始

### 1. 初始化密码保险箱

```bash
# 交互模式（推荐）
python password_vault.py init

# 非交互模式（适合自动化测试，设置环境变量）
set VAULT_MASTER_PASSWORD=MySecureMaster123
python password_vault.py init
```

### 2. 添加密码记录

```bash
# 完整参数
python password_vault.py add -s "GitHub" -u "myusername" -p "MyP@ssw0rd!" -n "工作账号"

# 使用环境变量免输入主密码
set VAULT_MASTER_PASSWORD=MySecureMaster123
python password_vault.py add -s "Gmail" -u "user@gmail.com" -p "GmailPass2024!" -n "个人邮箱"
```

### 3. 查看密码列表

```bash
# 默认隐藏密码（安全模式）
set VAULT_MASTER_PASSWORD=MySecureMaster123
python password_vault.py list

# 显示明文密码
python password_vault.py list --show-password
```

### 4. 搜索密码记录

```bash
set VAULT_MASTER_PASSWORD=MySecureMaster123
python password_vault.py search -k "GitHub"
python password_vault.py search -k "邮箱" --show-password
```

### 5. 修改密码记录

```bash
set VAULT_MASTER_PASSWORD=MySecureMaster123

# 按 ID 修改
python password_vault.py update -i 1 -p "NewSecureP@ss123" -n "更新了密码"

# 按站点和用户名修改
python password_vault.py update -s "GitHub" -u "myusername" -p "NewGithubP@ss456"
```

### 6. 删除密码记录

```bash
set VAULT_MASTER_PASSWORD=MySecureMaster123
python password_vault.py delete -i 1
```

### 7. 生成随机密码

```bash
# 生成 16 位密码（默认）
python password_vault.py generate

# 生成 32 位高强度密码
python password_vault.py generate -l 32

# 生成不含特殊字符的密码
python password_vault.py generate --no-special

# 生成后直接保存为记录
set VAULT_MASTER_PASSWORD=MySecureMaster123
python password_vault.py generate -l 20 --save -s "Baidu" -u "testuser" -n "百度测试账号"
```

### 8. 密码安全体检

```bash
set VAULT_MASTER_PASSWORD=MySecureMaster123
python password_vault.py audit
```

安全体检会检测以下风险：
- **弱密码**：常见弱密码、长度不足、字符类型单一
- **重复密码**：多条记录使用相同密码
- **过期密码**：超过 90 天未更新
- **缺少备注**：未填写备注信息

输出风险等级（高/中/低）和具体整改建议。

### 9. 导出脱敏 CSV

```bash
set VAULT_MASTER_PASSWORD=MySecureMaster123

# 导出到默认文件 passwords_export.csv
python password_vault.py export

# 导出到指定路径
python password_vault.py export -o "D:\backup\passwords_2024.csv"
```

导出字段（脱敏，不含明文密码）：
- 站点
- 用户名
- 备注
- 创建时间
- 更新时间
- 安全风险等级

### 10. 从 CSV 批量导入

```bash
set VAULT_MASTER_PASSWORD=MySecureMaster123

# 导入（重复记录跳过）
python password_vault.py import -f passwords_import.csv

# 导入（重复记录覆盖）
python password_vault.py import -f passwords_import.csv --overwrite
```

CSV 文件格式要求：
- 必填字段：`站点`、`用户名`
- 可选字段：`密码`、`备注`
- 若密码为空，将自动生成 16 位随机密码

CSV 示例：
```csv
站点,用户名,密码,备注
Twitter,my_twitter,TwitterPass123!,社交账号
LinkedIn,linkedin_user,,职业社交
```

### 11. 测试主密码验证

```bash
# 非交互模式验证
set VAULT_MASTER_PASSWORD=MySecureMaster123
python password_vault.py test-auth
```

## 非交互模式说明

为了方便自动化测试和脚本集成，支持以下两种非交互方式提供主密码：

1. **环境变量**（推荐）：
   ```bash
   set VAULT_MASTER_PASSWORD=你的主密码
   python password_vault.py [命令]
   ```

2. **命令行参数**：
   ```bash
   python password_vault.py [命令] --master-password 你的主密码
   ```

## 可运行验证命令

以下三组命令可快速验证全部功能，使用环境变量避免交互式输入：

### 验证组 1：初始化 + 添加 + 列表 + 搜索

```bat
@echo off
set VAULT_MASTER_PASSWORD=TestMaster123
if exist password_vault.db del password_vault.db

echo === 1. 初始化 ===
python password_vault.py init

echo.
echo === 2. 添加多条记录 ===
python password_vault.py add -s "GitHub" -u "devuser" -p "123456" -n "开发账号"
python password_vault.py add -s "Gmail" -u "dev@gmail.com" -p "123456" -n "开发邮箱"
python password_vault.py add -s "Baidu" -u "baidu_user" -p "B@idu2024Strong!" -n "百度云"

echo.
echo === 3. 列表（隐藏密码模式） ===
python password_vault.py list

echo.
echo === 4. 列表（显示明文） ===
python password_vault.py list --show-password

echo.
echo === 5. 搜索 ===
python password_vault.py search -k "mail"
pause
```

### 验证组 2：密码生成 + 修改 + 安全体检

```bat
@echo off
set VAULT_MASTER_PASSWORD=TestMaster123

echo === 1. 生成随机密码（仅生成） ===
python password_vault.py generate -l 20

echo.
echo === 2. 生成并保存 ===
python password_vault.py generate -l 16 --save -s "Weibo" -u "weibo_user" -n "微博账号"

echo.
echo === 3. 按 ID 修改记录 ===
python password_vault.py update -i 1 -p "NewGitHubP@ss123!" -n "更新了弱密码"

echo.
echo === 4. 按站点+用户名修改 ===
python password_vault.py update -s "Gmail" -u "dev@gmail.com" -p "NewGmailP@ss456!"

echo.
echo === 5. 安全体检 ===
python password_vault.py audit
pause
```

### 验证组 3：导出 + 导入 + 清理

```bat
@echo off
set VAULT_MASTER_PASSWORD=TestMaster123

echo === 1. 导出脱敏 CSV ===
python password_vault.py export -o test_export.csv

echo.
echo === 2. 查看导出文件内容 ===
type test_export.csv

echo.
echo === 3. 准备导入文件 ===
(
echo 站点,用户名,密码,备注
echo Zhihu,zhihu_user,Zh1huP@ss2024!,知乎账号
echo CSDN,csdn_user,,CSDN博客
echo GitHub,devuser,OverwriteP@ss789!,覆盖的GitHub
) > test_import.csv

echo.
echo === 4. 导入（默认跳过重复） ===
python password_vault.py import -f test_import.csv

echo.
echo === 5. 导入（覆盖重复） ===
python password_vault.py import -f test_import.csv --overwrite

echo.
echo === 6. 最终列表 ===
python password_vault.py list --show-password

echo.
echo === 7. 清理测试数据 ===
del password_vault.db test_export.csv test_import.csv
echo 清理完成
pause
```

## 数据存储

- 数据库文件：`password_vault.db`（与脚本同目录）
- 加密方式：使用 SHA-256 派生密钥，XOR 加密所有敏感字段
- 注意：本工具为示例项目，加密方式简单，生产环境请使用专业密码管理工具

## 命令速查表

| 命令 | 说明 | 主要参数 |
|------|------|----------|
| `init` | 初始化保险箱 | - |
| `add` | 添加密码记录 | `-s`站点 `-u`用户名 `-p`密码 `-n`备注 |
| `list` | 列出所有记录 | `--show-password`显示明文 |
| `search` | 搜索记录 | `-k`关键词 `--show-password` |
| `update` | 修改记录 | `-i`ID 或 `-s`站点+`-u`用户名 `-p`新密码 `-n`新备注 |
| `delete` | 删除记录 | `-i`ID |
| `generate` | 生成随机密码 | `-l`长度 `--no-upper/lower/digits/special` `--save` `-s` `-u` `-n` |
| `audit` | 安全体检 | - |
| `export` | 导出脱敏 CSV | `-o`输出文件 |
| `import` | 批量导入 CSV | `-f`文件 `--overwrite` |
| `test-auth` | 验证主密码 | - |
