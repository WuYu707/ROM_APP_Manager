# ROM APP Manager

从 ROM 解包目录中扫描、查看、卸载和添加系统 APP，支持 Android 1.0 ~ 16。

## 功能

- **ROM 扫描**：自动扫描所有分区目录（system、vendor、product 等），并行解析 APK 信息
- **AI 批量分析**：一键分析所有应用，自动分类为「可安全卸载 / 谨慎卸载 / 不可卸载」
- **应用管理**：支持添加、卸载系统 APP，自动清理关联文件（权限 XML、overlay、oat 缓存）
- **数据导出**：导出为 CSV / JSON 格式
- **分区统计**：查看各分区应用数量和空间占用

## 截图

运行后选择 ROM 解包目录即可使用。

## 环境要求

- Windows 10/11
- Python 3.8+（直接运行）或使用打包好的 exe

## 使用方法

### 方式一：直接运行

```bash
py rom_app_manager.py
```

### 方式二：exe 文件

下载 `ROM_APP_Manager.exe` 双击运行，无需 Python 环境。

## APK 解析工具

将 `aapt2.exe` 放入 `phone_tool/` 目录（按优先级）：

1. `aapt2.exe` — 推荐，支持全版本 Android（含 Android 16）
2. `aapt_tool.exe` — 回退，支持到 Android 8.x APK

## AI 功能

点击「AI 配置」设置 OpenAI 兼容接口（如 DeepSeek），然后点击「AI 批量分析」。

- AI 分析结果会缓存到 `ai_cache.json`，重复分析秒完成
- 3 秒内连按 3 次「AI 批量分析」可强制重新分析

## 打包为 exe

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name "ROM_APP_Manager" --add-data "phone_tool;phone_tool" rom_app_manager.py
```

## 作者

wuyu

## 版本

v1.0.0
