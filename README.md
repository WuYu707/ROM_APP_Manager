# ROM APP Manager

从 ROM 解包目录中扫描、查看、卸载和添加系统 APP，支持 Android 1.0 ~ 16。

## 功能

- **ROM 扫描**：自动扫描所有分区目录（system、vendor、product 等），并行解析 APK 信息
- **AI 批量分析**：一键分析所有应用，自动分类为「可安全卸载 / 谨慎卸载 / 不可卸载」
- **应用管理**：支持添加、卸载系统 APP，自动清理关联文件（权限 XML、overlay、oat 缓存）
- **数据导出**：导出为 CSV / JSON 格式
- **分区统计**：查看各分区应用数量和空间占用


## AI 功能

点击「AI 配置」设置 OpenAI 兼容接口（如 DeepSeek），然后点击「AI 批量分析」。

- AI 分析结果会缓存到 `ai_cache.json`，重复分析秒完成
- 3 秒内连按 3 次「AI 批量分析」可强制重新分析



## 作者

WuYu707

## 版本

v1.0.0

## 许可证

[Apache License 2.0](LICENSE)

## 致谢

- `aapt2.exe` / `aapt_tool.exe` 来自 Android SDK，版权归 Google 所有，遵循 [Apache License 2.0](https://android.googlesource.com/platform/sdk/+/refs/heads/main/LICENSE)
