# jsonl-quarantine

本地 JSONL 坏行隔离工具：保留合法行原始字节，把坏行放入独立二进制文件，
通过包含行号、字节偏移和原因的流水账记录全部输入。不会猜测修复，也不会静默丢弃。
Python 3.11+，无运行时第三方依赖，不联网。

```sh
python -m pip install .
python examples/demo.py
python -m jsonl_quarantine quarantine examples/mixed.jsonl demo-output
python -m jsonl_quarantine verify examples/mixed.jsonl demo-output
```

示例故意含坏行，隔离命令返回 1 表示成功完成但有拒绝记录；验证通过返回 0。
完整安装步骤、参数和退出码见 [英文 README](README.md)。输出目录必须不存在。
`verify` 会根据原文件重新分类，逐字节验证结果及 SHA-256，不只是相信 manifest。

默认每行最多 8 MiB（含换行），大行以小块隔离；JSON 解码对象可能占用更多内存。
默认接受所有 JSON 值，`--objects-only` 只接受对象。拒绝重复键、非有限数值、
非法 UTF-8、BOM、空行、过深结构和不成对代理字符。仅支持本地未压缩普通文件。
没有总磁盘配额；不要并发修改输入或结果。数据文件包含原始内容，不能当作脱敏工具。

使用 `python -m pip uninstall jsonl-quarantine` 卸载；确认不再需要后清理示例输出目录
和虚拟环境。MIT 许可证。测试方式见 [贡献说明](CONTRIBUTING.md)。
