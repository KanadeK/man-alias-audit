# man-alias-audit

在安装软件包之前，检查暂存 man 手册树中的 `.so` 别名和文件系统符号链接，
给出完整链路，找出缺失目标、循环、压缩版本冲突与越界路径。
Python 3.11+，无运行依赖、无网络请求，不执行 roff 或格式化命令。

```sh
python -m pip install .
python examples/make_demo.py demo-good
man-alias-audit demo-good
python examples/make_demo.py demo-bad --broken
man-alias-audit demo-bad --json
```

正确示例返回 0；损坏示例返回 1；目录或用法错误返回 2。
根目录应直接包含 `man1`、`man3` 等节目录；不同语言目录请分别运行检查。

关键区别：`.so man1/tool.1` 可以回退到唯一的 `tool.1.gz`；符号链接指向
`tool.1` 时必须存在精确文件，不能自动加上 `.gz`。压缩候选有多个时不会猜测顺序，
而是报告歧义。即使精确文件可用，同时存在多个压缩版本也会使策略检查失败。

支持普通文本、gzip、bzip2、xz 单流 UTF-8 文件。复杂 roff 包含、未知压缩、
越界路径、目录链接和特殊文件不会被当作正常结果。普通终点页面不代表 roff 格式正确。
仅扫描一个语言下的平坦 man 树，不模拟 MANPATH、系统安装路径重映射或任意宏。
完整规则与资源上限见英文 README。

Linux CI 使用原生 zsoelim 对照验证压缩别名链，符号链接/FIFO 测试也在那里执行。
卸载：`python -m pip uninstall man-alias-audit`；演示结束后可删除自己生成的目录。
