"""ELF64 重定位载荷审计服务。

- :mod:`app.elfaudit`: ELF64 ET_REL 重定位审计核心（纯标准库）。
- :mod:`app.server`: 审计页面 / 审计 API / 健康检查的 HTTP 服务。
"""

__all__ = ["elfaudit", "server"]
