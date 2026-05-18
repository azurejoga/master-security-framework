from __future__ import annotations

import re
import html
import hashlib
import hmac
import time
import json
import urllib.parse
from typing import Any, Optional
from master_security.core import get_logger, get_metrics, create_span
from master_security.core.exceptions import ValidationError, SecurityError
import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Default detection patterns
# ---------------------------------------------------------------------------

DEFAULT_XSS_PATTERNS: list[str] = [
    r"<script[^>]*>.*?</script>",
    r"javascript\s*:",
    r"on(?:load|error|click|mouseover|focus|blur|submit|change|keyup|keydown|mouseout|mouseenter|mouseleave)\s*=",
    r"<iframe[^>]*>",
    r"<object[^>]*>",
    r"<embed[^>]*>",
    r"<applet[^>]*>",
    r"<meta[^>]*http-equiv[^>]*>",
    r"<link[^>]*rel\s*=\s*[\"']?stylesheet",
    r"expression\s*\(",
    r"url\s*\(\s*[\"']?\s*javascript",
    r"<svg[^>]*on\w+\s*=",
    r"<img[^>]*on\w+\s*=",
    r"<body[^>]*on\w+\s*=",
    r"<div[^>]*on\w+\s*=",
    r"<input[^>]*on\w+\s*=",
    r"<form[^>]*action\s*=\s*[\"']?javascript",
    r"document\.(?:cookie|write|location|domain)",
    r"window\.(?:location|open|alert|confirm|prompt)",
    r"eval\s*\(",
    r"setTimeout\s*\(\s*[\"']?",
    r"setInterval\s*\(\s*[\"']?",
    r"Function\s*\(",
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"insertAdjacentHTML\s*\(",
    r"document\.createElement\s*\(\s*[\"']script",
    r"fromCharCode",
    r"atob\s*\(",
    r"\balert\s*\(",
    r"\bprompt\s*\(",
    r"\bconfirm\s*\(",
]

DEFAULT_SQLI_PATTERNS: list[str] = [
    r"(\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|EXECUTE)\b)",
    r"(--|#|/\*)",
    r"(\bOR\b\s+\d+\s*=\s*\d+)",
    r"(\bOR\b\s+[\"'][^\"']*[\"']\s*=\s*[\"'])",
    r"(\bAND\b\s+\d+\s*=\s*\d+)",
    r"(;\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|EXEC))",
    r"(\bWAITFOR\b\s+DELAY\b)",
    r"(\bBENCHMARK\s*\()",
    r"(\bSLEEP\s*\()",
    r"(LOAD_FILE\s*\()",
    r"(INTO\s+(?:OUT|DUMP)FILE\b)",
    r"(\bINFORMATION_SCHEMA\b)",
    r"(\bSYSOBJECTS\b)",
    r"(\bSYSCOLUMNS\b)",
    r"(xp_cmdshell)",
    r"(sp_executesql)",
    r"(\bHAVING\b\s+\d+)",
    r"(\bGROUP\s+BY\b\s+\d+)",
    r"(ORDER\s+BY\s+\d+)",
    r"(\bUNION\s+ALL\s+SELECT\b)",
    r"(';\s*--)",
    r"(\bCHAR\s*\(\s*\d+\s*\))",
    r"(\bCONCAT\s*\()",
    r"(\bGROUP_CONCAT\s*\()",
    r"(\bSUBSTRING\s*\()",
    r"(\bMID\s*\()",
    r"(\bLEFT\s*\(\s*@@version)",
    r"(\bversion\s*\(\s*\))",
    r"(\bDATABASE\s*\(\s*\))",
    r"(\bUSER\s*\(\s*\))",
    r"(\bCURRENT_USER\b)",
    r"(\bSYSTEM_USER\b)",
    r"(\bSESSION_USER\b)",
    r"(0x[0-9a-fA-F]+)",
]

DEFAULT_SSRF_PATTERNS: list[str] = [
    r"(?:127\.0\.0\.1|localhost|0\.0\.0\.0)",
    r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    r"(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})",
    r"(?:192\.168\.\d{1,3}\.\d{1,3})",
    r"(?:169\.254\.\d{1,3}\.\d{1,3})",
    r"(?:\[::1\]|::1|0:0:0:0:0:0:0:1)",
    r"(?:fd[0-9a-f]{2}:)",
    r"(?:fe80:)",
    r"(?:0x[0-9a-fA-F]+)",
    r"(?:\d+\.\d+\.\d+\.\d+)",
    r"(?:xip\.io|nip\.io|sslip\.io|localtest\.me|lvh\.me)",
    r"(?:metadata\.google\.internal|169\.254\.169\.254)",
    r"(?:instance-data|100\.100\.100\.200)",
    r"(?:file://)",
    r"(?:gopher://)",
    r"(?:dict://)",
    r"(?:ldap://)",
    r"(?:tftp://)",
]

DEFAULT_RCE_PATTERNS: list[str] = [
    r"\b(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(",
    r"\b(?:Runtime\.getRuntime|ProcessBuilder)\b",
    r"\b(?:subprocess|os\.system|os\.popen|os\.exec)\b",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bcompile\s*\(",
    r"\b__import__\s*\(",
    r"\bgetattr\s*\(.*__",
    r"\bsetattr\s*\(.*__",
    r"\bglobals\s*\(\s*\)",
    r"\blocals\s*\(\s*\)",
    r"\bvars\s*\(\s*\)",
    r"\bdir\s*\(\s*\)",
    r"\btype\s*\(\s*\)\s*\(",
    r"\bobject\s*\(\s*\)\.__",
    r"\b__class__\b",
    r"\b__bases__\b",
    r"\b__subclasses__\b",
    r"\b__mro__\b",
    r"\b__globals__\b",
    r"\b__builtins__\b",
    r"\b__dict__\b",
    r"\b__reduce__\b",
    r"\b__reduce_ex__\b",
    r"\b__getstate__\b",
    r"\b__setstate__\b",
    r"\bpickle\b",
    r"\byaml\.load\b",
    r"\bmarshal\.loads?\b",
    r"\bshelve\b",
    r"\bimportlib\b",
    r"\bctypes\b",
    r"\bffi\b",
    r"\bdlopen\b",
    r"(?:\||;|&&|\|\|)\s*(?:cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl|ruby|php)",
    r"\$\{[^}]*\}",
    r"`[^`]+`",
    r"\$\([^)]+\)",
]

DEFAULT_LFI_PATTERNS: list[str] = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e/",
    r"\.\.%2f",
    r"%252e%252e%252f",
    r"/etc/(?:passwd|shadow|hosts|group|sudoers|crontab|fstab)",
    r"/proc/(?:self|version|cmdline|environ|maps|mounts|net)",
    r"/var/log/",
    r"C:\\\\Windows\\\\",
    r"C:\\\\Program Files",
    r"boot\.ini",
    r"win\.ini",
    r"php://(?:filter|input|expect|data|zip|phar)",
    r"data://",
    r"expect://",
    r"file://",
    r"zip://",
    r"phar://",
]

DEFAULT_RFI_PATTERNS: list[str] = [
    r"https?://[^/\s]+\.(?:php|asp|aspx|jsp|cgi|pl|py|rb)\b",
    r"https?://[^/\s]+/shell",
    r"https?://[^/\s]+/c99",
    r"https?://[^/\s]+/r57",
    r"https?://[^/\s]+/webshell",
    r"https?://[^/\s]+/backdoor",
    r"https?://[^/\s]+/cmd",
    r"https?://[^/\s]+/upload",
    r"=https?://",
    r"\?https?://",
    r"\binclude\s*\(\s*[\"']https?://",
    r"\brequire\s*\(\s*[\"']https?://",
]

DEFAULT_CMD_INJECTION_PATTERNS: list[str] = [
    r"[;|&`]\s*(?:cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl|ruby|php|rm|mv|cp|chmod|chown|kill|ps|netstat|ifconfig|ipconfig|nmap|tcpdump)",
    r"\$\([^)]+\)",
    r"`[^`]+`",
    r"\$\{[^}]+\}",
    r"\|\s*(?:bash|sh|cmd|powershell|python|perl|ruby|php)\b",
    r";\s*(?:bash|sh|cmd|powershell|python|perl|ruby|php)\b",
    r"&&\s*(?:bash|sh|cmd|powershell|python|perl|ruby|php)\b",
    r"\|\|\s*(?:bash|sh|cmd|powershell|python|perl|ruby|php)\b",
    r">\s*/dev/tcp/",
    r"<\s*/dev/tcp/",
    r"/dev/(?:tcp|udp)/",
    r"\bnc\s+-[elp]",
    r"\bncat\b",
    r"\bsocat\b",
    r"\bbase64\s+-d\b",
    r"\bxor\s+",
    r"\bxxd\b",
    r"\bod\b.*-A",
]

DEFAULT_TEMPLATE_INJECTION_PATTERNS: dict[str, list[str]] = {
    "jinja2": [
        r"\{\{.*\}\}",
        r"\{%.*%\}",
        r"\{#.*#\}",
        r"\bconfig\b",
        r"\bself\b",
        r"\brequest\b",
        r"\bcycler\b",
        r"\bjoiner\b",
        r"\bnamespace\b",
        r"\blipsum\b",
        r"\bdict\b",
        r"\bclass\b",
        r"\b__mro__\b",
        r"\b__subclasses__\b",
        r"\b__globals__\b",
        r"\b__builtins__\b",
    ],
    "twig": [
        r"\{\{.*\}\}",
        r"\{%.*%\}",
        r"\{#.*#\}",
        r"\b_app\b",
        r"\b_request\b",
        r"\b_session\b",
        r"\b_globals\b",
        r"\b_self\b",
    ],
    "ejs": [
        r"<%.*%>",
        r"<%-.*%>",
        r"<%=.*%>",
        r"\bprocess\b",
        r"\bglobal\b",
        r"\brequire\b",
    ],
    "handlebars": [
        r"\{\{.*\}\}",
        r"\{\{#.*\}\}",
        r"\bhelper\b",
        r"\bpartial\b",
    ],
    "mako": [
        r"\$\{.*\}",
        r"<%.*%>",
        r"\bcontext\b",
        r"\bself\b",
        r"\bnext\b",
        r"\bparent\b",
    ],
    "pug": [
        r"#\{.*\}",
        r"!\{.*\}",
        r"\beach\b",
        r"\binclude\b",
        r"\bextends\b",
    ],
    "default": [
        r"\{\{.*\}\}",
        r"\{%.*%\}",
        r"<%.*%>",
        r"\$\{.*\}",
        r"#\{.*\}",
    ],
}

DEFAULT_DANGEROUS_JS_PATTERNS: list[str] = [
    r"eval\s*\(",
    r"Function\s*\(",
    r"setTimeout\s*\(\s*[\"']",
    r"setInterval\s*\(\s*[\"']",
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"insertAdjacentHTML\s*\(",
    r"execScript\s*\(",
    r"import\s*\(",
    r"new\s+Function\s*\(",
]

DEFAULT_ALLOWED_TAGS: list[str] = [
    "p", "br", "strong", "em", "u", "s", "blockquote", "code", "pre",
    "ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6", "a", "img",
    "table", "thead", "tbody", "tr", "th", "td", "div", "span", "hr",
    "dl", "dt", "dd", "abbr", "acronym", "b", "i", "sub", "sup", "tt",
    "kbd", "var", "q", "cite", "dfn", "address", "bdo", "del", "ins",
]

DEFAULT_ALLOWED_ATTRS: list[str] = [
    "href", "src", "alt", "title", "class", "id", "style", "target",
    "rel", "width", "height", "colspan", "rowspan", "abbr", "cite",
    "datetime", "lang", "dir", "tabindex", "accesskey", "role",
    "aria-label", "aria-describedby", "aria-hidden",
]

DEFAULT_ALLOWED_CSS_PROPERTIES: list[str] = [
    "color", "background-color", "background", "font-size", "font-weight",
    "font-family", "text-align", "text-decoration", "margin", "padding",
    "border", "border-radius", "width", "height", "display", "position",
    "top", "right", "bottom", "left", "float", "clear", "overflow",
    "opacity", "visibility", "z-index", "cursor", "line-height",
    "letter-spacing", "word-spacing", "white-space", "vertical-align",
    "box-shadow", "text-shadow", "transform", "transition", "animation",
]

DEFAULT_ALLOWED_SVG_ELEMENTS: list[str] = [
    "svg", "g", "path", "circle", "ellipse", "rect", "line", "polyline",
    "polygon", "text", "tspan", "defs", "clipPath", "linearGradient",
    "radialGradient", "stop", "use", "marker", "pattern", "filter",
    "feGaussianBlur", "feOffset", "feMerge", "feMergeNode", "feFlood",
    "feComposite", "feColorMatrix", "feBlend", "feImage", "feTile",
    "feDiffuseLighting", "feSpecularLighting", "feDropShadow",
    "feMorphology", "feConvolveMatrix", "feDisplacementMap",
    "feTurbulence", "feComponentTransfer", "feFuncR", "feFuncG",
    "feFuncB", "feFuncA",
]

DEFAULT_ALLOWED_ORIGINS: list[str] = []
DEFAULT_ALLOWED_METHODS: list[str] = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
DEFAULT_ALLOWED_HEADERS: list[str] = ["Content-Type", "Authorization", "Accept", "X-Requested-With"]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _classify_xss_severity(pattern: str) -> str:
    """Classify XSS pattern severity."""
    critical_patterns = [
        r"eval\s*\(", r"document\.(?:cookie|write|location|domain)",
        r"window\.(?:location|open)", r"Function\s*\(",
        r"innerHTML\s*=", r"insertAdjacentHTML",
    ]
    high_patterns = [
        r"<script[^>]*>", r"javascript\s*:", r"on\w+\s*=",
        r"<iframe", r"<object", r"<embed",
    ]
    for p in critical_patterns:
        if re.search(p, pattern):
            return "critical"
    for p in high_patterns:
        if re.search(p, pattern):
            return "high"
    return "medium"


def _xss_pattern_score(pattern: str) -> float:
    """Score an XSS pattern by danger level."""
    critical_patterns = [r"eval\s*\(", r"document\.cookie", r"Function\s*\("]
    high_patterns = [r"<script", r"javascript\s*:", r"on\w+\s*="]
    for p in critical_patterns:
        if re.search(p, pattern):
            return 0.95
    for p in high_patterns:
        if re.search(p, pattern):
            return 0.85
    return 0.6


def _max_severity(matches: list[dict[str, Any]]) -> str:
    """Return the highest severity from a list of matches."""
    order = ["none", "low", "medium", "high", "critical"]
    max_idx = 0
    for m in matches:
        idx = order.index(m["severity"]) if m["severity"] in order else 0
        max_idx = max(max_idx, idx)
    return order[max_idx]


def _classify_sqli_severity(pattern: str) -> str:
    """Classify SQL injection pattern severity."""
    critical_patterns = [
        r"xp_cmdshell", r"sp_executesql", r"WAITFOR\s+DELAY",
        r"BENCHMARK\s*\(", r"SLEEP\s*\(", r"INTO\s+(?:OUT|DUMP)FILE",
    ]
    high_patterns = [
        r"UNION\s+ALL\s+SELECT", r";\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)",
        r"INFORMATION_SCHEMA", r"LOAD_FILE\s*\(",
    ]
    for p in critical_patterns:
        if re.search(p, pattern, re.IGNORECASE):
            return "critical"
    for p in high_patterns:
        if re.search(p, pattern, re.IGNORECASE):
            return "high"
    return "medium"


def _sqli_pattern_score(pattern: str) -> float:
    """Score an SQL injection pattern by danger level."""
    critical_patterns = [r"xp_cmdshell", r"WAITFOR", r"BENCHMARK", r"SLEEP"]
    high_patterns = [r"UNION.*SELECT", r"INFORMATION_SCHEMA", r";.*SELECT"]
    for p in critical_patterns:
        if re.search(p, pattern, re.IGNORECASE):
            return 0.95
    for p in high_patterns:
        if re.search(p, pattern, re.IGNORECASE):
            return 0.85
    return 0.6


def _classify_nosqli_severity(pattern: str) -> str:
    """Classify NoSQL injection pattern severity."""
    critical_patterns = [r"\$where", r"\$function", r"\$accumulator", r"db\.\w+\s*\("]
    high_patterns = [r"\$regex", r"\$exists", r"\$expr", r"\$jsonSchema"]
    for p in critical_patterns:
        if re.search(p, pattern):
            return "critical"
    for p in high_patterns:
        if re.search(p, pattern):
            return "high"
    return "medium"


def _nosqli_pattern_score(pattern: str) -> float:
    """Score a NoSQL injection pattern by danger level."""
    critical_patterns = [r"\$where", r"\$function", r"db\."]
    high_patterns = [r"\$regex", r"\$exists", r"\$expr"]
    for p in critical_patterns:
        if re.search(p, pattern):
            return 0.95
    for p in high_patterns:
        if re.search(p, pattern):
            return 0.85
    return 0.6


def _classify_ssrf_severity(pattern: str) -> str:
    """Classify SSRF pattern severity."""
    critical_patterns = [
        r"metadata\.google\.internal", r"169\.254\.169\.254",
        r"instance-data", r"100\.100\.100\.200",
        r"file://", r"gopher://", r"dict://",
    ]
    high_patterns = [
        r"127\.0\.0\.1", r"localhost", r"::1",
        r"10\.", r"172\.(?:1[6-9]|2\d|3[01])\.", r"192\.168\.",
    ]
    for p in critical_patterns:
        if re.search(p, pattern):
            return "critical"
    for p in high_patterns:
        if re.search(p, pattern):
            return "high"
    return "medium"


def _ssrf_pattern_score(pattern: str) -> float:
    """Score an SSRF pattern by danger level."""
    critical_patterns = [r"metadata\.google", r"169\.254\.169\.254", r"file://", r"gopher://"]
    high_patterns = [r"127\.0\.0\.1", r"localhost", r"10\.", r"192\.168\."]
    for p in critical_patterns:
        if re.search(p, pattern):
            return 0.95
    for p in high_patterns:
        if re.search(p, pattern):
            return 0.85
    return 0.6


def _classify_rce_severity(pattern: str) -> str:
    """Classify RCE pattern severity."""
    critical_patterns = [
        r"system\s*\(", r"exec\s*\(", r"shell_exec", r"popen",
        r"Runtime\.getRuntime", r"os\.system", r"os\.popen",
        r"__reduce__", r"__reduce_ex__", r"__subclasses__",
        r"__builtins__", r"__globals__", r"pickle",
    ]
    high_patterns = [
        r"eval\s*\(", r"compile\s*\(", r"__import__",
        r"getattr\s*\(.*__", r"setattr\s*\(.*__",
        r"globals\s*\(", r"locals\s*\(",
    ]
    for p in critical_patterns:
        if re.search(p, pattern):
            return "critical"
    for p in high_patterns:
        if re.search(p, pattern):
            return "high"
    return "medium"


def _rce_pattern_score(pattern: str) -> float:
    """Score an RCE pattern by danger level."""
    critical_patterns = [r"system\s*\(", r"os\.system", r"__reduce__", r"pickle"]
    high_patterns = [r"eval\s*\(", r"__import__", r"globals\s*\("]
    for p in critical_patterns:
        if re.search(p, pattern):
            return 0.95
    for p in high_patterns:
        if re.search(p, pattern):
            return 0.85
    return 0.6


def _classify_lfi_severity(pattern: str) -> str:
    """Classify LFI pattern severity."""
    critical_patterns = [
        r"/etc/passwd", r"/etc/shadow", r"php://filter",
        r"php://input", r"php://expect", r"data://",
        r"/proc/self/environ", r"/proc/self/cmdline",
    ]
    high_patterns = [
        r"\.\./", r"\.\.\\", r"%2e%2e",
        r"/proc/", r"/var/log/",
    ]
    for p in critical_patterns:
        if re.search(p, pattern):
            return "critical"
    for p in high_patterns:
        if re.search(p, pattern):
            return "high"
    return "medium"


def _lfi_pattern_score(pattern: str) -> float:
    """Score an LFI pattern by danger level."""
    critical_patterns = [r"/etc/passwd", r"/etc/shadow", r"php://", r"data://"]
    high_patterns = [r"\.\./", r"\.\.\\", r"/proc/"]
    for p in critical_patterns:
        if re.search(p, pattern):
            return 0.95
    for p in high_patterns:
        if re.search(p, pattern):
            return 0.85
    return 0.6


def _classify_rfi_severity(pattern: str) -> str:
    """Classify RFI pattern severity."""
    critical_patterns = [
        r"/shell", r"/c99", r"/r57", r"/webshell",
        r"/backdoor", r"/cmd", r"include\s*\(.*https?://",
    ]
    high_patterns = [
        r"https?://[^/\s]+\.(?:php|asp|aspx|jsp)",
        r"require\s*\(.*https?://",
    ]
    for p in critical_patterns:
        if re.search(p, pattern):
            return "critical"
    for p in high_patterns:
        if re.search(p, pattern):
            return "high"
    return "medium"


def _rfi_pattern_score(pattern: str) -> float:
    """Score an RFI pattern by danger level."""
    critical_patterns = [r"/shell", r"/c99", r"/webshell", r"include.*https"]
    high_patterns = [r"\.php", r"\.asp", r"require.*https"]
    for p in critical_patterns:
        if re.search(p, pattern):
            return 0.95
    for p in high_patterns:
        if re.search(p, pattern):
            return 0.85
    return 0.6


def _classify_template_severity(pattern: str, engine: str) -> str:
    """Classify template injection pattern severity."""
    critical_patterns = [
        r"__mro__", r"__subclasses__", r"__globals__",
        r"__builtins__", r"__class__", r"config",
        r"process\b", r"require\b", r"context\b",
    ]
    high_patterns = [
        r"\{\{.*\}\}", r"\{%.*%\}", r"<%.*%>",
        r"self\b", r"request\b", r"_app\b",
    ]
    for p in critical_patterns:
        if re.search(p, pattern):
            return "critical"
    for p in high_patterns:
        if re.search(p, pattern):
            return "high"
    return "medium"


def _template_pattern_score(pattern: str, engine: str) -> float:
    """Score a template injection pattern by danger level."""
    critical_patterns = [r"__mro__", r"__subclasses__", r"__globals__", r"config"]
    high_patterns = [r"\{\{", r"\{%", r"<%", r"self"]
    for p in critical_patterns:
        if re.search(p, pattern):
            return 0.95
    for p in high_patterns:
        if re.search(p, pattern):
            return 0.85
    return 0.6


def _classify_cmd_injection_severity(pattern: str) -> str:
    """Classify command injection pattern severity."""
    critical_patterns = [
        r"/dev/tcp", r"nc\s+-[elp]", r"ncat", r"socat",
        r"base64\s+-d", r"\|\s*(?:bash|sh|cmd|powershell)",
    ]
    high_patterns = [
        r"[;|&`]\s*(?:cat|ls|id|whoami|uname|pwd|wget|curl)",
        r"\$\([^)]+\)", r"`[^`]+`",
    ]
    for p in critical_patterns:
        if re.search(p, pattern):
            return "critical"
    for p in high_patterns:
        if re.search(p, pattern):
            return "high"
    return "medium"


def _cmd_injection_pattern_score(pattern: str) -> float:
    """Score a command injection pattern by danger level."""
    critical_patterns = [r"/dev/tcp", r"nc\s+-", r"ncat", r"socat"]
    high_patterns = [r"[;|&`]\s*(?:cat|ls|id)", r"\$\(", r"`"]
    for p in critical_patterns:
        if re.search(p, pattern):
            return 0.95
    for p in high_patterns:
        if re.search(p, pattern):
            return 0.85
    return 0.6


def _classify_deserialization_severity(pattern: str) -> str:
    """Classify deserialization pattern severity."""
    critical_patterns = [
        r"__reduce__", r"__reduce_ex__", r"system", r"popen",
        r"!!python/object", r"!!ruby/object", r"!!php/object",
        r"BinaryFormatter", r"LosFormatter",
        r"org\.apache\.commons\.collections",
    ]
    high_patterns = [
        r"!!python/object/new", r"!!python/object/apply",
        r"java\.util\.", r"java\.lang\.",
        r"O:\d+:", r"\$type", r"__proto__",
    ]
    for p in critical_patterns:
        if re.search(p, pattern):
            return "critical"
    for p in high_patterns:
        if re.search(p, pattern):
            return "high"
    return "medium"


def _deserialization_pattern_score(pattern: str) -> float:
    """Score a deserialization pattern by danger level."""
    critical_patterns = [r"__reduce__", r"system", r"!!python/object", r"BinaryFormatter"]
    high_patterns = [r"!!python/object/new", r"java\.", r"\$type", r"O:\d+"]
    for p in critical_patterns:
        if re.search(p, pattern):
            return 0.95
    for p in high_patterns:
        if re.search(p, pattern):
            return 0.85
    return 0.6


def _classify_path_traversal_severity(pattern: str) -> str:
    """Classify path traversal pattern severity."""
    critical_patterns = [
        r"/etc/passwd", r"/etc/shadow", r"/proc/self",
        r"boot\.ini", r"win\.ini",
    ]
    high_patterns = [
        r"\.\./", r"\.\.\\", r"%2e%2e",
    ]
    for p in critical_patterns:
        if re.search(p, pattern):
            return "critical"
    for p in high_patterns:
        if re.search(p, pattern):
            return "high"
    return "medium"


def _path_traversal_pattern_score(pattern: str) -> float:
    """Score a path traversal pattern by danger level."""
    critical_patterns = [r"/etc/passwd", r"/etc/shadow", r"/proc/self"]
    high_patterns = [r"\.\./", r"\.\.\\", r"%2e%2e"]
    for p in critical_patterns:
        if re.search(p, pattern):
            return 0.95
    for p in high_patterns:
        if re.search(p, pattern):
            return 0.85
    return 0.6


def _classify_redirect_severity(pattern: str) -> str:
    """Classify redirect pattern severity."""
    critical_patterns = [r"javascript\s*:", r"data\s*:"]
    high_patterns = [r"//[^/]", r"\\/", r"@.*\."]
    for p in critical_patterns:
        if re.search(p, pattern):
            return "critical"
    for p in high_patterns:
        if re.search(p, pattern):
            return "high"
    return "medium"


def _redirect_pattern_score(pattern: str) -> float:
    """Score a redirect pattern by danger level."""
    critical_patterns = [r"javascript\s*:", r"data\s*:"]
    high_patterns = [r"//[^/]", r"@.*\."]
    for p in critical_patterns:
        if re.search(p, pattern):
            return 0.95
    for p in high_patterns:
        if re.search(p, pattern):
            return 0.85
    return 0.6


def _safe_resolve_path(base_path: str, user_path: str) -> str:
    """Safely resolve a user-provided path against a base path."""
    base = base_path.replace("\\", "/").rstrip("/")
    user = user_path.replace("\\", "/")
    user = user.replace("\x00", "")
    combined = base + "/" + user.lstrip("/")
    parts = combined.split("/")
    resolved: list[str] = []
    for part in parts:
        if part == "..":
            if resolved:
                resolved.pop()
        elif part and part != ".":
            resolved.append(part)
    return "/" + "/".join(resolved)


# ---------------------------------------------------------------------------
# 1. detect_xss
# ---------------------------------------------------------------------------

def detect_xss(
    input_str: str,
    patterns: Optional[list[str]] = None,
    severity_threshold: str = "low",
) -> dict[str, Any]:
    """Detect Cross-Site Scripting (XSS) attack patterns in input string.

    Args:
        input_str: The input string to analyze for XSS patterns.
        patterns: Optional list of regex patterns. Uses DEFAULT_XSS_PATTERNS if None.
        severity_threshold: Minimum severity to report ('low', 'medium', 'high', 'critical').

    Returns:
        dict with keys: detected (bool), severity (str), matches (list), score (float).

    Example:
        >>> detect_xss('<script>alert(1)</script>')
        {'detected': True, 'severity': 'high', 'matches': [...], 'score': 0.9}
    """
    metrics = get_metrics()
    metrics.inc_counter("web.detect_xss.calls")

    with create_span("detect_xss") as span:
        if not input_str:
            span.set_attribute("empty_input", True)
            return {"detected": False, "severity": "none", "matches": [], "score": 0.0}

        active_patterns = patterns or DEFAULT_XSS_PATTERNS
        severity_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        threshold = severity_levels.get(severity_threshold, 0)

        matches: list[dict[str, Any]] = []
        max_score = 0.0

        for pattern in active_patterns:
            try:
                found = re.findall(pattern, input_str, re.IGNORECASE | re.DOTALL)
                if found:
                    severity = _classify_xss_severity(pattern)
                    if severity_levels.get(severity, 0) >= threshold:
                        matches.append({
                            "pattern": pattern,
                            "match": found[0] if isinstance(found[0], str) else str(found[0]),
                            "severity": severity,
                        })
                        score = _xss_pattern_score(pattern)
                        max_score = max(max_score, score)
            except re.error:
                logger.warning("invalid_xss_pattern", pattern=pattern)

        detected = len(matches) > 0
        overall_severity = _max_severity(matches) if matches else "none"

        logger.info(
            "xss_detection_complete",
            detected=detected,
            severity=overall_severity,
            match_count=len(matches),
        )

        span.set_attribute("detected", detected)
        span.set_attribute("severity", overall_severity)
        metrics.inc_counter("web.detect_xss.detected" if detected else "web.detect_xss.clean")

        return {
            "detected": detected,
            "severity": overall_severity,
            "matches": matches,
            "score": round(max_score, 2),
        }


# ---------------------------------------------------------------------------
# 2. sanitize_html
# ---------------------------------------------------------------------------

def sanitize_html(
    html_str: str,
    allowed_tags: Optional[list[str]] = None,
    allowed_attrs: Optional[list[str]] = None,
) -> str:
    """Sanitize HTML by removing disallowed tags and attributes.

    Args:
        html_str: The HTML string to sanitize.
        allowed_tags: List of allowed HTML tag names. Defaults to DEFAULT_ALLOWED_TAGS.
        allowed_attrs: List of allowed HTML attribute names. Defaults to DEFAULT_ALLOWED_ATTRS.

    Returns:
        Sanitized HTML string with only allowed tags and attributes.

    Example:
        >>> sanitize_html('<script>alert(1)</script><p>Hello</p>')
        '<p>Hello</p>'
    """
    metrics = get_metrics()
    metrics.inc_counter("web.sanitize_html.calls")

    with create_span("sanitize_html") as span:
        if not html_str:
            return ""

        tags = allowed_tags or DEFAULT_ALLOWED_TAGS
        attrs = allowed_attrs or DEFAULT_ALLOWED_ATTRS

        dangerous_tags = ["script", "style", "iframe", "object", "embed", "applet", "form", "input", "button", "textarea", "select"]
        for tag in dangerous_tags:
            if tag not in tags:
                html_str = re.sub(
                    rf"<{tag}[^>]*>.*?</{tag}>",
                    "",
                    html_str,
                    flags=re.IGNORECASE | re.DOTALL,
                )
                html_str = re.sub(
                    rf"<{tag}[^>]*/?>",
                    "",
                    html_str,
                    flags=re.IGNORECASE,
                )

        html_str = re.sub(
            r"\s*on\w+\s*=\s*(?:[\"'][^\"']*[\"']|\S+)",
            "",
            html_str,
            flags=re.IGNORECASE,
        )
        html_str = re.sub(
            r"javascript\s*:",
            "blocked:",
            html_str,
            flags=re.IGNORECASE,
        )

        def filter_tag(match: re.Match[str]) -> str:
            tag_name = match.group(1).lower()
            if tag_name in tags:
                return match.group(0)
            return ""

        html_str = re.sub(r"</?([a-zA-Z][a-zA-Z0-9]*)\b[^>]*/?>", filter_tag, html_str)

        def filter_attrs(match: re.Match[str]) -> str:
            tag = match.group(1)
            attr_str = match.group(2) or ""
            if tag.lower() not in tags:
                return ""
            filtered_attrs = []
            for attr_match in re.finditer(r'([a-zA-Z][\w-]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|(\S+))', attr_str):
                attr_name = attr_match.group(1).lower()
                if attr_name in attrs:
                    attr_value = attr_match.group(2) or attr_match.group(3) or attr_match.group(4) or ""
                    if attr_name in ("href", "src", "action") and re.match(r"javascript\s*:", attr_value, re.IGNORECASE):
                        continue
                    filtered_attrs.append(f'{attr_name}="{attr_value}"')
            if filtered_attrs:
                return f"<{tag} {' '.join(filtered_attrs)}>"
            return f"<{tag}>"

        html_str = re.sub(r"<([a-zA-Z][a-zA-Z0-9]*)(\s[^>]*)?>", filter_attrs, html_str)
        html_str = re.sub(r"</([a-zA-Z][a-zA-Z0-9]*)>", lambda m: f"</{m.group(1)}>" if m.group(1).lower() in tags else "", html_str)

        span.set_attribute("input_length", len(html_str))
        metrics.inc_counter("web.sanitize_html.completed")

        return html_str


# ---------------------------------------------------------------------------
# 3. sanitize_svg
# ---------------------------------------------------------------------------

def sanitize_svg(
    svg: str,
    allowed_elements: Optional[list[str]] = None,
) -> str:
    """Sanitize SVG content by removing dangerous elements and attributes.

    Args:
        svg: The SVG string to sanitize.
        allowed_elements: List of allowed SVG element names. Defaults to DEFAULT_ALLOWED_SVG_ELEMENTS.

    Returns:
        Sanitized SVG string.

    Example:
        >>> sanitize_svg('<svg><script>alert(1)</script><rect/></svg>')
        '<svg><rect/></svg>'
    """
    metrics = get_metrics()
    metrics.inc_counter("web.sanitize_svg.calls")

    with create_span("sanitize_svg") as span:
        if not svg:
            return ""

        elements = allowed_elements or DEFAULT_ALLOWED_SVG_ELEMENTS

        dangerous = ["script", "style", "foreignObject", "animate", "animateTransform", "animateMotion", "set", "discard"]
        for tag in dangerous:
            svg = re.sub(
                rf"<{tag}[^>]*>.*?</{tag}>",
                "",
                svg,
                flags=re.IGNORECASE | re.DOTALL,
            )
            svg = re.sub(
                rf"<{tag}[^>]*/?>",
                "",
                svg,
                flags=re.IGNORECASE,
            )

        svg = re.sub(
            r"\s*on\w+\s*=\s*(?:[\"'][^\"']*[\"']|\S+)",
            "",
            svg,
            flags=re.IGNORECASE,
        )
        svg = re.sub(
            r"javascript\s*:",
            "blocked:",
            svg,
            flags=re.IGNORECASE,
        )

        def filter_svg_tag(match: re.Match[str]) -> str:
            tag_name = match.group(1)
            if tag_name.lower() in [e.lower() for e in elements]:
                return match.group(0)
            return ""

        svg = re.sub(r"</?([a-zA-Z][a-zA-Z0-9]*)\b[^>]*/?>", filter_svg_tag, svg)

        svg = re.sub(
            r'\s*xlink:href\s*=\s*(?:"[^"]*"|\'[^\']*\'|\S+)',
            "",
            svg,
            flags=re.IGNORECASE,
        )

        span.set_attribute("input_length", len(svg))
        metrics.inc_counter("web.sanitize_svg.completed")

        return svg


# ---------------------------------------------------------------------------
# 4. sanitize_markdown
# ---------------------------------------------------------------------------

def sanitize_markdown(
    markdown: str,
    allowed_html: Optional[list[str]] = None,
) -> str:
    """Sanitize markdown content by removing dangerous HTML embedded within.

    Args:
        markdown: The markdown string to sanitize.
        allowed_html: List of allowed HTML tags within markdown. Defaults to DEFAULT_ALLOWED_TAGS.

    Returns:
        Sanitized markdown string.

    Example:
        >>> sanitize_markdown('# Hello\\n<script>alert(1)</script>')
        '# Hello\\n'
    """
    metrics = get_metrics()
    metrics.inc_counter("web.sanitize_markdown.calls")

    with create_span("sanitize_markdown") as span:
        if not markdown:
            return ""

        tags = allowed_html or DEFAULT_ALLOWED_TAGS

        dangerous = ["script", "style", "iframe", "object", "embed", "applet", "form", "link", "meta"]
        for tag in dangerous:
            markdown = re.sub(
                rf"<{tag}[^>]*>.*?</{tag}>",
                "",
                markdown,
                flags=re.IGNORECASE | re.DOTALL,
            )
            markdown = re.sub(
                rf"<{tag}[^>]*/?>",
                "",
                markdown,
                flags=re.IGNORECASE,
            )

        markdown = re.sub(
            r"\s*on\w+\s*=\s*(?:[\"'][^\"']*[\"']|\S+)",
            "",
            markdown,
            flags=re.IGNORECASE,
        )

        markdown = re.sub(
            r"\[([^\]]*)\]\s*\(\s*javascript:[^)]*\)",
            r"[\1](#blocked)",
            markdown,
            flags=re.IGNORECASE,
        )

        markdown = re.sub(
            r"!\[([^\]]*)\]\s*\(\s*data:[^)]*\)",
            r"![\1](#blocked)",
            markdown,
            flags=re.IGNORECASE,
        )

        def filter_md_tag(match: re.Match[str]) -> str:
            tag_name = match.group(1).lower()
            if tag_name in tags:
                return match.group(0)
            return ""

        markdown = re.sub(r"</?([a-zA-Z][a-zA-Z0-9]*)\b[^>]*/?>", filter_md_tag, markdown)

        span.set_attribute("input_length", len(markdown))
        metrics.inc_counter("web.sanitize_markdown.completed")

        return markdown


# ---------------------------------------------------------------------------
# 5. sanitize_css
# ---------------------------------------------------------------------------

def sanitize_css(
    css: str,
    allowed_properties: Optional[list[str]] = None,
) -> str:
    """Sanitize CSS by removing dangerous properties and values.

    Args:
        css: The CSS string to sanitize.
        allowed_properties: List of allowed CSS property names. Defaults to DEFAULT_ALLOWED_CSS_PROPERTIES.

    Returns:
        Sanitized CSS string.

    Example:
        >>> sanitize_css('color: red; background: url(javascript:alert(1))')
        'color: red; '
    """
    metrics = get_metrics()
    metrics.inc_counter("web.sanitize_css.calls")

    with create_span("sanitize_css") as span:
        if not css:
            return ""

        props = allowed_properties or DEFAULT_ALLOWED_CSS_PROPERTIES

        css = re.sub(
            r"expression\s*\([^)]*\)",
            "/* removed */",
            css,
            flags=re.IGNORECASE,
        )
        css = re.sub(
            r"url\s*\(\s*[\"']?\s*javascript:[^)]*\)",
            "/* removed */",
            css,
            flags=re.IGNORECASE,
        )
        css = re.sub(
            r"url\s*\(\s*[\"']?\s*data:[^)]*\)",
            "/* removed */",
            css,
            flags=re.IGNORECASE,
        )
        css = re.sub(
            r"url\s*\(\s*[\"']?\s*vbscript:[^)]*\)",
            "/* removed */",
            css,
            flags=re.IGNORECASE,
        )

        css = re.sub(
            r"@import\s+[^;]+;",
            "",
            css,
            flags=re.IGNORECASE,
        )

        def filter_css_prop(match: re.Match[str]) -> str:
            prop_name = match.group(1).strip().lower()
            if prop_name in props:
                return match.group(0)
            return ""

        css = re.sub(r"([a-zA-Z-]+)\s*:\s*[^;]+;", filter_css_prop, css)

        css = re.sub(
            r"(?:behavior|-moz-binding)\s*:\s*[^;]+;",
            "",
            css,
            flags=re.IGNORECASE,
        )

        span.set_attribute("input_length", len(css))
        metrics.inc_counter("web.sanitize_css.completed")

        return css


# ---------------------------------------------------------------------------
# 6. sanitize_js
# ---------------------------------------------------------------------------

def sanitize_js(
    js_code: str,
    dangerous_patterns: Optional[list[str]] = None,
) -> str:
    """Sanitize JavaScript code by removing dangerous patterns.

    Args:
        js_code: The JavaScript code to sanitize.
        dangerous_patterns: List of regex patterns to remove. Defaults to DEFAULT_DANGEROUS_JS_PATTERNS.

    Returns:
        Sanitized JavaScript code string.

    Example:
        >>> sanitize_js('eval(userInput)')
        '/* removed */'
    """
    metrics = get_metrics()
    metrics.inc_counter("web.sanitize_js.calls")

    with create_span("sanitize_js") as span:
        if not js_code:
            return ""

        patterns = dangerous_patterns or DEFAULT_DANGEROUS_JS_PATTERNS

        for pattern in patterns:
            try:
                js_code = re.sub(
                    pattern,
                    "/* removed */",
                    js_code,
                    flags=re.IGNORECASE,
                )
            except re.error:
                logger.warning("invalid_js_pattern", pattern=pattern)

        span.set_attribute("input_length", len(js_code))
        metrics.inc_counter("web.sanitize_js.completed")

        return js_code


# ---------------------------------------------------------------------------
# 7. detect_sqli
# ---------------------------------------------------------------------------

def detect_sqli(
    input_str: str,
    patterns: Optional[list[str]] = None,
    context: Optional[str] = None,
) -> dict[str, Any]:
    """Detect SQL Injection attack patterns in input string.

    Args:
        input_str: The input string to analyze for SQL injection patterns.
        patterns: Optional list of regex patterns. Uses DEFAULT_SQLI_PATTERNS if None.
        context: Optional context string (e.g., 'query', 'parameter', 'header').

    Returns:
        dict with keys: detected (bool), severity (str), matches (list), score (float), context (str).

    Example:
        >>> detect_sqli("' OR 1=1 --")
        {'detected': True, 'severity': 'high', 'matches': [...], 'score': 0.9}
    """
    metrics = get_metrics()
    metrics.inc_counter("web.detect_sqli.calls")

    with create_span("detect_sqli") as span:
        if not input_str:
            span.set_attribute("empty_input", True)
            return {"detected": False, "severity": "none", "matches": [], "score": 0.0, "context": context}

        active_patterns = patterns or DEFAULT_SQLI_PATTERNS

        matches: list[dict[str, Any]] = []
        max_score = 0.0

        for pattern in active_patterns:
            try:
                found = re.findall(pattern, input_str, re.IGNORECASE | re.DOTALL)
                if found:
                    severity = _classify_sqli_severity(pattern)
                    matches.append({
                        "pattern": pattern,
                        "match": found[0] if isinstance(found[0], str) else str(found[0]),
                        "severity": severity,
                    })
                    score = _sqli_pattern_score(pattern)
                    max_score = max(max_score, score)
            except re.error:
                logger.warning("invalid_sqli_pattern", pattern=pattern)

        detected = len(matches) > 0
        overall_severity = _max_severity(matches) if matches else "none"

        logger.info(
            "sqli_detection_complete",
            detected=detected,
            severity=overall_severity,
            match_count=len(matches),
            context=context,
        )

        span.set_attribute("detected", detected)
        span.set_attribute("severity", overall_severity)
        metrics.inc_counter("web.detect_sqli.detected" if detected else "web.detect_sqli.clean")

        return {
            "detected": detected,
            "severity": overall_severity,
            "matches": matches,
            "score": round(max_score, 2),
            "context": context,
        }


# ---------------------------------------------------------------------------
# 8. detect_nosqli
# ---------------------------------------------------------------------------

def detect_nosqli(
    input_str: str,
    patterns: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect NoSQL Injection attack patterns in input string.

    Args:
        input_str: The input string to analyze for NoSQL injection patterns.
        patterns: Optional list of regex patterns for NoSQL injection detection.

    Returns:
        dict with keys: detected (bool), severity (str), matches (list), score (float).

    Example:
        >>> detect_nosqli('{"$gt": ""}')
        {'detected': True, 'severity': 'high', 'matches': [...], 'score': 0.85}
    """
    metrics = get_metrics()
    metrics.inc_counter("web.detect_nosqli.calls")

    with create_span("detect_nosqli") as span:
        if not input_str:
            return {"detected": False, "severity": "none", "matches": [], "score": 0.0}

        nosqli_patterns = patterns or [
            r"\$gt", r"\$gte", r"\$lt", r"\$lte", r"\$ne", r"\$nin",
            r"\$eq", r"\$regex", r"\$exists", r"\$where", r"\$in",
            r"\$or", r"\$and", r"\$not", r"\$nor", r"\$all",
            r"\$size", r"\$slice", r"\$elemMatch", r"\$expr",
            r"\$jsonSchema", r"\$text", r"\$search", r"\$natural",
            r"\$regexMatch", r"\$regexFind", r"\$function",
            r"\$accumulator", r"\$addFields", r"\$project",
            r"db\.\w+\s*\(", r"MongoClient", r"mongoose",
            r"\{\s*\"\$[a-zA-Z]+\"\s*:",
            r"\{\s*'\$[a-zA-Z]+'\s*:",
        ]

        matches: list[dict[str, Any]] = []
        max_score = 0.0

        for pattern in nosqli_patterns:
            try:
                found = re.findall(pattern, input_str, re.IGNORECASE)
                if found:
                    severity = _classify_nosqli_severity(pattern)
                    matches.append({
                        "pattern": pattern,
                        "match": found[0] if isinstance(found[0], str) else str(found[0]),
                        "severity": severity,
                    })
                    score = _nosqli_pattern_score(pattern)
                    max_score = max(max_score, score)
            except re.error:
                logger.warning("invalid_nosqli_pattern", pattern=pattern)

        detected = len(matches) > 0
        overall_severity = _max_severity(matches) if matches else "none"

        logger.info(
            "nosqli_detection_complete",
            detected=detected,
            severity=overall_severity,
            match_count=len(matches),
        )

        span.set_attribute("detected", detected)
        span.set_attribute("severity", overall_severity)
        metrics.inc_counter("web.detect_nosqli.detected" if detected else "web.detect_nosqli.clean")

        return {
            "detected": detected,
            "severity": overall_severity,
            "matches": matches,
            "score": round(max_score, 2),
        }


# ---------------------------------------------------------------------------
# 9. detect_ssrf
# ---------------------------------------------------------------------------

def detect_ssrf(
    url: str,
    allowed_domains: Optional[list[str]] = None,
    blocked_ips: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect Server-Side Request Forgery (SSRF) attack patterns in URL.

    Args:
        url: The URL to analyze for SSRF patterns.
        allowed_domains: List of allowed domain names.
        blocked_ips: List of blocked IP addresses/ranges. Defaults to private/internal IPs.

    Returns:
        dict with keys: detected (bool), severity (str), matches (list), score (float), is_allowed (bool).

    Example:
        >>> detect_ssrf('http://169.254.169.254/latest/meta-data/')
        {'detected': True, 'severity': 'critical', 'matches': [...], 'score': 0.95}
    """
    metrics = get_metrics()
    metrics.inc_counter("web.detect_ssrf.calls")

    with create_span("detect_ssrf") as span:
        if not url:
            return {"detected": False, "severity": "none", "matches": [], "score": 0.0, "is_allowed": False}

        active_patterns = DEFAULT_SSRF_PATTERNS
        blocked = blocked_ips or [
            "127.0.0.1", "0.0.0.0", "10.0.0.0/8", "172.16.0.0/12",
            "192.168.0.0/16", "169.254.0.0/16", "::1", "fe80::/10",
        ]

        matches: list[dict[str, Any]] = []
        max_score = 0.0

        for pattern in active_patterns:
            try:
                found = re.findall(pattern, url, re.IGNORECASE)
                if found:
                    severity = _classify_ssrf_severity(pattern)
                    matches.append({
                        "pattern": pattern,
                        "match": found[0] if isinstance(found[0], str) else str(found[0]),
                        "severity": severity,
                    })
                    score = _ssrf_pattern_score(pattern)
                    max_score = max(max_score, score)
            except re.error:
                logger.warning("invalid_ssrf_pattern", pattern=pattern)

        is_allowed = False
        if allowed_domains:
            try:
                parsed = urllib.parse.urlparse(url)
                hostname = parsed.hostname or ""
                is_allowed = any(
                    hostname == d or hostname.endswith("." + d)
                    for d in allowed_domains
                )
            except Exception:
                is_allowed = False

        detected = len(matches) > 0
        overall_severity = _max_severity(matches) if matches else "none"

        logger.info(
            "ssrf_detection_complete",
            detected=detected,
            severity=overall_severity,
            match_count=len(matches),
            is_allowed=is_allowed,
        )

        span.set_attribute("detected", detected)
        span.set_attribute("severity", overall_severity)
        metrics.inc_counter("web.detect_ssrf.detected" if detected else "web.detect_ssrf.clean")

        return {
            "detected": detected,
            "severity": overall_severity,
            "matches": matches,
            "score": round(max_score, 2),
            "is_allowed": is_allowed,
        }


# ---------------------------------------------------------------------------
# 10. detect_rce
# ---------------------------------------------------------------------------

def detect_rce(
    input_str: str,
    patterns: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect Remote Code Execution (RCE) attack patterns in input string.

    Args:
        input_str: The input string to analyze for RCE patterns.
        patterns: Optional list of regex patterns. Uses DEFAULT_RCE_PATTERNS if None.

    Returns:
        dict with keys: detected (bool), severity (str), matches (list), score (float).

    Example:
        >>> detect_rce('eval(os.system("id"))')
        {'detected': True, 'severity': 'critical', 'matches': [...], 'score': 0.95}
    """
    metrics = get_metrics()
    metrics.inc_counter("web.detect_rce.calls")

    with create_span("detect_rce") as span:
        if not input_str:
            return {"detected": False, "severity": "none", "matches": [], "score": 0.0}

        active_patterns = patterns or DEFAULT_RCE_PATTERNS

        matches: list[dict[str, Any]] = []
        max_score = 0.0

        for pattern in active_patterns:
            try:
                found = re.findall(pattern, input_str, re.IGNORECASE | re.DOTALL)
                if found:
                    severity = _classify_rce_severity(pattern)
                    matches.append({
                        "pattern": pattern,
                        "match": found[0] if isinstance(found[0], str) else str(found[0]),
                        "severity": severity,
                    })
                    score = _rce_pattern_score(pattern)
                    max_score = max(max_score, score)
            except re.error:
                logger.warning("invalid_rce_pattern", pattern=pattern)

        detected = len(matches) > 0
        overall_severity = _max_severity(matches) if matches else "none"

        logger.info(
            "rce_detection_complete",
            detected=detected,
            severity=overall_severity,
            match_count=len(matches),
        )

        span.set_attribute("detected", detected)
        span.set_attribute("severity", overall_severity)
        metrics.inc_counter("web.detect_rce.detected" if detected else "web.detect_rce.clean")

        return {
            "detected": detected,
            "severity": overall_severity,
            "matches": matches,
            "score": round(max_score, 2),
        }


# ---------------------------------------------------------------------------
# 11. detect_lfi
# ---------------------------------------------------------------------------

def detect_lfi(
    input_str: str,
    patterns: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect Local File Inclusion (LFI) attack patterns in input string.

    Args:
        input_str: The input string to analyze for LFI patterns.
        patterns: Optional list of regex patterns. Uses DEFAULT_LFI_PATTERNS if None.

    Returns:
        dict with keys: detected (bool), severity (str), matches (list), score (float).

    Example:
        >>> detect_lfi('../../../etc/passwd')
        {'detected': True, 'severity': 'high', 'matches': [...], 'score': 0.85}
    """
    metrics = get_metrics()
    metrics.inc_counter("web.detect_lfi.calls")

    with create_span("detect_lfi") as span:
        if not input_str:
            return {"detected": False, "severity": "none", "matches": [], "score": 0.0}

        active_patterns = patterns or DEFAULT_LFI_PATTERNS

        matches: list[dict[str, Any]] = []
        max_score = 0.0

        for pattern in active_patterns:
            try:
                found = re.findall(pattern, input_str, re.IGNORECASE)
                if found:
                    severity = _classify_lfi_severity(pattern)
                    matches.append({
                        "pattern": pattern,
                        "match": found[0] if isinstance(found[0], str) else str(found[0]),
                        "severity": severity,
                    })
                    score = _lfi_pattern_score(pattern)
                    max_score = max(max_score, score)
            except re.error:
                logger.warning("invalid_lfi_pattern", pattern=pattern)

        detected = len(matches) > 0
        overall_severity = _max_severity(matches) if matches else "none"

        logger.info(
            "lfi_detection_complete",
            detected=detected,
            severity=overall_severity,
            match_count=len(matches),
        )

        span.set_attribute("detected", detected)
        span.set_attribute("severity", overall_severity)
        metrics.inc_counter("web.detect_lfi.detected" if detected else "web.detect_lfi.clean")

        return {
            "detected": detected,
            "severity": overall_severity,
            "matches": matches,
            "score": round(max_score, 2),
        }


# ---------------------------------------------------------------------------
# 12. detect_rfi
# ---------------------------------------------------------------------------

def detect_rfi(
    input_str: str,
    patterns: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect Remote File Inclusion (RFI) attack patterns in input string.

    Args:
        input_str: The input string to analyze for RFI patterns.
        patterns: Optional list of regex patterns. Uses DEFAULT_RFI_PATTERNS if None.

    Returns:
        dict with keys: detected (bool), severity (str), matches (list), score (float).

    Example:
        >>> detect_rfi('http://evil.com/shell.php')
        {'detected': True, 'severity': 'critical', 'matches': [...], 'score': 0.95}
    """
    metrics = get_metrics()
    metrics.inc_counter("web.detect_rfi.calls")

    with create_span("detect_rfi") as span:
        if not input_str:
            return {"detected": False, "severity": "none", "matches": [], "score": 0.0}

        active_patterns = patterns or DEFAULT_RFI_PATTERNS

        matches: list[dict[str, Any]] = []
        max_score = 0.0

        for pattern in active_patterns:
            try:
                found = re.findall(pattern, input_str, re.IGNORECASE)
                if found:
                    severity = _classify_rfi_severity(pattern)
                    matches.append({
                        "pattern": pattern,
                        "match": found[0] if isinstance(found[0], str) else str(found[0]),
                        "severity": severity,
                    })
                    score = _rfi_pattern_score(pattern)
                    max_score = max(max_score, score)
            except re.error:
                logger.warning("invalid_rfi_pattern", pattern=pattern)

        detected = len(matches) > 0
        overall_severity = _max_severity(matches) if matches else "none"

        logger.info(
            "rfi_detection_complete",
            detected=detected,
            severity=overall_severity,
            match_count=len(matches),
        )

        span.set_attribute("detected", detected)
        span.set_attribute("severity", overall_severity)
        metrics.inc_counter("web.detect_rfi.detected" if detected else "web.detect_rfi.clean")

        return {
            "detected": detected,
            "severity": overall_severity,
            "matches": matches,
            "score": round(max_score, 2),
        }


# ---------------------------------------------------------------------------
# 13. detect_template_injection
# ---------------------------------------------------------------------------

def detect_template_injection(
    input_str: str,
    engine_type: str = "default",
) -> dict[str, Any]:
    """Detect Server-Side Template Injection (SSTI) attack patterns.

    Args:
        input_str: The input string to analyze for template injection patterns.
        engine_type: Template engine type ('jinja2', 'twig', 'ejs', 'handlebars', 'mako', 'pug', 'default').

    Returns:
        dict with keys: detected (bool), severity (str), matches (list), score (float), engine (str).

    Example:
        >>> detect_template_injection('{{config.__class__}}', 'jinja2')
        {'detected': True, 'severity': 'critical', 'matches': [...], 'score': 0.95}
    """
    metrics = get_metrics()
    metrics.inc_counter("web.detect_template_injection.calls")

    with create_span("detect_template_injection") as span:
        if not input_str:
            return {"detected": False, "severity": "none", "matches": [], "score": 0.0, "engine": engine_type}

        engine_patterns = DEFAULT_TEMPLATE_INJECTION_PATTERNS.get(
            engine_type.lower(),
            DEFAULT_TEMPLATE_INJECTION_PATTERNS["default"],
        )

        matches: list[dict[str, Any]] = []
        max_score = 0.0

        for pattern in engine_patterns:
            try:
                found = re.findall(pattern, input_str, re.IGNORECASE | re.DOTALL)
                if found:
                    severity = _classify_template_severity(pattern, engine_type)
                    matches.append({
                        "pattern": pattern,
                        "match": found[0] if isinstance(found[0], str) else str(found[0]),
                        "severity": severity,
                    })
                    score = _template_pattern_score(pattern, engine_type)
                    max_score = max(max_score, score)
            except re.error:
                logger.warning("invalid_template_pattern", pattern=pattern, engine=engine_type)

        detected = len(matches) > 0
        overall_severity = _max_severity(matches) if matches else "none"

        logger.info(
            "template_injection_detection_complete",
            detected=detected,
            severity=overall_severity,
            match_count=len(matches),
            engine=engine_type,
        )

        span.set_attribute("detected", detected)
        span.set_attribute("severity", overall_severity)
        span.set_attribute("engine", engine_type)
        metrics.inc_counter("web.detect_template_injection.detected" if detected else "web.detect_template_injection.clean")

        return {
            "detected": detected,
            "severity": overall_severity,
            "matches": matches,
            "score": round(max_score, 2),
            "engine": engine_type,
        }


# ---------------------------------------------------------------------------
# 14. detect_command_injection
# ---------------------------------------------------------------------------

def detect_command_injection(
    input_str: str,
    patterns: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect OS Command Injection attack patterns in input string.

    Args:
        input_str: The input string to analyze for command injection patterns.
        patterns: Optional list of regex patterns. Uses DEFAULT_CMD_INJECTION_PATTERNS if None.

    Returns:
        dict with keys: detected (bool), severity (str), matches (list), score (float).

    Example:
        >>> detect_command_injection('; cat /etc/passwd')
        {'detected': True, 'severity': 'critical', 'matches': [...], 'score': 0.95}
    """
    metrics = get_metrics()
    metrics.inc_counter("web.detect_command_injection.calls")

    with create_span("detect_command_injection") as span:
        if not input_str:
            return {"detected": False, "severity": "none", "matches": [], "score": 0.0}

        active_patterns = patterns or DEFAULT_CMD_INJECTION_PATTERNS

        matches: list[dict[str, Any]] = []
        max_score = 0.0

        for pattern in active_patterns:
            try:
                found = re.findall(pattern, input_str, re.IGNORECASE)
                if found:
                    severity = _classify_cmd_injection_severity(pattern)
                    matches.append({
                        "pattern": pattern,
                        "match": found[0] if isinstance(found[0], str) else str(found[0]),
                        "severity": severity,
                    })
                    score = _cmd_injection_pattern_score(pattern)
                    max_score = max(max_score, score)
            except re.error:
                logger.warning("invalid_cmd_injection_pattern", pattern=pattern)

        detected = len(matches) > 0
        overall_severity = _max_severity(matches) if matches else "none"

        logger.info(
            "command_injection_detection_complete",
            detected=detected,
            severity=overall_severity,
            match_count=len(matches),
        )

        span.set_attribute("detected", detected)
        span.set_attribute("severity", overall_severity)
        metrics.inc_counter("web.detect_command_injection.detected" if detected else "web.detect_command_injection.clean")

        return {
            "detected": detected,
            "severity": overall_severity,
            "matches": matches,
            "score": round(max_score, 2),
        }


# ---------------------------------------------------------------------------
# 15. detect_deserialization_attack
# ---------------------------------------------------------------------------

def detect_deserialization_attack(
    data: Any,
    allowed_classes: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect insecure deserialization attack patterns.

    Args:
        data: The data to analyze (string, bytes, or dict).
        allowed_classes: List of allowed class/type names for deserialization.

    Returns:
        dict with keys: detected (bool), severity (str), matches (list), score (float), data_type (str).

    Example:
        >>> detect_deserialization_attack('r\\n__main__\\nExploit\\n')
        {'detected': True, 'severity': 'critical', 'matches': [...], 'score': 0.95}
    """
    metrics = get_metrics()
    metrics.inc_counter("web.detect_deserialization_attack.calls")

    with create_span("detect_deserialization_attack") as span:
        data_type = type(data).__name__
        data_str = str(data) if not isinstance(data, str) else data

        deserialization_patterns: list[str] = [
            r"cpython\.",
            r"__reduce__",
            r"__reduce_ex__",
            r"__getstate__",
            r"__setstate__",
            r"b'?cos\\n(?:system|popen|exec)",
            r"b'?cposix\\n(?:system|popen)",
            r"b'?csubprocess\\n",
            r"b'?c__main__\\n",
            r"\x80\x0[345]",
            r"\xac\xed\x00\x05",
            r"java\.util\.",
            r"java\.lang\.",
            r"javax\.naming\.",
            r"org\.apache\.commons\.collections",
            r"org\.springframework\.",
            r"!!python/object",
            r"!!python/object/new",
            r"!!python/object/apply",
            r"!!ruby/object",
            r"!!ruby/class",
            r"!!ruby/module",
            r"!!perl",
            r"!!php/object",
            r"!!java/",
            r"O:\d+:\"[^\"]+\":\d+:\{",
            r"a:\d+:\{",
            r"Assembly-CSharp",
            r"System\.Runtime\.Serialization",
            r"System\.Web\.UI\.ObjectStateFormatter",
            r"LosFormatter",
            r"NetDataContractSerializer",
            r"BinaryFormatter",
            r"\$type\s*:",
            r"\$values\s*:",
            r"\$ref\s*:",
            r"\bconstructor\b.*prototype",
            r"__proto__",
        ]

        matches: list[dict[str, Any]] = []
        max_score = 0.0

        for pattern in deserialization_patterns:
            try:
                found = re.findall(pattern, data_str, re.IGNORECASE | re.DOTALL)
                if found:
                    severity = _classify_deserialization_severity(pattern)
                    matches.append({
                        "pattern": pattern,
                        "match": found[0] if isinstance(found[0], str) else str(found[0]),
                        "severity": severity,
                    })
                    score = _deserialization_pattern_score(pattern)
                    max_score = max(max_score, score)
            except re.error:
                logger.warning("invalid_deserialization_pattern", pattern=pattern)

        if allowed_classes and isinstance(data, dict):
            for key, value in data.items():
                if key in ("$type", "__class__", "class") and value not in allowed_classes:
                    matches.append({
                        "pattern": "disallowed_class",
                        "match": f"{key}: {value}",
                        "severity": "high",
                    })
                    max_score = max(max_score, 0.85)

        detected = len(matches) > 0
        overall_severity = _max_severity(matches) if matches else "none"

        logger.info(
            "deserialization_detection_complete",
            detected=detected,
            severity=overall_severity,
            match_count=len(matches),
            data_type=data_type,
        )

        span.set_attribute("detected", detected)
        span.set_attribute("severity", overall_severity)
        span.set_attribute("data_type", data_type)
        metrics.inc_counter("web.detect_deserialization_attack.detected" if detected else "web.detect_deserialization_attack.clean")

        return {
            "detected": detected,
            "severity": overall_severity,
            "matches": matches,
            "score": round(max_score, 2),
            "data_type": data_type,
        }


# ---------------------------------------------------------------------------
# 16. detect_path_traversal
# ---------------------------------------------------------------------------

def detect_path_traversal(
    input_str: str,
    base_path: Optional[str] = None,
) -> dict[str, Any]:
    """Detect path traversal attack patterns in input string.

    Args:
        input_str: The input string to analyze for path traversal patterns.
        base_path: Optional base path to validate against.

    Returns:
        dict with keys: detected (bool), severity (str), matches (list), score (float), is_safe (bool).

    Example:
        >>> detect_path_traversal('../../../etc/passwd', '/var/www')
        {'detected': True, 'severity': 'high', 'matches': [...], 'score': 0.85}
    """
    metrics = get_metrics()
    metrics.inc_counter("web.detect_path_traversal.calls")

    with create_span("detect_path_traversal") as span:
        if not input_str:
            return {"detected": False, "severity": "none", "matches": [], "score": 0.0, "is_safe": True}

        traversal_patterns: list[str] = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e/",
            r"\.\.%2f",
            r"%252e%252e%252f",
            r"%c0%ae",
            r"%c1%9c",
            r"\.\.\.\./",
            r"\.\.//",
            r"//",
            r"\\",
            r"/etc/passwd",
            r"/etc/shadow",
            r"/proc/self",
            r"boot\.ini",
            r"win\.ini",
        ]

        matches: list[dict[str, Any]] = []
        max_score = 0.0

        for pattern in traversal_patterns:
            try:
                found = re.findall(pattern, input_str, re.IGNORECASE)
                if found:
                    severity = _classify_path_traversal_severity(pattern)
                    matches.append({
                        "pattern": pattern,
                        "match": found[0] if isinstance(found[0], str) else str(found[0]),
                        "severity": severity,
                    })
                    score = _path_traversal_pattern_score(pattern)
                    max_score = max(max_score, score)
            except re.error:
                logger.warning("invalid_path_traversal_pattern", pattern=pattern)

        is_safe = True
        if base_path:
            try:
                resolved = _safe_resolve_path(base_path, input_str)
                is_safe = resolved.startswith(base_path)
            except Exception:
                is_safe = False
                matches.append({
                    "pattern": "path_resolution_failed",
                    "match": input_str,
                    "severity": "high",
                })
                max_score = max(max_score, 0.85)

        detected = len(matches) > 0
        overall_severity = _max_severity(matches) if matches else "none"

        logger.info(
            "path_traversal_detection_complete",
            detected=detected,
            severity=overall_severity,
            match_count=len(matches),
            is_safe=is_safe,
        )

        span.set_attribute("detected", detected)
        span.set_attribute("severity", overall_severity)
        metrics.inc_counter("web.detect_path_traversal.detected" if detected else "web.detect_path_traversal.clean")

        return {
            "detected": detected,
            "severity": overall_severity,
            "matches": matches,
            "score": round(max_score, 2),
            "is_safe": is_safe,
        }


# ---------------------------------------------------------------------------
# 17. detect_open_redirect
# ---------------------------------------------------------------------------

def detect_open_redirect(
    url: str,
    allowed_hosts: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Detect open redirect attack patterns in URL.

    Args:
        url: The URL to analyze for open redirect patterns.
        allowed_hosts: List of allowed hostnames for redirects.

    Returns:
        dict with keys: detected (bool), severity (str), matches (list), score (float), is_allowed (bool).

    Example:
        >>> detect_open_redirect('https://evil.com/?next=https://good.com', ['good.com'])
        {'detected': True, 'severity': 'high', 'matches': [...], 'score': 0.85}
    """
    metrics = get_metrics()
    metrics.inc_counter("web.detect_open_redirect.calls")

    with create_span("detect_open_redirect") as span:
        if not url:
            return {"detected": False, "severity": "none", "matches": [], "score": 0.0, "is_allowed": False}

        redirect_patterns: list[str] = [
            r"javascript\s*:",
            r"data\s*:",
            r"//[^/]",
            r"\\/",
            r"%2f%2f",
            r"%5c",
            r"@.*\.",
            r"\.\./",
        ]

        matches: list[dict[str, Any]] = []
        max_score = 0.0

        for pattern in redirect_patterns:
            try:
                found = re.findall(pattern, url, re.IGNORECASE)
                if found:
                    severity = _classify_redirect_severity(pattern)
                    matches.append({
                        "pattern": pattern,
                        "match": found[0] if isinstance(found[0], str) else str(found[0]),
                        "severity": severity,
                    })
                    score = _redirect_pattern_score(pattern)
                    max_score = max(max_score, score)
            except re.error:
                logger.warning("invalid_redirect_pattern", pattern=pattern)

        is_allowed = False
        if allowed_hosts:
            try:
                parsed = urllib.parse.urlparse(url)
                hostname = parsed.hostname or ""
                hostname = hostname.split(":")[0]
                is_allowed = any(
                    hostname == h or hostname.endswith("." + h)
                    for h in allowed_hosts
                )
            except Exception:
                is_allowed = False

        decoded = urllib.parse.unquote(url)
        if decoded != url:
            for pattern in redirect_patterns:
                try:
                    found = re.findall(pattern, decoded, re.IGNORECASE)
                    if found:
                        matches.append({
                            "pattern": f"encoded:{pattern}",
                            "match": found[0] if isinstance(found[0], str) else str(found[0]),
                            "severity": "high",
                        })
                        max_score = max(max_score, 0.85)
                except re.error:
                    pass

        detected = len(matches) > 0
        overall_severity = _max_severity(matches) if matches else "none"

        logger.info(
            "open_redirect_detection_complete",
            detected=detected,
            severity=overall_severity,
            match_count=len(matches),
            is_allowed=is_allowed,
        )

        span.set_attribute("detected", detected)
        span.set_attribute("severity", overall_severity)
        metrics.inc_counter("web.detect_open_redirect.detected" if detected else "web.detect_open_redirect.clean")

        return {
            "detected": detected,
            "severity": overall_severity,
            "matches": matches,
            "score": round(max_score, 2),
            "is_allowed": is_allowed,
        }


# ---------------------------------------------------------------------------
# 18. validate_cors
# ---------------------------------------------------------------------------

def validate_cors(
    origin: str,
    allowed_origins: Optional[list[str]] = None,
    allowed_methods: Optional[list[str]] = None,
    allowed_headers: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Validate Cross-Origin Resource Sharing (CORS) request.

    Args:
        origin: The Origin header value from the request.
        allowed_origins: List of allowed origin domains.
        allowed_methods: List of allowed HTTP methods. Defaults to DEFAULT_ALLOWED_METHODS.
        allowed_headers: List of allowed HTTP headers. Defaults to DEFAULT_ALLOWED_HEADERS.

    Returns:
        dict with keys: allowed (bool), origin (str), methods (list), headers (list), expose_headers (list).

    Example:
        >>> validate_cors('https://example.com', ['https://example.com'])
        {'allowed': True, 'origin': 'https://example.com', ...}
    """
    metrics = get_metrics()
    metrics.inc_counter("web.validate_cors.calls")

    with create_span("validate_cors") as span:
        origins = allowed_origins or []
        methods = allowed_methods or DEFAULT_ALLOWED_METHODS
        headers = allowed_headers or DEFAULT_ALLOWED_HEADERS

        is_allowed = False
        if origin:
            if "*" in origins:
                is_allowed = True
            else:
                is_allowed = any(
                    origin == o or origin.endswith("." + o.lstrip("*."))
                    for o in origins
                )

        if origin == "null":
            is_allowed = False

        response_headers: dict[str, Any] = {
            "allowed": is_allowed,
            "origin": origin if is_allowed else "",
            "methods": methods if is_allowed else [],
            "headers": headers if is_allowed else [],
            "expose_headers": ["X-Request-Id", "X-Rate-Limit-Remaining"] if is_allowed else [],
            "max_age": 86400 if is_allowed else 0,
            "credentials": is_allowed and origin != "*",
        }

        logger.info(
            "cors_validation_complete",
            origin=origin,
            allowed=is_allowed,
        )

        span.set_attribute("allowed", is_allowed)
        span.set_attribute("origin", origin)
        metrics.inc_counter("web.validate_cors.allowed" if is_allowed else "web.validate_cors.denied")

        return response_headers


# ---------------------------------------------------------------------------
# 19. secure_headers
# ---------------------------------------------------------------------------

def secure_headers(
    request: Optional[dict[str, Any]] = None,
    config: Optional[dict[str, Any]] = None,
) -> dict[str, str]:
    """Generate secure HTTP response headers.

    Args:
        request: Optional request dict with method, path, etc.
        config: Optional configuration dict for header values.

    Returns:
        dict of secure HTTP headers to add to response.

    Example:
        >>> secure_headers()
        {'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', ...}
    """
    metrics = get_metrics()
    metrics.inc_counter("web.secure_headers.calls")

    with create_span("secure_headers") as span:
        cfg = config or {}

        headers: dict[str, str] = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": cfg.get("x_frame_options", "DENY"),
            "X-XSS-Protection": "0",
            "Referrer-Policy": cfg.get("referrer_policy", "strict-origin-when-cross-origin"),
            "Permissions-Policy": cfg.get(
                "permissions_policy",
                "camera=(), microphone=(), geolocation=(), payment=()",
            ),
            "Strict-Transport-Security": cfg.get(
                "hsts",
                "max-age=31536000; includeSubDomains; preload",
            ),
            "Cache-Control": cfg.get("cache_control", "no-store, no-cache, must-revalidate"),
            "Pragma": "no-cache",
            "X-Powered-By": "",
            "Server": "",
            "Cross-Origin-Opener-Policy": cfg.get("coop", "same-origin"),
            "Cross-Origin-Resource-Policy": cfg.get("corp", "same-origin"),
            "Cross-Origin-Embedder-Policy": cfg.get("coep", "require-corp"),
        }

        if "csp" in cfg:
            headers["Content-Security-Policy"] = cfg["csp"]

        headers = {k: v for k, v in headers.items() if v}

        logger.info(
            "secure_headers_generated",
            header_count=len(headers),
        )

        span.set_attribute("header_count", len(headers))
        metrics.inc_counter("web.secure_headers.completed")

        return headers


# ---------------------------------------------------------------------------
# 20. generate_csp
# ---------------------------------------------------------------------------

def generate_csp(
    config: Optional[dict[str, Any]] = None,
) -> str:
    """Generate a Content-Security-Policy header value.

    Args:
        config: Optional dict with CSP directive values.
            Keys: default-src, script-src, style-src, img-src, font-src,
            connect-src, frame-src, media-src, object-src, base-uri,
            form-action, frame-ancestors, report-uri, report-to.

    Returns:
        CSP header string.

    Example:
        >>> generate_csp({'default-src': "'self'", 'script-src': "'self' 'unsafe-inline'"})
        "default-src 'self'; script-src 'self' 'unsafe-inline'"
    """
    metrics = get_metrics()
    metrics.inc_counter("web.generate_csp.calls")

    with create_span("generate_csp") as span:
        cfg = config or {}

        defaults: dict[str, str] = {
            "default-src": "'self'",
            "script-src": "'self'",
            "style-src": "'self'",
            "img-src": "'self' data:",
            "font-src": "'self'",
            "connect-src": "'self'",
            "media-src": "'self'",
            "object-src": "'none'",
            "base-uri": "'self'",
            "form-action": "'self'",
            "frame-ancestors": "'none'",
            "upgrade-insecure-requests": "",
        }

        merged = {**defaults, **cfg}

        directives: list[str] = []
        for directive, value in merged.items():
            if value is not None:
                if value == "":
                    directives.append(directive)
                else:
                    directives.append(f"{directive} {value}")

        csp = "; ".join(directives)

        logger.info(
            "csp_generated",
            directive_count=len(directives),
        )

        span.set_attribute("directive_count", len(directives))
        metrics.inc_counter("web.generate_csp.completed")

        return csp


# ---------------------------------------------------------------------------
# 21. validate_csp
# ---------------------------------------------------------------------------

def validate_csp(
    csp_header: str,
    policy: Optional[dict[str, Any]] = None,
) -> bool:
    """Validate a Content-Security-Policy header against a security policy.

    Args:
        csp_header: The CSP header string to validate.
        policy: Optional dict with required CSP directives and values.

    Returns:
        True if CSP meets policy requirements, False otherwise.

    Example:
        >>> validate_csp("default-src 'self'", {'default-src': "'self'"})
        True
    """
    metrics = get_metrics()
    metrics.inc_counter("web.validate_csp.calls")

    with create_span("validate_csp") as span:
        if not csp_header:
            span.set_attribute("valid", False)
            return False

        parsed: dict[str, str] = {}
        for directive in csp_header.split(";"):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split(None, 1)
            if len(parts) == 2:
                parsed[parts[0]] = parts[1]
            elif len(parts) == 1:
                parsed[parts[0]] = ""

        req_policy = policy or {
            "default-src": None,
            "script-src": None,
            "object-src": "'none'",
            "base-uri": "'self'",
            "form-action": "'self'",
            "frame-ancestors": "'none'",
        }

        valid = True
        issues: list[str] = []

        for directive, required_value in req_policy.items():
            if directive not in parsed:
                if required_value is not None or directive == "default-src":
                    valid = False
                    issues.append(f"missing directive: {directive}")
            elif required_value is not None:
                if required_value not in parsed[directive]:
                    valid = False
                    issues.append(f"directive {directive} missing required value: {required_value}")

        dangerous_values = ["'unsafe-inline'", "'unsafe-eval'", "*"]
        for directive, value in parsed.items():
            for dangerous in dangerous_values:
                if dangerous in value:
                    if directive in ("script-src", "default-src") and dangerous == "'unsafe-eval'":
                        valid = False
                        issues.append(f"dangerous value in {directive}: {dangerous}")
                    elif directive in ("script-src", "default-src") and dangerous == "'unsafe-inline'":
                        issues.append(f"warning: unsafe-inline in {directive}")

        logger.info(
            "csp_validation_complete",
            valid=valid,
            issues=issues,
        )

        span.set_attribute("valid", valid)
        metrics.inc_counter("web.validate_csp.valid" if valid else "web.validate_csp.invalid")

        return valid


# ---------------------------------------------------------------------------
# 22. csrf_protect
# ---------------------------------------------------------------------------

def csrf_protect(
    request: Optional[dict[str, Any]] = None,
    token: Optional[str] = None,
    session_token: Optional[str] = None,
) -> bool:
    """Protect against Cross-Site Request Forgery (CSRF) attacks.

    Args:
        request: Optional request dict with method and headers.
        token: The CSRF token from the request.
        session_token: The CSRF token stored in the session.

    Returns:
        True if request is protected/valid, False if CSRF attack detected.

    Example:
        >>> csrf_protect(token='abc123', session_token='abc123')
        True
    """
    metrics = get_metrics()
    metrics.inc_counter("web.csrf_protect.calls")

    with create_span("csrf_protect") as span:
        safe_methods = {"GET", "HEAD", "OPTIONS", "TRACE"}
        if request and request.get("method", "").upper() in safe_methods:
            span.set_attribute("safe_method", True)
            return True

        if not token or not session_token:
            logger.warning("csrf_missing_token")
            span.set_attribute("valid", False)
            metrics.inc_counter("web.csrf_protect.denied")
            return False

        is_valid = hmac.compare_digest(token, session_token)

        logger.info(
            "csrf_validation_complete",
            valid=is_valid,
        )

        span.set_attribute("valid", is_valid)
        metrics.inc_counter("web.csrf_protect.allowed" if is_valid else "web.csrf_protect.denied")

        return is_valid


# ---------------------------------------------------------------------------
# 23. validate_csrf
# ---------------------------------------------------------------------------

def validate_csrf(
    token: Optional[str] = None,
    session_token: Optional[str] = None,
) -> bool:
    """Validate a CSRF token against the session token.

    Args:
        token: The CSRF token from the request.
        session_token: The CSRF token stored in the session.

    Returns:
        True if tokens match, False otherwise.

    Example:
        >>> validate_csrf(token='abc123', session_token='abc123')
        True
    """
    metrics = get_metrics()
    metrics.inc_counter("web.validate_csrf.calls")

    with create_span("validate_csrf") as span:
        if not token or not session_token:
            span.set_attribute("valid", False)
            metrics.inc_counter("web.validate_csrf.invalid")
            return False

        is_valid = hmac.compare_digest(token, session_token)

        logger.info(
            "csrf_token_validation_complete",
            valid=is_valid,
        )

        span.set_attribute("valid", is_valid)
        metrics.inc_counter("web.validate_csrf.valid" if is_valid else "web.validate_csrf.invalid")

        return is_valid


# ---------------------------------------------------------------------------
# 24. secure_cookie
# ---------------------------------------------------------------------------

def secure_cookie(
    name: str,
    value: str,
    domain: Optional[str] = None,
    path: str = "/",
    secure: bool = True,
    httponly: bool = True,
    samesite: str = "Strict",
    max_age: Optional[int] = None,
) -> str:
    """Generate a secure Set-Cookie header value.

    Args:
        name: Cookie name.
        value: Cookie value.
        domain: Optional cookie domain.
        path: Cookie path. Defaults to '/'.
        secure: Whether cookie requires HTTPS. Defaults to True.
        httponly: Whether cookie is HTTP-only. Defaults to True.
        samesite: SameSite attribute ('Strict', 'Lax', 'None'). Defaults to 'Strict'.
        max_age: Optional max age in seconds.

    Returns:
        Set-Cookie header string.

    Example:
        >>> secure_cookie('session', 'abc123')
        'session=abc123; Path=/; Secure; HttpOnly; SameSite=Strict'
    """
    metrics = get_metrics()
    metrics.inc_counter("web.secure_cookie.calls")

    with create_span("secure_cookie") as span:
        if not name or not re.match(r'^[a-zA-Z0-9_\-]+$', name):
            raise ValidationError(f"Invalid cookie name: {name}")

        encoded_value = urllib.parse.quote(value, safe="")

        parts = [f"{name}={encoded_value}"]

        if path:
            parts.append(f"Path={path}")

        if domain:
            parts.append(f"Domain={domain}")

        if max_age is not None:
            parts.append(f"Max-Age={max_age}")

        if secure:
            parts.append("Secure")

        if httponly:
            parts.append("HttpOnly")

        valid_samesite = {"Strict", "Lax", "None"}
        if samesite not in valid_samesite:
            raise ValidationError(f"Invalid SameSite value: {samesite}")
        parts.append(f"SameSite={samesite}")

        cookie_header = "; ".join(parts)

        logger.info(
            "secure_cookie_generated",
            name=name,
            secure=secure,
            httponly=httponly,
            samesite=samesite,
        )

        span.set_attribute("name", name)
        span.set_attribute("secure", secure)
        metrics.inc_counter("web.secure_cookie.completed")

        return cookie_header


# ---------------------------------------------------------------------------
# 25. detect_clickjacking
# ---------------------------------------------------------------------------

def detect_clickjacking(
    headers: Optional[dict[str, str]] = None,
    frame_options: Optional[str] = None,
) -> bool:
    """Detect potential clickjacking vulnerability in response headers.

    Args:
        headers: Response headers dict to check.
        frame_options: Expected X-Frame-Options value.

    Returns:
        True if clickjacking protection is detected, False if vulnerable.

    Example:
        >>> detect_clickjacking({'X-Frame-Options': 'DENY'})
        True
    """
    metrics = get_metrics()
    metrics.inc_counter("web.detect_clickjacking.calls")

    with create_span("detect_clickjacking") as span:
        if not headers:
            span.set_attribute("protected", False)
            metrics.inc_counter("web.detect_clickjacking.vulnerable")
            return False

        xfo = headers.get("X-Frame-Options", "")
        csp_frame = headers.get("Content-Security-Policy", "")

        has_xfo_protection = xfo.upper() in ("DENY", "SAMEORIGIN")
        has_csp_protection = "frame-ancestors" in csp_frame

        has_csp_frame_protection = False
        if csp_frame:
            for directive in csp_frame.split(";"):
                directive = directive.strip()
                if directive.startswith("frame-ancestors"):
                    has_csp_frame_protection = True
                    break

        protected = has_xfo_protection or has_csp_frame_protection

        if frame_options and xfo.upper() != frame_options.upper():
            protected = False

        logger.info(
            "clickjacking_detection_complete",
            protected=protected,
            has_xfo=has_xfo_protection,
            has_csp=has_csp_protection,
        )

        span.set_attribute("protected", protected)
        metrics.inc_counter("web.detect_clickjacking.protected" if protected else "web.detect_clickjacking.vulnerable")

        return protected


# ---------------------------------------------------------------------------
# 26. validate_origin
# ---------------------------------------------------------------------------

def validate_origin(
    origin: str,
    allowed_origins: Optional[list[str]] = None,
) -> bool:
    """Validate the Origin header against a list of allowed origins.

    Args:
        origin: The Origin header value.
        allowed_origins: List of allowed origin strings.

    Returns:
        True if origin is allowed, False otherwise.

    Example:
        >>> validate_origin('https://example.com', ['https://example.com'])
        True
    """
    metrics = get_metrics()
    metrics.inc_counter("web.validate_origin.calls")

    with create_span("validate_origin") as span:
        if not origin:
            span.set_attribute("valid", False)
            metrics.inc_counter("web.validate_origin.invalid")
            return False

        origins = allowed_origins or []

        if "*" in origins:
            span.set_attribute("valid", True)
            metrics.inc_counter("web.validate_origin.valid")
            return True

        if origin in origins:
            span.set_attribute("valid", True)
            metrics.inc_counter("web.validate_origin.valid")
            return True

        for allowed in origins:
            if allowed.startswith("*."):
                base_domain = allowed[2:]
                if origin.endswith("." + base_domain):
                    span.set_attribute("valid", True)
                    metrics.inc_counter("web.validate_origin.valid")
                    return True

        span.set_attribute("valid", False)
        metrics.inc_counter("web.validate_origin.invalid")
        return False


# ---------------------------------------------------------------------------
# 27. validate_referer
# ---------------------------------------------------------------------------

def validate_referer(
    referer: str,
    expected_domain: str,
) -> bool:
    """Validate the Referer header against an expected domain.

    Args:
        referer: The Referer header value.
        expected_domain: The expected domain name.

    Returns:
        True if referer matches expected domain, False otherwise.

    Example:
        >>> validate_referer('https://example.com/page', 'example.com')
        True
    """
    metrics = get_metrics()
    metrics.inc_counter("web.validate_referer.calls")

    with create_span("validate_referer") as span:
        if not referer or not expected_domain:
            span.set_attribute("valid", False)
            metrics.inc_counter("web.validate_referer.invalid")
            return False

        try:
            parsed = urllib.parse.urlparse(referer)
            referer_host = parsed.hostname or ""

            if referer_host == expected_domain:
                span.set_attribute("valid", True)
                metrics.inc_counter("web.validate_referer.valid")
                return True

            if referer_host.endswith("." + expected_domain):
                span.set_attribute("valid", True)
                metrics.inc_counter("web.validate_referer.valid")
                return True

            span.set_attribute("valid", False)
            metrics.inc_counter("web.validate_referer.invalid")
            return False

        except Exception:
            span.set_attribute("valid", False)
            metrics.inc_counter("web.validate_referer.invalid")
            return False


# ---------------------------------------------------------------------------
# 28. secure_redirect
# ---------------------------------------------------------------------------

def secure_redirect(
    url: str,
    allowed_hosts: Optional[list[str]] = None,
) -> str:
    """Validate and return a safe redirect URL.

    Args:
        url: The URL to redirect to.
        allowed_hosts: List of allowed hostnames for redirects.

    Returns:
        The validated URL if safe, or '/' if the redirect is not allowed.

    Raises:
        SecurityError: If the URL contains dangerous patterns.

    Example:
        >>> secure_redirect('https://example.com/page', ['example.com'])
        'https://example.com/page'
    """
    metrics = get_metrics()
    metrics.inc_counter("web.secure_redirect.calls")

    with create_span("secure_redirect") as span:
        if not url:
            span.set_attribute("safe_url", "/")
            metrics.inc_counter("web.secure_redirect.blocked")
            return "/"

        dangerous_patterns = [
            r"javascript\s*:",
            r"data\s*:",
            r"vbscript\s*:",
            r"\balert\s*\(",
            r"\beval\s*\(",
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                logger.warning(
                    "dangerous_redirect_blocked",
                    url=url,
                    pattern=pattern,
                )
                span.set_attribute("blocked", True)
                metrics.inc_counter("web.secure_redirect.blocked")
                raise SecurityError(f"Dangerous redirect URL blocked: {url}")

        if allowed_hosts:
            try:
                parsed = urllib.parse.urlparse(url)
                hostname = parsed.hostname or ""
                hostname = hostname.split(":")[0]

                is_allowed = any(
                    hostname == h or hostname.endswith("." + h)
                    for h in allowed_hosts
                )

                if not is_allowed:
                    logger.warning(
                        "redirect_to_unauthorized_host",
                        url=url,
                        host=hostname,
                    )
                    span.set_attribute("blocked", True)
                    metrics.inc_counter("web.secure_redirect.blocked")
                    return "/"

            except Exception:
                span.set_attribute("blocked", True)
                metrics.inc_counter("web.secure_redirect.blocked")
                return "/"

        logger.info("secure_redirect_allowed", url=url)
        span.set_attribute("safe_url", url)
        metrics.inc_counter("web.secure_redirect.allowed")

        return url


# ---------------------------------------------------------------------------
# 29. webhook_signature
# ---------------------------------------------------------------------------

def webhook_signature(
    payload: str,
    secret: str,
    algorithm: str = "sha256",
    timestamp: Optional[str] = None,
) -> str:
    """Generate a webhook signature for payload verification.

    Args:
        payload: The webhook payload string.
        secret: The shared secret key for HMAC.
        algorithm: Hash algorithm ('sha256', 'sha384', 'sha512'). Defaults to 'sha256'.
        timestamp: Optional timestamp string to include in signature.

    Returns:
        Hex-encoded HMAC signature string.

    Example:
        >>> webhook_signature('{"event": "test"}', 'secret')
        'a1b2c3...'
    """
    metrics = get_metrics()
    metrics.inc_counter("web.webhook_signature.calls")

    with create_span("webhook_signature") as span:
        algorithms = {
            "sha256": hashlib.sha256,
            "sha384": hashlib.sha384,
            "sha512": hashlib.sha512,
        }

        if algorithm not in algorithms:
            raise ValidationError(f"Unsupported algorithm: {algorithm}")

        if timestamp:
            message = f"{timestamp}.{payload}".encode("utf-8")
        else:
            message = payload.encode("utf-8")

        secret_bytes = secret.encode("utf-8")

        signature = hmac.new(
            secret_bytes,
            message,
            algorithms[algorithm],
        ).hexdigest()

        logger.info(
            "webhook_signature_generated",
            algorithm=algorithm,
            has_timestamp=timestamp is not None,
        )

        span.set_attribute("algorithm", algorithm)
        metrics.inc_counter("web.webhook_signature.completed")

        return signature


# ---------------------------------------------------------------------------
# 30. webhook_replay_protection
# ---------------------------------------------------------------------------

def webhook_replay_protection(
    signature: str,
    timestamp: str,
    payload: str,
    secret: str,
    window: int = 300,
) -> bool:
    """Protect against webhook replay attacks by validating signature and timestamp.

    Args:
        signature: The HMAC signature to validate.
        timestamp: The timestamp when the webhook was generated (Unix epoch seconds).
        payload: The original webhook payload.
        secret: The shared secret key for HMAC verification.
        window: Time window in seconds for accepting webhooks. Defaults to 300 (5 minutes).

    Returns:
        True if signature is valid and timestamp is within window, False otherwise.

    Example:
        >>> webhook_replay_protection(sig, str(int(time.time())), payload, 'secret')
        True
    """
    metrics = get_metrics()
    metrics.inc_counter("web.webhook_replay_protection.calls")

    with create_span("webhook_replay_protection") as span:
        try:
            ts = int(timestamp)
        except (ValueError, TypeError):
            logger.warning("webhook_invalid_timestamp", timestamp=timestamp)
            span.set_attribute("valid", False)
            metrics.inc_counter("web.webhook_replay_protection.rejected")
            return False

        current_time = int(time.time())
        time_diff = abs(current_time - ts)

        if time_diff > window:
            logger.warning(
                "webhook_timestamp_outside_window",
                time_diff=time_diff,
                window=window,
            )
            span.set_attribute("valid", False)
            span.set_attribute("reason", "timestamp_expired")
            metrics.inc_counter("web.webhook_replay_protection.expired")
            return False

        expected_signature = webhook_signature(
            payload=payload,
            secret=secret,
            algorithm="sha256",
            timestamp=timestamp,
        )

        is_valid = hmac.compare_digest(signature, expected_signature)

        logger.info(
            "webhook_replay_protection_complete",
            valid=is_valid,
            time_diff=time_diff,
        )

        span.set_attribute("valid", is_valid)
        metrics.inc_counter(
            "web.webhook_replay_protection.valid" if is_valid
            else "web.webhook_replay_protection.invalid"
        )

        return is_valid


__all__ = [
    "detect_xss",
    "sanitize_html",
    "sanitize_svg",
    "sanitize_markdown",
    "sanitize_css",
    "sanitize_js",
    "detect_sqli",
    "detect_nosqli",
    "detect_ssrf",
    "detect_rce",
    "detect_lfi",
    "detect_rfi",
    "detect_template_injection",
    "detect_command_injection",
    "detect_deserialization_attack",
    "detect_path_traversal",
    "detect_open_redirect",
    "validate_cors",
    "secure_headers",
    "generate_csp",
    "validate_csp",
    "csrf_protect",
    "validate_csrf",
    "secure_cookie",
    "detect_clickjacking",
    "validate_origin",
    "validate_referer",
    "secure_redirect",
    "webhook_signature",
    "webhook_replay_protection",
]
