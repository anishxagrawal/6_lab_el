# Mapping of profiler detected languages to CodeQL language CLI keys and query packs
LANGUAGE_MAP = {
    "python": {
        "codeql_lang": "python",
        "pack": "codeql/python-queries:codeql-suites/python-security-and-quality.qls"
    },
    "javascript": {
        "codeql_lang": "javascript",
        "pack": "codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls"
    },
    "typescript": {
        "codeql_lang": "javascript",  # CodeQL treats TS as JS
        "pack": "codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls"
    },
    "java": {
        "codeql_lang": "java",
        "pack": "codeql/java-queries:codeql-suites/java-security-and-quality.qls"
    },
    "go": {
        "codeql_lang": "go",
        "pack": "codeql/go-queries:codeql-suites/go-security-and-quality.qls"
    },
    "c#": {
        "codeql_lang": "csharp",
        "pack": "codeql/csharp-queries:codeql-suites/csharp-security-and-quality.qls"
    },
    "c": {
        "codeql_lang": "cpp",
        "pack": "codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls"
    },
    "c++": {
        "codeql_lang": "cpp",
        "pack": "codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls"
    },
    "ruby": {
        "codeql_lang": "ruby",
        "pack": "codeql/ruby-queries:codeql-suites/ruby-security-and-quality.qls"
    }
}
