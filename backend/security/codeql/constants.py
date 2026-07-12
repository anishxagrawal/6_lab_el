# Mapping of profiler detected languages to CodeQL language CLI keys and query packs
LANGUAGE_MAP = {
    "python": {
        "codeql_lang": "python",
        "pack": "codeql/python-queries"
    },
    "javascript": {
        "codeql_lang": "javascript",
        "pack": "codeql/javascript-queries"
    },
    "typescript": {
        "codeql_lang": "javascript",  # CodeQL treats TS as JS
        "pack": "codeql/javascript-queries"
    },
    "java": {
        "codeql_lang": "java",
        "pack": "codeql/java-queries"
    },
    "go": {
        "codeql_lang": "go",
        "pack": "codeql/go-queries"
    },
    "c#": {
        "codeql_lang": "csharp",
        "pack": "codeql/csharp-queries"
    },
    "c": {
        "codeql_lang": "cpp",
        "pack": "codeql/cpp-queries"
    },
    "c++": {
        "codeql_lang": "cpp",
        "pack": "codeql/cpp-queries"
    },
    "ruby": {
        "codeql_lang": "ruby",
        "pack": "codeql/ruby-queries"
    }
}
