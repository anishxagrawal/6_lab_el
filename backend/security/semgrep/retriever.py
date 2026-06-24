from pathlib import Path

from .constants import KNOWLEDGE_DIR


def normalize_category(
    category: str,
) -> str:
    """
    A03:2021 -> A03
    """

    if not category:
        return ""

    return category.split(":")[0]


def knowledge_file_path(
    category: str,
) -> Path:

    category = normalize_category(
        category
    )

    return KNOWLEDGE_DIR / f"{category}.md"


def load_knowledge_document(
    category: str,
) -> str:
    """
    Load single OWASP document.
    """

    path = knowledge_file_path(
        category
    )

    if not path.exists():
        return ""

    try:
        return path.read_text(
            encoding="utf-8"
        )

    except Exception:
        return ""


def retrieve_knowledge(
    categories: list[str],
) -> str:
    """
    Retrieve OWASP documents
    for detected categories.
    """

    chunks = []

    seen = set()

    for category in categories:

        category = normalize_category(
            category
        )

        if category in seen:
            continue

        seen.add(category)

        document = load_knowledge_document(
            category
        )

        if document:
            chunks.append(
                f"""
=========================
{category}
=========================

{document}
"""
            )

    return "\n\n".join(
        chunks
    )


def retrieve_category_context(
    category: str,
) -> str:
    """
    Retrieve a single category.
    """

    return load_knowledge_document(
        category
    )


def build_retrieval_metadata(
    categories: list[str],
) -> dict:
    """
    Metadata useful for logging,
    analytics, debugging.
    """

    unique_categories = sorted(
        {
            normalize_category(cat)
            for cat in categories
            if cat
        }
    )

    return {
        "categories": unique_categories,
        "documents_retrieved": len(
            unique_categories
        ),
    }


def retrieve_context_bundle(
    categories: list[str],
) -> dict:
    """
    Convenience wrapper.

    Returns:

    {
        "context": "...",
        "metadata": {...}
    }
    """

    context = retrieve_knowledge(
        categories
    )

    metadata = (
        build_retrieval_metadata(
            categories
        )
    )

    return {
        "context": context,
        "metadata": metadata,
    }