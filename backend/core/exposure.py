from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

import httpx


async def get_first_commit_date(
    client: httpx.AsyncClient,
    owner: str,
    name: str,
    file_path: str,
    repo_path: str | None = None,
) -> tuple[datetime | None, int]:
    """
    Get first commit date and exposure duration.
    """

    if repo_path:
        try:
            import subprocess
            result = subprocess.run(
                ["git", "log", "--follow", "--format=%cI", "--reverse", "--", file_path],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True,
                timeout=5
            )
            dates = result.stdout.strip().splitlines()
            if dates:
                first_commit_date_str = dates[0]
                # Convert ISO-8601 string to datetime. In Python 3.11+, fromisoformat handles 'Z' and offset formats natively.
                # However, to be extra safe:
                dt_str = first_commit_date_str.replace("Z", "+00:00")
                first_commit_dt = datetime.fromisoformat(dt_str)
                now = datetime.now(timezone.utc)
                exposure_days = max(0, (now - first_commit_dt).days)
                print(f"OK: Exposure calculated (local git) for {file_path} ({exposure_days} days)")
                return first_commit_dt, exposure_days
        except Exception as e:
            print(f"WARNING: Local git lookup failed for {file_path}: {e}. Falling back to GitHub API.")

    try:

        url = (
            f"https://api.github.com/repos/"
            f"{owner}/{name}/commits"
        )

        response = await client.get(
            url,
            params={
                "path": file_path,
                "per_page": 1,
                "page": 1,
            },
            timeout=10,
        )

        if response.status_code != 200:

            print(
                f"WARNING: GitHub API returned "
                f"{response.status_code} "
                f"for {owner}/{name}/{file_path}"
            )

            return None, 0

        history_response = response

        last_link = response.links.get(
            "last"
        )

        if (
            last_link
            and last_link.get("url")
        ):

            history_response = (
                await client.get(
                    last_link["url"],
                    timeout=10,
                )
            )

            if (
                history_response.status_code
                != 200
            ):
                print(
                    "WARNING: GitHub API "
                    "last-page lookup failed "
                    f"for {owner}/{name}/{file_path}"
                )

                return None, 0

        commits = history_response.json()

        if (
            not commits
            or not isinstance(
                commits,
                list,
            )
        ):
            print(
                f"WARNING: No commits found "
                f"for {file_path}"
            )

            return None, 0

        oldest_commit = commits[0]

        commit_meta = (
            oldest_commit.get(
                "commit",
                {},
            )
        )

        commit_date_str = (
            commit_meta.get(
                "committer",
                {},
            ).get("date")
            or
            commit_meta.get(
                "author",
                {},
            ).get("date")
        )

        if not commit_date_str:

            print(
                f"WARNING: No commit date "
                f"found for {file_path}"
            )

            return None, 0

        first_commit_dt = (
            datetime.fromisoformat(
                commit_date_str.replace(
                    "Z",
                    "+00:00",
                )
            )
        )

        now = datetime.now(
            timezone.utc
        )

        exposure_days = max(
            0,
            (
                now
                - first_commit_dt
            ).days,
        )

        print(
            f"OK: Exposure calculated "
            f"for {file_path} "
            f"({exposure_days} days)"
        )

        return (
            first_commit_dt,
            exposure_days,
        )

    except Exception as e:

        print(
            f"WARNING: Error calculating "
            f"exposure for {file_path}: {e}"
        )

        return None, 0


def calculate_exposure_score(
    severity: str,
    exposure_days: int,
) -> float:
    """
    severity_rank × log₂(days + 2)
    """

    severity_map = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    severity_rank = (
        severity_map.get(
            str(severity).upper(),
            1,
        )
    )

    if exposure_days < 0:
        exposure_days = 0

    exposure_multiplier = (
        math.log2(
            exposure_days + 2
        )
    )

    return round(
        severity_rank
        * exposure_multiplier,
        2,
    )


async def hydrate_missing_exposure_fields(
    supabase_client,
    owner: str,
    name: str,
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Backfill missing exposure data.
    """

    pending = [
        finding
        for finding in findings
        if (
            finding.get(
                "first_commit_date"
            )
            is None
            or finding.get(
                "exposure_days"
            )
            is None
            or finding.get(
                "exposure_score"
            )
            is None
        )
    ]

    if not pending:
        return findings

    async with httpx.AsyncClient(
        timeout=30
    ) as http_client:

        for finding in pending:

            file_path = str(
                finding.get(
                    "file_path"
                )
                or ""
            ).strip()

            if not file_path:
                continue

            (
                first_commit_date,
                exposure_days,
            ) = await get_first_commit_date(
                http_client,
                owner,
                name,
                file_path,
            )

            if first_commit_date is None:
                continue

            exposure_score = (
                calculate_exposure_score(
                    str(
                        finding.get(
                            "severity"
                        )
                        or "LOW"
                    ),
                    exposure_days,
                )
            )

            patch = {
                "first_commit_date":
                    first_commit_date.isoformat(),

                "exposure_days":
                    exposure_days,

                "exposure_score":
                    exposure_score,
            }

            finding.update(
                patch
            )

            try:

                if finding.get("id"):

                    (
                        supabase_client
                        .table("findings")
                        .update(patch)
                        .eq(
                            "id",
                            finding["id"],
                        )
                        .execute()
                    )

            except Exception as exc:

                print(
                    "WARNING: Failed to "
                    "backfill exposure "
                    f"fields for {file_path}: "
                    f"{exc}"
                )

    return findings