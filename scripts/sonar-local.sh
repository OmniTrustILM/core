#!/usr/bin/env bash
# Local SonarQube analysis for core (Java/Maven).
# Spins up an ephemeral SonarQube Community container, runs mvn verify with
# JaCoCo coverage, then the Sonar Maven plugin against the local instance,
# waits for the server to process the report, and prints the quality gate +
# open issues.
# Usage: ./scripts/sonar-local.sh
#
# IMPORTANT — Limitation of ephemeral SonarQube:
# The SonarQube container is freshly started on every run, so it has no
# previous analysis to use as a "new code" baseline. The Quality Gate's
# new-code conditions therefore evaluate trivially OK and do NOT match the
# behaviour you'll see on SonarCloud (where a real baseline exists). To
# approximate PR-style focus locally, this script queries the issues of each
# file changed since the merge base with origin/main (`git diff`; uncommitted
# and untracked files count, as the scan analyses them), marks the issues on
# lines the branch added, and reports the duplication on those lines.
# Use it as a smoke-check; treat SonarCloud on the actual PR as authoritative.
set -euo pipefail

CONTAINER_NAME="ilm-core-sonarqube"
SONAR_PORT="${SONAR_PORT:-9000}"
PROJECT_KEY="ilm-core"
SONAR_URL="http://localhost:${SONAR_PORT}"
BASE_BRANCH="${BASE_BRANCH:-origin/main}"

# Resolved before the container and the build start: an unusable base would
# otherwise show up only after the scan, as a silent whole-project listing.
if ! MERGE_BASE=$(git merge-base "${BASE_BRANCH}" HEAD 2>/dev/null); then
    echo "ERROR: Cannot compare against '${BASE_BRANCH}' (not found or no common history)."
    echo "Run 'git fetch origin' or set BASE_BRANCH=<ref>."
    exit 1
fi

cleanup() {
    echo "Stopping SonarQube..."
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

echo "Starting SonarQube Community on port ${SONAR_PORT}..."
docker run -d --name "${CONTAINER_NAME}" -p "${SONAR_PORT}:9000" sonarqube:community >/dev/null

echo "Waiting for SonarQube to be ready (up to 2 minutes)..."
for i in $(seq 1 120); do
    if curl -sf "${SONAR_URL}/api/system/status" 2>/dev/null | grep -q '"status":"UP"'; then
        echo "SonarQube is ready."
        break
    fi
    if [ "$i" -eq 120 ]; then
        echo "ERROR: SonarQube failed to start within 2 minutes."
        exit 1
    fi
    sleep 1
done

echo "Configuring SonarQube..."
# SonarQube ships with `admin/admin` as the factory default; the server forces
# this password to be changed on first login. We rotate it to `Admin12345678!`
# (a value that satisfies SonarQube's password policy) so the rest of the script
# can authenticate. Both credentials are scoped to this ephemeral container only —
# the container is removed by the EXIT trap, so neither value is persisted.
curl -s -o /dev/null -u admin:admin -X POST \
    "${SONAR_URL}/api/users/change_password?login=admin&previousPassword=admin&password=Admin12345678!" 2>/dev/null || true

if curl -sf -u admin:Admin12345678! "${SONAR_URL}/api/system/status" >/dev/null 2>&1; then
    SONAR_CREDS="admin:Admin12345678!"
elif curl -sf -u admin:admin "${SONAR_URL}/api/system/status" >/dev/null 2>&1; then
    SONAR_CREDS="admin:admin"
else
    echo "ERROR: Cannot authenticate to SonarQube."
    exit 1
fi

TOKEN_NAME="ci-$(date +%s)"
TOKEN=$(curl -sf -u "${SONAR_CREDS}" -X POST \
    "${SONAR_URL}/api/user_tokens/generate?name=${TOKEN_NAME}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

if [ -z "${TOKEN}" ]; then
    echo "ERROR: Failed to generate SonarQube token."
    exit 1
fi

echo "Running mvn verify with JaCoCo..."
mvn -B -U verify -Dmaven.compiler.proc=full

echo "Running sonar:sonar..."
# Full coordinates: the plugin's group is not in Maven's default pluginGroups,
# so the short `sonar:` prefix does not resolve.
mvn -B org.sonarsource.scanner.maven:sonar-maven-plugin:sonar \
    -Dmaven.compiler.proc=full \
    -Dsonar.projectKey="${PROJECT_KEY}" \
    -Dsonar.host.url="${SONAR_URL}" \
    -Dsonar.token="${TOKEN}" \
    -Dsonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml \
    -Dsonar.cpd.minimumTokens=100

echo ""
echo "=== SonarQube Results ==="
echo "Dashboard: ${SONAR_URL}/dashboard?id=${PROJECT_KEY}"

# Sonar processes the analysis report asynchronously after upload. Wait for the
# Compute Engine task of this analysis: until it succeeds, the quality gate and
# the issue list are missing or partial.
echo ""
echo "Waiting for Sonar to process the analysis..."
CE_TASK_URL=$(sed -n 's/^ceTaskUrl=//p' target/sonar/report-task.txt 2>/dev/null || true)
if [ -z "${CE_TASK_URL}" ]; then
    echo "ERROR: ceTaskUrl not found in target/sonar/report-task.txt."
    exit 1
fi
# Each request is bounded, so a server that stops answering cannot outlast the deadline.
CE_DEADLINE=$((SECONDS + 300))
while true; do
    CE_STATUS=$(curl -s --max-time 10 -u "${SONAR_CREDS}" "${CE_TASK_URL}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['task']['status'])" 2>/dev/null || true)
    case "${CE_STATUS}" in
        SUCCESS)
            break
            ;;
        FAILED|CANCELED)
            echo "ERROR: Sonar analysis task ended as ${CE_STATUS}."
            exit 1
            ;;
    esac
    if [ "${SECONDS}" -ge "${CE_DEADLINE}" ]; then
        echo "ERROR: Sonar did not finish processing the analysis within 5 minutes."
        exit 1
    fi
    sleep 2
done
GATE=$(curl -s --max-time 30 -u "${SONAR_CREDS}" \
    "${SONAR_URL}/api/qualitygates/project_status?projectKey=${PROJECT_KEY}" || true)

# Determine the set of files changed since the merge base with the base branch
# (origin/main by default), uncommitted and untracked ones included: the scan
# analysed the working tree. We report the issues of those files only —
# ephemeral SonarQube has no previous analysis to use as a "new code" baseline,
# so we approximate PR-style focus with the git diff.
# quotePath=false: Git would escape non-ASCII names, which Sonar does not know by that spelling.
CHANGED=$(git -c core.quotePath=false diff --name-only "${MERGE_BASE}")
UNTRACKED=$(git -c core.quotePath=false ls-files --others --exclude-standard)
CHANGED=$(printf '%s\n%s\n' "${CHANGED}" "${UNTRACKED}" | sed '/^$/d' | sort -u)
if [ -z "${CHANGED}" ]; then
    echo ""
    echo "(No changes vs ${BASE_BRANCH}; reporting full project for first-run baseline.)"
    SCOPE_DESC="all project files"
else
    echo ""
    echo "Files changed vs ${BASE_BRANCH}:"
    echo "${CHANGED}" | sed 's/^/  /'
    SCOPE_DESC="changed files only"
fi

echo ""
echo "================================================================================"
echo "EPHEMERAL SONARQUBE — LIMITATION"
echo "================================================================================"
echo "  This run uses a freshly-started SonarQube container with no previous"
echo "  analysis to act as a 'new code' baseline. The Quality Gate evaluates"
echo "  trivially OK and does NOT match SonarCloud, where a real baseline exists."
echo "  Treat this as a smoke check; SonarCloud on the actual PR is authoritative."
echo "================================================================================"

echo ""
echo "Quality Gate (whole project; new-code conditions trivially OK without baseline):"
echo "${GATE}" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)['projectStatus']
    print(f'  Status: {d[\"status\"]}')
    for c in d.get('conditions', []):
        print(f'  {c[\"metricKey\"]}: {c[\"actualValue\"]} (threshold: {c[\"errorThreshold\"]}) - {c[\"status\"]}')
except Exception as e:
    print(f'  WARN: Quality gate not available ({e}). See dashboard.')
"

echo ""
echo "Issues — ${SCOPE_DESC} (unresolved):"
# One query per changed file: a project-wide search returns pages of 500 in no
# useful order, so the changed files' issues are mostly not on the first page.
SONAR_URL="${SONAR_URL}" PROJECT_KEY="${PROJECT_KEY}" BASE_BRANCH="${BASE_BRANCH}" \
MERGE_BASE="${MERGE_BASE}" SONAR_CREDS="${SONAR_CREDS}" CHANGED_LIST="${CHANGED}" python3 - <<'PY'
import base64, json, os, re, subprocess, sys, urllib.error, urllib.parse, urllib.request

URL = os.environ['SONAR_URL']
KEY = os.environ['PROJECT_KEY']
BASE = os.environ['BASE_BRANCH']
MERGE_BASE = os.environ['MERGE_BASE']
AUTH ='Basic ' + base64.b64encode(os.environ['SONAR_CREDS'].encode()).decode()
CHANGED = [f.strip() for f in os.environ['CHANGED_LIST'].splitlines() if f.strip()]
PAGE_SIZE = 500
LIST_LIMIT = 50


def api(endpoint, **params):
    request = urllib.request.Request(f'{URL}/api/{endpoint}?{urllib.parse.urlencode(params)}',
                                     headers={'Authorization': AUTH})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def unresolved_issues(component):
    issues, page = [], 1
    while True:
        result = api('issues/search', components=component, resolved='false', ps=PAGE_SIZE, p=page)
        issues += result['issues']
        total = result['paging']['total']
        if len(issues) >= total:
            return issues
        # The search API serves at most 10000 results, however many pages are asked for.
        if page * PAGE_SIZE >= 10000:
            sys.exit(f'ERROR: {component} has {total} unresolved issues, more than the search API serves.')
        page += 1


def known_component(component):
    # An unknown file is not an error for the issue search: it answers with zero issues.
    try:
        return api('components/show', component=component)['component']
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def git(*args):
    return subprocess.run(['git', '-c', 'core.quotePath=false', *args],
                          capture_output=True, text=True, check=True).stdout


def added_lines():
    # No external diff or text conversion: the parser reads the plain unified format.
    diff = git('diff', '-M', '-U0', '--no-color', '--no-ext-diff', '--no-textconv',
               '--src-prefix=a/', '--dst-prefix=b/', MERGE_BASE)
    added, path, in_header = {}, None, False
    for line in diff.splitlines():
        if line.startswith('diff --git '):
            path, in_header = None, True
        elif in_header and line.startswith('+++ '):
            # Git ends the header with a tab when the path contains a space.
            path = line[6:].rstrip('\t') if line.startswith('+++ b/') else None
        elif line.startswith('@@ '):
            in_header = False
            if path:
                start, count = re.match(r'@@ -\S+ \+(\d+)(?:,(\d+))?', line).groups()
                added.setdefault(path, set()).update(range(int(start), int(start) + int(count or 1)))
    # The scan reads the working tree, where a file that is not tracked yet is new in full.
    for path in git('ls-files', '--others', '--exclude-standard').splitlines():
        if os.path.isfile(path):
            with open(path, encoding='utf-8', errors='replace') as source:
                added[path] = set(range(1, len(source.readlines()) + 1))
    return added


def duplicated_lines(component):
    result = api('duplications/show', key=component)
    own_refs = {ref for ref, file in result['files'].items() if file['key'] == component}
    lines = set()
    for duplication in result['duplications']:
        for block in duplication['blocks']:
            if block['_ref'] in own_refs:
                lines.update(range(block['from'], block['from'] + block['size']))
    return lines


def print_issues(title, issues, limit=None):
    if issues:
        print(f'  {title}:')
    for issue in sorted(issues, key=lambda i: (i['component'], i.get('line', 0)))[:limit]:
        path = issue['component'].split(':', 1)[-1]
        print(f'    [{issue.get("severity", "?")}] {path}:{issue.get("line", "?")} - {issue["message"]}')


def main():
    if not CHANGED:
        result = api('issues/search', components=KEY, resolved='false', ps=PAGE_SIZE)
        print(f'  Total in scope: {result["paging"]["total"]}')
        print_issues(f'Up to {LIST_LIMIT} shown', result['issues'], LIST_LIMIT)
        return
    added = added_lines()
    on_added, pre_existing = [], []
    known = new_lines = duplicated = 0
    for path in CHANGED:
        component = f'{KEY}:{path}'
        info = known_component(component)
        if info is None:
            continue
        known += 1
        lines = added.get(path, set())
        for issue in unresolved_issues(component):
            (on_added if issue.get('line') in lines else pre_existing).append(issue)
        # Sonar detects duplications in main code only, so test files stay out of the ratio.
        if info['qualifier'] == 'FIL':
            new_lines += len(lines)
            duplicated += len(lines & duplicated_lines(component))
    print(f'  Files known to Sonar: {known} of {len(CHANGED)} changed')
    print(f'  Total in scope: {len(on_added) + len(pre_existing)} ({len(on_added)} on lines added vs {BASE})')
    print_issues('On lines added by this branch', on_added)
    print_issues(f'Pre-existing on changed files (up to {LIST_LIMIT} shown)', pre_existing, LIST_LIMIT)
    if new_lines:
        print(f'  Duplication on added lines (main code): {duplicated} of {new_lines} '
              f'({100 * duplicated / new_lines:.1f}%)')


try:
    main()
except (OSError, subprocess.CalledProcessError) as error:
    sys.exit(f'ERROR: {error}')
PY

echo ""
echo "Done. (Set BASE_BRANCH=<other> to compare against a different base; default: origin/main.)"
