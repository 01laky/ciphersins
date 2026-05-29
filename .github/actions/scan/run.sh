#!/usr/bin/env bash
set -euo pipefail

ACTION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

INPUT_PATH="${INPUT_PATH:-.}"
INPUT_VERSION="${INPUT_VERSION:-1.3.2}"
INPUT_FAIL_ON="${INPUT_FAIL_ON:-high}"
INPUT_FORMAT="${INPUT_FORMAT:-sarif}"
INPUT_OUTPUT="${INPUT_OUTPUT:-}"
INPUT_CONFIG="${INPUT_CONFIG:-}"
INPUT_NO_CONFIG="${INPUT_NO_CONFIG:-false}"
INPUT_ONLY="${INPUT_ONLY:-}"
INPUT_IGNORE="${INPUT_IGNORE:-}"
INPUT_CWD="${INPUT_CWD:-}"
INPUT_NO_COLOR="${INPUT_NO_COLOR:-true}"
INPUT_INCLUDE="${INPUT_INCLUDE:-}"
INPUT_EXCLUDE="${INPUT_EXCLUDE:-}"
INPUT_MAX_FINDINGS="${INPUT_MAX_FINDINGS:-}"
INPUT_ALLOW_CRITICAL_IGNORE="${INPUT_ALLOW_CRITICAL_IGNORE:-false}"
INPUT_VERBOSE="${INPUT_VERBOSE:-false}"
INPUT_STRICT_CONFIG="${INPUT_STRICT_CONFIG:-false}"
INPUT_WRITE_SUMMARY="${INPUT_WRITE_SUMMARY:-true}"
INPUT_SCAN_TITLE="${INPUT_SCAN_TITLE:-CipherSins}"
INPUT_SOFT_FAIL="${INPUT_SOFT_FAIL:-false}"

WORKSPACE="${GITHUB_WORKSPACE:-$(pwd)}"
EFFECTIVE_CWD="${INPUT_CWD:-$WORKSPACE}"

if [ -z "$INPUT_OUTPUT" ]; then
	case "$INPUT_FORMAT" in
	json) INPUT_OUTPUT="ciphersins.json" ;;
	sarif) INPUT_OUTPUT="ciphersins.sarif" ;;
	*) INPUT_OUTPUT="" ;;
	esac
fi

resolve_default_path() {
	local base="$1"
	local path_input="$2"
	if [ -z "$path_input" ] || [ "$path_input" = "." ]; then
		if [ -d "$base/src" ]; then
			echo "./src"
		else
			echo "."
		fi
	else
		echo "$path_input"
	fi
}

EFFECTIVE_PATH="$(resolve_default_path "$EFFECTIVE_CWD" "$INPUT_PATH")"

IFS=',' read -ra PATH_PARTS <<< "$EFFECTIVE_PATH"
SCAN_ARGS=()
for part in "${PATH_PARTS[@]}"; do
	trimmed="$(echo "$part" | xargs)"
	if [ -n "$trimmed" ]; then
		SCAN_ARGS+=("$trimmed")
	fi
done

CLI_ARGS=(scan "${SCAN_ARGS[@]}")

CLI_ARGS+=(--format "$INPUT_FORMAT")

if [ "$INPUT_FAIL_ON" = "none" ]; then
	CLI_ARGS+=(--fail-on none)
elif [ -n "$INPUT_FAIL_ON" ]; then
	CLI_ARGS+=(--fail-on "$INPUT_FAIL_ON")
fi

if [ -n "$INPUT_OUTPUT" ]; then
	CLI_ARGS+=(--output "$INPUT_OUTPUT")
fi

if [ -n "$INPUT_CONFIG" ]; then
	CLI_ARGS+=(--config "$INPUT_CONFIG")
fi

if [ "$INPUT_NO_CONFIG" = "true" ]; then
	CLI_ARGS+=(--no-config)
fi

if [ -n "$INPUT_ONLY" ]; then
	CLI_ARGS+=(--only "$INPUT_ONLY")
fi

if [ -n "$INPUT_IGNORE" ]; then
	CLI_ARGS+=(--ignore "$INPUT_IGNORE")
fi

if [ -n "$INPUT_CWD" ]; then
	CLI_ARGS+=(--cwd "$INPUT_CWD")
fi

if [ "$INPUT_NO_COLOR" = "true" ]; then
	CLI_ARGS+=(--no-color)
fi

if [ -n "$INPUT_INCLUDE" ]; then
	IFS=',' read -ra INC_PARTS <<< "$INPUT_INCLUDE"
	for inc in "${INC_PARTS[@]}"; do
		trimmed_inc="$(echo "$inc" | xargs)"
		if [ -n "$trimmed_inc" ]; then
			CLI_ARGS+=(--include "$trimmed_inc")
		fi
	done
fi

if [ -n "$INPUT_EXCLUDE" ]; then
	IFS=',' read -ra EXC_PARTS <<< "$INPUT_EXCLUDE"
	for exc in "${EXC_PARTS[@]}"; do
		trimmed_exc="$(echo "$exc" | xargs)"
		if [ -n "$trimmed_exc" ]; then
			CLI_ARGS+=(--exclude "$trimmed_exc")
		fi
	done
fi

if [ -n "$INPUT_MAX_FINDINGS" ]; then
	CLI_ARGS+=(--max-findings "$INPUT_MAX_FINDINGS")
fi

if [ "$INPUT_ALLOW_CRITICAL_IGNORE" = "true" ]; then
	CLI_ARGS+=(--allow-critical-ignore)
fi

if [ "$INPUT_VERBOSE" = "true" ]; then
	CLI_ARGS+=(--verbose)
fi

if [ "$INPUT_STRICT_CONFIG" = "true" ]; then
	CLI_ARGS+=(--strict-config)
fi

set +e
if [ "$INPUT_VERSION" = "workspace" ]; then
	WORKSPACE_CLI="$WORKSPACE/packages/ciphersins/dist/cli.js"
	if [ ! -f "$WORKSPACE_CLI" ]; then
		echo "error: workspace CLI not found at $WORKSPACE_CLI — run npm run build first" >&2
		exit 2
	fi
	(
		cd "$EFFECTIVE_CWD"
		node "$WORKSPACE_CLI" "${CLI_ARGS[@]}"
	)
else
	(
		cd "$EFFECTIVE_CWD"
		npx --yes "ciphersins@${INPUT_VERSION}" "${CLI_ARGS[@]}"
	)
fi
EXIT_CODE=$?
set -e

OUTPUT_ABS=""
if [ -n "$INPUT_OUTPUT" ]; then
	OUTPUT_ABS="$(cd "$EFFECTIVE_CWD" && cd "$(dirname "$INPUT_OUTPUT")" && pwd)/$(basename "$INPUT_OUTPUT")"
fi

FINDINGS_COUNT=""
SUMMARY_LINE=""

if [ -n "$OUTPUT_ABS" ] && [ -f "$OUTPUT_ABS" ]; then
	SUMMARY_JSON="$(node "$ACTION_DIR/write-summary.mjs" \
		"$INPUT_FORMAT" \
		"$OUTPUT_ABS" \
		"$EXIT_CODE" \
		"$INPUT_SCAN_TITLE" \
		"$INPUT_FAIL_ON" \
		"$EFFECTIVE_PATH" \
		"$INPUT_WRITE_SUMMARY")"

	FINDINGS_COUNT="$(echo "$SUMMARY_JSON" | node -e "process.stdin.on('data',d=>{const j=JSON.parse(d);console.log(j.counts.total)})")"
	SUMMARY_LINE="$(echo "$SUMMARY_JSON" | node -e "process.stdin.on('data',d=>{const j=JSON.parse(d);console.log(j.summaryLine)})")"
fi

{
	echo "exit-code=$EXIT_CODE"
	echo "findings-count=$FINDINGS_COUNT"
	echo "summary=$SUMMARY_LINE"
	if [ -n "$OUTPUT_ABS" ]; then
		echo "sarif-path=$OUTPUT_ABS"
	fi
} >> "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

if [ "$EXIT_CODE" -ge 2 ]; then
	exit "$EXIT_CODE"
fi

if [ "$EXIT_CODE" -eq 1 ] && [ "$INPUT_SOFT_FAIL" != "true" ]; then
	exit 1
fi

exit 0
