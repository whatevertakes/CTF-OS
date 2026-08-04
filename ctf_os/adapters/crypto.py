from __future__ import annotations

from .base import ExperimentSpec, GenericAdapter, ProgressMarker, ProofPolicy


_STATIC_SOURCE_PARAMETER_SCAN = (
    "set -eu; target=$1; "
    "if [ -L \"$target\" ]; then "
    "printf '%s\\n' 'ctfos_static_scan_error=not_regular_file' >&2; "
    "exit 2; fi; "
    "if [ ! -f \"$target\" ]; then "
    "printf '%s\\n' 'ctfos_scan_mode=skipped' "
    "'ctfos_static_scan_reason=no_regular_source_binding'; "
    "exit 0; fi; "
    "case \"$target\" in "
    "*.py|*.pyw|*.sage) language=python; "
    "pattern='^[[:space:]]*(from[[:space:]]+[A-Za-z0-9_.]+[[:space:]]+import|import[[:space:]]+|(async[[:space:]]+)?(def|class)[[:space:]]+|print([[:space:]]|>>)|[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[^=]|.*(AES|DES|RSA|SHA|MD5|pow|random|randint|encrypt|decrypt)[A-Za-z0-9_.]*[[:space:]]*\\()' ;; "
    "*.ipynb|*.json) language=json; "
    "pattern='^[[:space:]]*\"[^\"]+\"[[:space:]]*:' ;; "
    "*.c|*.h|*.cc|*.cpp|*.cxx|*.hpp) language=c_family; "
    "pattern='^[[:space:]]*(#[[:space:]]*define[[:space:]]+|(static[[:space:]]+)?const[[:space:]]+|.*(AES|DES|RSA|SHA|MD5|BN_|EVP_)[A-Za-z0-9_]*[[:space:]]*\\()' ;; "
    "*.js|*.mjs|*.ts) language=javascript; "
    "pattern='^[[:space:]]*((export[[:space:]]+)?(const|let|var|class|function)[[:space:]]+|.*(encrypt|decrypt|digest|subtle)[A-Za-z0-9_.]*[[:space:]]*\\()' ;; "
    "*.rb) language=ruby; "
    "pattern='^[[:space:]]*(require[[:space:]]+|[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=|.*(encrypt|decrypt|digest)[A-Za-z0-9_.]*[[:space:]]*\\()' ;; "
    "*) language=text; "
    "pattern='^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*[[:space:]]*=|.*(AES|DES|RSA|SHA|MD5|encrypt|decrypt))' ;; "
    "esac; "
    "dialect_hint=; "
    "if [ \"$language\" = python ]; then dialect_hint=unknown; "
    "if /usr/bin/head -c 512 -- \"$target\" | /usr/bin/head -n 1 | "
    "rg --text --quiet -- '^#![[:space:]]*([^[:space:]]*/python2([.][0-9]+)?|[^[:space:]]*/env[[:space:]]+(-S[[:space:]]+)?python2([.][0-9]+)?)([[:space:]]|$)'; "
    "then dialect_hint=python2_shebang; "
    "elif /usr/bin/head -c 512 -- \"$target\" | /usr/bin/head -n 1 | "
    "rg --text --quiet -- '^#![[:space:]]*([^[:space:]]*/python3([.][0-9]+)?|[^[:space:]]*/env[[:space:]]+(-S[[:space:]]+)?python3([.][0-9]+)?)([[:space:]]|$)'; "
    "then dialect_hint=python3_shebang; fi; fi; "
    "mime=$(/usr/bin/file --brief --mime-type -- \"$target\"); "
    "size=$(/usr/bin/stat --format=%s -- \"$target\"); "
    "if [ \"$size\" -gt 262144 ]; then truncated=true; "
    "else truncated=false; fi; "
    "printf 'ctfos_scan_mode=static\\nctfos_source_language=%s\\n' "
    "\"$language\"; "
    "if [ \"$language\" = python ]; then "
    "printf 'ctfos_source_dialect_hint=%s\\n' \"$dialect_hint\"; fi; "
    "printf 'ctfos_source_mime=%s\\nctfos_source_bytes=%s\\n' "
    "\"$mime\" \"$size\"; "
    "printf 'ctfos_scan_limit_bytes=262144\\nctfos_locator_output_limit_bytes=60000\\nctfos_scan_truncated=%s\\n' "
    "\"$truncated\"; "
    "/usr/bin/head -c 262144 -- \"$target\" | "
    "rg --text --line-number --no-heading --color never --max-count 120 "
    "--max-columns 384 --max-columns-preview -- \"$pattern\" - | "
    "/usr/bin/head -c 60000 || true"
)


class CryptoAdapter(GenericAdapter):
    name = "crypto"

    def initial_observations(self) -> tuple[ExperimentSpec, ...]:
        return (
            ExperimentSpec(
                "source_parameters",
                (
                    "classify source language and extract bounded static "
                    "primitive, parameter, and sample-structure locators"
                ),
                (
                    "/bin/sh",
                    "-lc",
                    _STATIC_SOURCE_PARAMETER_SCAN,
                    "ctfos-crypto-static-source-scan",
                    "{primary}",
                ),
                (
                    "language and MIME classification plus bounded exact "
                    "parameter/source line locators"
                ),
                "primitive and parameter scale are known from static evidence",
                "primary input is not a regular source-like file",
                "light",
                30,
            ),
        )

    def progress_markers(self) -> tuple[ProgressMarker, ...]:
        return tuple(
            ProgressMarker(key, label, "parameter/source locator or executed run")
            for key, label in (
                ("paradigm_classified", "attack paradigm classified"),
                ("parameters_captured", "parameters captured"),
                ("known_attack_matched", "known attack conditions matched"),
                ("sweep_bounded", "parameter sweep bounded"),
                ("plaintext_recovered", "plaintext recovered"),
                (
                    "metamorphic_variant_verified",
                    "changed-parameter variant verified",
                ),
            )
        )

    def proof_policy(self, *, remote: bool = False) -> ProofPolicy:
        return ProofPolicy(
            mode="sample_matrix",
            clean_repetitions=3,
            remote_repetitions=1 if remote else 0,
            notes=(
                "preserve per-sample successes and failures separately; "
                "candidate promotion requires the six-run "
                "crypto_solver_metamorphic_variant_v1 contract"
            ),
        )

    def failure_labels(self) -> tuple[str, ...]:
        return (
            "wrong_paradigm",
            "parameter_scale_mismatch",
            "abstract_only_reference",
            "reimplemented_known_primitive",
            "sample_overfit",
            "metamorphic_variant_failed",
            "solver_nondeterministic",
            "runtime_unpinned",
        )

    def captain_guidance(self) -> str:
        return (
            "Classify the paradigm before writing a solver. Preserve full source "
            "documents with hashes when external knowledge is needed; abstracts "
            "alone are insufficient. Prefer vetted Sage/flatter implementations "
            "for lattice and finite-field operations. Treat "
            "`ctfos_source_dialect_hint=python2_shebang` as a parser-routing "
            "constraint: do not use Python 3 `ast.parse`, `compile`, or "
            "`py_compile` on that source; use bounded text locators or a parser "
            "that explicitly supports Python 2. `unknown` does not mean Python "
            "3; establish compatibility first. A `SyntaxError` may indicate a "
            "parser/dialect mismatch and does not refute the attack hypothesis. "
            "Preserve the solver, "
            "runtime fingerprint, inputs, outputs, and assumptions as one "
            "replayable workspace. A candidate is not Crypto proof until "
            "crypto_solver_metamorphic_variant_v1 passes three clean original "
            "runs and three clean runs of an independently expected, changed-"
            "parameter variant."
        )
