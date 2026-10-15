"""Structural and optional Draft 2020-12 validation for the public JSON schemas."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = PROJECT_ROOT / "schemas"

try:
    from jsonschema import Draft202012Validator, ValidationError
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012
except ImportError:
    Draft202012Validator = None
    ValidationError = None
    Registry = None
    Resource = None
    DRAFT202012 = None


def read_schema(name: str) -> dict[str, object]:
    with (SCHEMA_ROOT / name).open(encoding="utf-8") as schema_file:
        return json.load(schema_file)


class SchemaStructureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report_schema = read_schema("report-v1.schema.json")
        self.batch_schema = read_schema("batch-v1.schema.json")
        self.error_schema = read_schema("error-v1.schema.json")

    def test_schemas_declare_draft_2020_12(self) -> None:
        draft = "https://json-schema.org/draft/2020-12/schema"
        self.assertEqual(self.report_schema["$schema"], draft)
        self.assertEqual(self.batch_schema["$schema"], draft)
        self.assertEqual(self.error_schema["$schema"], draft)
        for schema in (self.report_schema, self.batch_schema, self.error_schema):
            self.assertNotIn("$id", schema)

    def test_single_error_schema_is_exact_and_versioned(self) -> None:
        self.assertEqual(
            set(self.error_schema["required"]), {"schema_version", "error"}
        )
        self.assertIs(self.error_schema["additionalProperties"], False)
        self.assertEqual(
            self.error_schema["properties"]["schema_version"], {"const": 1}
        )
        self.assertEqual(self.error_schema["properties"]["error"]["type"], "string")

    def test_report_is_exact_versioned_shape_and_keeps_codes_open(self) -> None:
        self.assertEqual(
            set(self.report_schema["required"]),
            {
                "schema_version",
                "format",
                "member_count",
                "total_size",
                "complete",
                "ok",
                "findings",
            },
        )
        self.assertIs(self.report_schema["additionalProperties"], False)
        properties = self.report_schema["properties"]
        self.assertEqual(properties["schema_version"], {"const": 1})
        finding = self.report_schema["$defs"]["finding"]
        self.assertEqual(set(finding["required"]), {"code", "member", "message"})
        self.assertIs(finding["additionalProperties"], False)
        self.assertEqual(finding["properties"]["code"]["type"], "string")
        self.assertNotIn("enum", finding["properties"]["code"])

    def test_batch_requires_report_or_error_with_local_report_reference(self) -> None:
        self.assertEqual(
            set(self.batch_schema["required"]),
            {"schema_version", "kind", "ok", "results"},
        )
        self.assertIs(self.batch_schema["additionalProperties"], False)
        self.assertEqual(self.batch_schema["properties"]["kind"], {"const": "batch"})
        result = self.batch_schema["$defs"]["result"]
        self.assertEqual(len(result["oneOf"]), 2)
        report_result, error_result = result["oneOf"]
        self.assertEqual(set(report_result["required"]), {"archive", "report"})
        self.assertEqual(
            report_result["properties"]["report"]["$ref"],
            "./report-v1.schema.json",
        )
        self.assertEqual(set(error_result["required"]), {"archive", "error"})
        for variant in (report_result, error_result):
            self.assertIs(variant["additionalProperties"], False)
        self.assertEqual(self.batch_schema["properties"]["results"]["minItems"], 1)


@unittest.skipUnless(
    Draft202012Validator is not None,
    "install the optional jsonschema package to run Draft 2020-12 validation",
)
class JSONSchemaValidationTests(unittest.TestCase):
    """Use jsonschema when available to validate fixtures and actual CLI output."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.report_schema = read_schema("report-v1.schema.json")
        cls.batch_schema = read_schema("batch-v1.schema.json")
        cls.error_schema = read_schema("error-v1.schema.json")
        report_resource = Resource.from_contents(
            cls.report_schema, default_specification=DRAFT202012
        )
        cls.registry = Registry().with_resource(
            "./report-v1.schema.json", report_resource
        )
        Draft202012Validator.check_schema(cls.report_schema)
        Draft202012Validator.check_schema(cls.batch_schema)
        Draft202012Validator.check_schema(cls.error_schema)
        cls.report_validator = Draft202012Validator(cls.report_schema)
        cls.error_validator = Draft202012Validator(cls.error_schema)
        cls.batch_validator = Draft202012Validator(
            cls.batch_schema, registry=cls.registry
        )

    def test_accepts_real_single_and_batch_cli_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            safe = temp / "safe.zip"
            unsafe = temp / "unsafe.zip"
            broken = temp / "broken.zip"
            with zipfile.ZipFile(safe, "w") as archive:
                archive.writestr("readme.txt", "ok")
            with zipfile.ZipFile(unsafe, "w") as archive:
                archive.writestr("../outside.txt", "flagged")
            broken.write_bytes(b"not an archive")

            single = self._run_cli(safe, "--json")
            self.assertEqual(single.returncode, 0, single.stderr)
            single_report = json.loads(single.stdout)
            self.report_validator.validate(single_report)

            single_error = self._run_cli(broken, "--json")
            self.assertEqual(single_error.returncode, 2, single_error.stderr)
            self.error_validator.validate(json.loads(single_error.stdout))

            batch = self._run_cli(safe, unsafe, broken, "--json")
            self.assertEqual(batch.returncode, 2, batch.stderr)
            batch_result = json.loads(batch.stdout)
            self.batch_validator.validate(batch_result)
            self.assertEqual(len(batch_result["results"]), 3)
            self.assertIn("report", batch_result["results"][0])
            self.assertIn("report", batch_result["results"][1])
            self.assertIn("error", batch_result["results"][2])

    def test_rejects_both_report_and_error_and_bad_report_shapes(self) -> None:
        valid_report = {
            "schema_version": 1,
            "format": "zip",
            "member_count": 1,
            "total_size": 1,
            "complete": True,
            "ok": True,
            "findings": [],
        }
        valid_batch = {
            "schema_version": 1,
            "kind": "batch",
            "ok": True,
            "results": [{"archive": "input.zip", "report": valid_report}],
        }
        self.batch_validator.validate(valid_batch)

        future_finding_report = {
            **valid_report,
            "ok": False,
            "findings": [
                {
                    "code": "future-code",
                    "member": "bad",
                    "message": "finding",
                }
            ],
        }
        self.report_validator.validate(future_finding_report)

        both_shapes = {
            **valid_batch,
            "results": [
                {
                    "archive": "input.zip",
                    "report": valid_report,
                    "error": "read failed",
                }
            ],
        }
        with self.assertRaises(ValidationError):
            self.batch_validator.validate(both_shapes)

        inconsistent_batch_ok = {**valid_batch, "ok": False}
        with self.assertRaises(ValidationError):
            self.batch_validator.validate(inconsistent_batch_ok)

        successful_batch_with_error = {
            **valid_batch,
            "results": [{"archive": "input.zip", "error": "read failed"}],
        }
        with self.assertRaises(ValidationError):
            self.batch_validator.validate(successful_batch_with_error)

        empty_batch = {**valid_batch, "results": []}
        with self.assertRaises(ValidationError):
            self.batch_validator.validate(empty_batch)

        for report in (
            {key: value for key, value in valid_report.items() if key != "ok"},
            {**valid_report, "member_count": "one"},
            {
                **valid_report,
                "findings": [
                    {
                        "code": "future-code",
                        "member": "bad",
                        "message": "finding",
                    }
                ],
            },
            {**valid_report, "complete": False},
        ):
            malformed_batch = {
                **valid_batch,
                "results": [{"archive": "input.zip", "report": report}],
            }
            with self.subTest(report=report), self.assertRaises(ValidationError):
                self.batch_validator.validate(malformed_batch)

        for result in (
            {"archive": "input.zip", "report": valid_report, "extra": True},
            {"archive": "input.zip"},
            {"archive": 7, "error": "read failed"},
        ):
            malformed_batch = {**valid_batch, "results": [result]}
            with self.subTest(result=result), self.assertRaises(ValidationError):
                self.batch_validator.validate(malformed_batch)

    def _run_cli(self, *arguments: Path | str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        source = str(PROJECT_ROOT / "src")
        environment["PYTHONPATH"] = source + (
            os.pathsep + environment["PYTHONPATH"]
            if environment.get("PYTHONPATH")
            else ""
        )
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "archive_preflight",
                *(str(argument) for argument in arguments),
            ],
            cwd=PROJECT_ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )


if __name__ == "__main__":
    unittest.main()
