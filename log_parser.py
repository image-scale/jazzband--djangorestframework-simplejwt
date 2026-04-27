import re


def parse_log(log: str) -> dict[str, str]:
    """Parse test runner output into per-test results.

    Args:
        log: Full stdout+stderr output of `bash run_test.sh 2>&1`.

    Returns:
        Dict mapping test_id to status.
        - test_id: pytest native format e.g. "tests/foo.py::TestClass::test_func"
        - status: one of "PASSED", "FAILED", "SKIPPED", "ERROR"
    """
    results = {}

    # Strip ANSI escape codes
    log = re.sub(r'\x1b\[[0-9;]*m', '', log)

    # Match pytest verbose lines: "test_id STATUS [ XX%]"
    # e.g. "tests/test_foo.py::TestClass::test_method PASSED [  5%]"
    pattern = re.compile(
        r'^(tests/\S+::[\S ]+?)\s+(PASSED|FAILED|SKIPPED|ERROR)\s+\[\s*\d+%\]',
        re.MULTILINE
    )
    for m in pattern.finditer(log):
        test_id = m.group(1).strip()
        status = m.group(2)
        results.setdefault(test_id, status)

    # Handle collection errors: "ERROR tests/foo.py" (no "::")
    error_pattern = re.compile(
        r'^ERROR\s+(tests/\S+\.py)\s*$',
        re.MULTILINE
    )
    for m in error_pattern.finditer(log):
        test_id = m.group(1).strip()
        results.setdefault(test_id, 'ERROR')

    return results

