from pathlib import Path
import os
import tempfile


_TEST_TEMP = str(
    (Path(__file__).resolve().parent / f".pytest-tmp-process-{os.getpid()}").resolve()
)
Path(_TEST_TEMP).mkdir(parents=True, exist_ok=True)
os.environ["TMP"] = _TEST_TEMP
os.environ["TEMP"] = _TEST_TEMP
os.environ["TMPDIR"] = _TEST_TEMP
os.environ["MAILTRACE_DISABLE_BACKGROUND_WORKERS"] = "true"
tempfile.tempdir = _TEST_TEMP
