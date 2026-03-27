from __future__ import annotations

import os
import re
import traceback
from pathlib import Path

try:
    from allure_commons._core import plugin_manager
    from allure_commons._hooks import hookimpl
    from allure_commons.logger import AllureFileLogger
    from allure_commons.model2 import Parameter, Status, StatusDetails, TestResult, TestStepResult
    from allure_commons.reporter import AllureReporter
    from allure_commons.utils import now, uuid4
except Exception:  # pragma: no cover - optional dependency
    plugin_manager = None
    AllureFileLogger = None
    hookimpl = None
    AllureReporter = None
    Parameter = None
    Status = None
    StatusDetails = None
    TestResult = None
    TestStepResult = None
    now = None
    uuid4 = None


_LOGGER = None
_REPORTER = None
_LISTENER = None
_CURRENT_TEST_UUID = None
_CURRENT_PAGE = None


def _results_dir() -> Path | None:
    env_dir = os.getenv("ALLURE_RESULTS_DIR", "").strip()
    if env_dir:
        return Path(env_dir)
    return None


def _ensure_lifecycle():
    global _LOGGER, _REPORTER, _LISTENER
    if AllureFileLogger is None or AllureReporter is None or plugin_manager is None:
        return None
    results_dir = _results_dir()
    if not results_dir:
        return None
    results_dir.mkdir(parents=True, exist_ok=True)

    if _LOGGER is None:
        _LOGGER = AllureFileLogger(str(results_dir))
    try:
        if _LOGGER not in plugin_manager.get_plugins():
            plugin_manager.register(_LOGGER)
    except Exception:
        pass

    if _REPORTER is None:
        _REPORTER = AllureReporter()

    if _LISTENER is None:
        _LISTENER = _StandaloneAllureListener(_REPORTER)
        try:
            if _LISTENER not in plugin_manager.get_plugins():
                plugin_manager.register(_LISTENER)
        except Exception:
            pass

    return _REPORTER


def set_current_page(page):
    global _CURRENT_PAGE
    _CURRENT_PAGE = page


def _sanitize_filename(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", name or "test")


def _highlight_last_locator(page) -> None:
    try:
        locator = getattr(page, "_last_locator", None)
        if not locator:
            return
        target = None
        try:
            target = locator.first if hasattr(locator, "first") else locator
        except Exception:
            target = locator
        if hasattr(target, "scroll_into_view_if_needed"):
            try:
                target.scroll_into_view_if_needed(timeout=1000)
            except Exception:
                pass
        try:
            target.evaluate(
                "el => { if (!el) return; el.setAttribute('data-smartai-highlight','1');"
                "el.style.outline='3px solid #ff3b30'; el.style.outlineOffset='2px';"
                "el.style.boxShadow='0 0 0 2px rgba(255,59,48,0.4)'; }"
            )
        except Exception:
            pass
    except Exception:
        pass


def _capture_failure_screenshot(test_name: str, test_uuid: str | None):
    page = _CURRENT_PAGE
    if page is None:
        return None
    try:
        results_dir = _results_dir()
        if not results_dir:
            return None
        results_dir.mkdir(parents=True, exist_ok=True)
        safe_name = _sanitize_filename(test_name)
        suffix = f"_{test_uuid}" if test_uuid else ""
        path = results_dir / f"{safe_name}{suffix}_failure.png"
        try:
            _highlight_last_locator(page)
            page.screenshot(path=str(path), full_page=False)
        except Exception:
            return None
        return path
    except Exception:
        return None


class _StandaloneAllureListener:
    def __init__(self, reporter):
        self.reporter = reporter

    @hookimpl
    def start_step(self, uuid, title, params):
        if TestStepResult is None:
            return
        step = TestStepResult()
        step.name = title
        if now:
            step.start = now()
        if Parameter is not None and isinstance(params, dict) and params:
            step.parameters = [
                Parameter(name=str(key), value=str(value))
                for key, value in params.items()
            ]
        self.reporter.start_step(_CURRENT_TEST_UUID, uuid, step)

    @hookimpl
    def stop_step(self, uuid, exc_type, exc_val, exc_tb):
        kwargs = {}
        if exc_type and Status is not None:
            kwargs["status"] = Status.FAILED
            if StatusDetails is not None:
                kwargs["statusDetails"] = StatusDetails(
                    message=str(exc_val),
                    trace="".join(traceback.format_exception(exc_type, exc_val, exc_tb)),
                )
        elif Status is not None:
            kwargs["status"] = Status.PASSED
        if now:
            kwargs["stop"] = now()
        self.reporter.stop_step(uuid, **kwargs)

    @hookimpl
    def attach_data(self, body, name, attachment_type, extension):
        self.reporter.attach_data(
            _CURRENT_TEST_UUID,
            body,
            name=name,
            attachment_type=attachment_type,
            extension=extension,
        )

    @hookimpl
    def attach_file(self, source, name, attachment_type, extension):
        self.reporter.attach_file(
            _CURRENT_TEST_UUID,
            source,
            name=name,
            attachment_type=attachment_type,
            extension=extension,
        )


def run_allure_case(name: str, func, *args, **kwargs):
    global _CURRENT_TEST_UUID
    reporter = _ensure_lifecycle()
    if reporter is None or TestResult is None or Status is None:
        return func(*args, **kwargs)
    outcome = None
    error = None
    test_result = TestResult()
    if uuid4:
        test_result.uuid = uuid4()
    test_result.name = name
    if now:
        test_result.start = now()
    test_uuid = test_result.uuid
    reporter.schedule_test(test_uuid, test_result)
    _CURRENT_TEST_UUID = test_uuid
    try:
        outcome = func(*args, **kwargs)
        test_result.status = Status.PASSED
    except Exception as exc:
        error = exc
        test_result.status = Status.FAILED
        if StatusDetails:
            test_result.statusDetails = StatusDetails(
                message=str(exc),
                trace=traceback.format_exc(),
            )
        try:
            screenshot_path = _capture_failure_screenshot(name, test_uuid)
            if screenshot_path and reporter is not None:
                reporter.attach_file(
                    test_uuid,
                    str(screenshot_path),
                    name="Failure Screenshot",
                    attachment_type="image/png",
                    extension="png",
                )
        except Exception:
            pass
    finally:
        if now:
            test_result.stop = now()
        _CURRENT_TEST_UUID = None
    reporter.close_test(test_uuid)
    if error:
        raise error
    return outcome
