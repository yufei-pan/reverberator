import pytest
import reverberator as rv


@pytest.fixture(autouse=True)
def restore_runtime_globals():
	old_poll = rv.POLL_WAIT_SECONDS
	rv.GREEN_LIGHT.set()
	yield
	rv.POLL_WAIT_SECONDS = old_poll
	rv.GREEN_LIGHT.set()
