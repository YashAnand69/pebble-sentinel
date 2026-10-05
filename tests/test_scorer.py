import json
import math
from pathlib import Path
import struct

import numpy as np
import pytest

from sentinel.scorer import TransformerScorer

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def model():
    return TransformerScorer()


def test_real_parameter_count_and_tied_output(model):
    assert model.parameters == 1_288_368
    assert len(model.weights) == 22
    assert model.config["context"] == 256
    assert model.weights["tokens"].shape == (51, 144)
    assert "output" not in model.weights


def test_incremental_logits_match_full_reference(model):
    tokens = model.encode("<bos> read proj-file via file-tool . exec test-runner via shell . edit proj-file via file-tool .")
    model.reset()
    reference = model.full_reference(tokens)
    for end in range(1, len(tokens) + 1):
        np.testing.assert_allclose(model.logits(tokens[:end]), reference[end - 1], atol=2e-5, rtol=2e-5)


def test_position_window_rollover_recomputes_exactly(model):
    tokens = model.encode("<bos> " + "read proj-file via file-tool . " * 55)
    model.reset()
    for length in (255, 256, 257, 263):
        np.testing.assert_allclose(model.logits(tokens[:length]), model.full_reference(tokens[:length])[-1], atol=3e-5, rtol=3e-5)


def test_surprise_is_max_token_bits_from_past_context(model):
    prefix = model.encode("<bos> " + "exec test-runner via shell . " * 52)
    action = model.encode("read secret-store via shell tainted .")
    reference = []
    for token in action:
        logits = model.full_reference(prefix)[-1].astype(np.float64)
        value = (np.log(np.exp(logits - logits.max()).sum()) + logits.max() - logits[token]) / math.log(2)
        reference.append(value)
        prefix.append(token)
    model.reset()
    result = model.score_tokens(prefix[:-len(action)], action)
    np.testing.assert_allclose(result["token_bits"], reference, atol=5e-5, rtol=2e-5)
    assert result["surprise_bits"] == max(result["token_bits"])


def test_unknown_input_uses_closed_vocabulary(model):
    assert model.encode("arbitrary-private-value") == [3]
    assert math.isfinite(model.score([], "arbitrary-private-value"))
    with pytest.raises(ValueError):
        model.score([], "")


def test_corrupt_nonfinite_checkpoint_refused(model, tmp_path):
    data = bytearray(model.checkpoint_path.read_bytes())
    start = 14 + struct.unpack_from("<I", data, 10)[0]
    struct.pack_into("<f", data, start, float("nan"))
    path = tmp_path / "broken.pebble-weights"
    path.write_bytes(data)
    with pytest.raises(ValueError, match="nonfinite"):
        TransformerScorer(path)


def test_pebble_numpy_numerical_parity(model):
    path = ROOT / "model/reports/parity.json"
    if not path.exists():
        pytest.skip("Run released parity export before this check")
    fixture = json.loads(path.read_text())
    assert fixture["metadata"]["seed"] == model.metadata["seed"]
    assert fixture["metadata"]["step"] == model.metadata["step"]
    for case in fixture["cases"]:
        model.reset()
        result = model.score_tokens(case["historyTokens"], case["actionTokens"])
        np.testing.assert_allclose(result["token_bits"], case["tokenBits"], atol=7e-5, rtol=3e-5)
