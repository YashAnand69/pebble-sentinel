from __future__ import annotations

import hashlib
import json
import math
import struct
import threading
from pathlib import Path

import numpy as np
from threadpoolctl import threadpool_limits

ROOT = Path(__file__).resolve().parents[2]
MODEL_ROOT = ROOT / "model"


def softmax(values: np.ndarray) -> np.ndarray:
    shifted = values - np.max(values, axis=-1, keepdims=True)
    exponentials = np.exp(shifted)
    return exponentials / exponentials.sum(axis=-1, keepdims=True)


def normalize(values: np.ndarray) -> np.ndarray:
    centered = values - values.mean(axis=-1, keepdims=True)
    return centered / np.sqrt((centered * centered).mean(axis=-1, keepdims=True) + np.float32(1e-5))


def gelu(values: np.ndarray) -> np.ndarray:
    return np.float32(0.5) * values * (1 + np.tanh(np.float32(math.sqrt(2 / math.pi)) * (values + np.float32(0.044715) * values ** 3)))


class TransformerScorer:
    def __init__(self, weights: str | Path | None = None, vocabulary: str | Path | None = None):
        self.thread_limit = threadpool_limits(limits=1, user_api="blas")
        path = Path(weights) if weights else MODEL_ROOT / "weights" / "seed-2026.pebble-weights"
        self.checkpoint_path = path
        raw = path.read_bytes()
        if not raw.startswith(b"PEBBLELM1\n") or len(raw) > 20_000_000:
            raise ValueError("Invalid or oversized Pebble checkpoint")
        header_size = struct.unpack_from("<I", raw, 10)[0]
        if header_size > 1_000_000 or header_size + 14 > len(raw):
            raise ValueError("Invalid checkpoint header length")
        header = json.loads(raw[14:14 + header_size])
        if header.get("format") != "pebble-weights" or header.get("version") != 1 or header.get("dtype") != "float32":
            raise ValueError("Unsupported checkpoint format")
        self.metadata = header["metadata"]
        self.config = self.metadata["config"]
        self.context = int(self.config["context"])
        self.width = int(self.config["width"])
        self.heads = int(self.config["heads"])
        self.layers = int(self.config["layers"])
        if not (1 <= self.context <= 256 and self.width % self.heads == 0 and 1 <= self.layers <= 12):
            raise ValueError("Invalid model architecture")
        vocabulary_path = Path(vocabulary) if vocabulary else MODEL_ROOT / "pal_vocab_v0.json"
        self.vocabulary = json.loads(vocabulary_path.read_text())
        self.lookup = {word: index for index, word in enumerate(self.vocabulary)}
        if len(self.vocabulary) != self.config["vocab"] or len(self.lookup) != len(self.vocabulary):
            raise ValueError("Vocabulary does not match checkpoint")
        expected = {"tokens": [self.config["vocab"], self.width], "positions": [self.context, self.width]}
        for layer in range(self.layers):
            expected.update({f"block{layer}.qkv": [3 * self.width, self.width], f"block{layer}.attention": [self.width, self.width], f"block{layer}.expand": [self.config["expansion"], self.width], f"block{layer}.project": [self.width, self.config["expansion"]]})
        self.weights = {}
        offset = 0
        payload = memoryview(raw)[14 + header_size:]
        for description in header["parameters"]:
            name = description["name"]
            shape = description["shape"]
            size = math.prod(shape) * 4
            if name not in expected or name in self.weights or shape != expected[name] or description["offset"] != offset or description["bytes"] != size or offset + size > len(payload):
                raise ValueError("Checkpoint parameter mismatch")
            tensor = np.frombuffer(payload[offset:offset + size], dtype="<f4").reshape(shape)
            if not np.isfinite(tensor).all():
                raise ValueError("Checkpoint has nonfinite parameters")
            self.weights[name] = tensor
            offset += size
        if offset != len(payload) or set(expected) != set(self.weights):
            raise ValueError("Checkpoint payload mismatch")
        self.parameters = sum(array.size for array in self.weights.values())
        self.sha256 = hashlib.sha256(raw).hexdigest()
        self.name = "Pebble PAL Transformer"
        self.hold_threshold = 0.0
        self.block_threshold = float("inf")
        self.metadata = {**self.metadata, "kind": "trained-pal-transformer", "parameters": self.parameters, "sha256": self.sha256, "calibrated": False}
        calibration_path = ROOT / "results/calibration.json"
        if calibration_path.exists():
            calibration = json.loads(calibration_path.read_text())
            if calibration.get("model_sha256") == self.sha256:
                self.hold_threshold = float(calibration["hold_threshold"])
                self.block_threshold = float(calibration["block_threshold"])
                if not (math.isfinite(self.hold_threshold) and math.isfinite(self.block_threshold) and 0 <= self.hold_threshold <= self.block_threshold):
                    raise ValueError("Invalid model calibration thresholds")
                self.metadata["calibrated"] = True
        self._lock = threading.RLock()
        self.reset()

    def encode(self, sentence: str) -> list[int]:
        return [self.lookup.get(token, 3) for token in sentence.split()]

    def reset(self) -> None:
        self._prefix = []
        head_width = self.width // self.heads
        self._keys = [np.empty((self.heads, self.context, head_width), dtype=np.float32) for _ in range(self.layers)]
        self._values = [np.empty((self.heads, self.context, head_width), dtype=np.float32) for _ in range(self.layers)]
        self._logits = None

    def _consume(self, token: int) -> np.ndarray:
        position = len(self._prefix)
        if position >= self.context:
            raise ValueError("Cache exceeds context")
        hidden = self.weights["tokens"][token] + self.weights["positions"][position]
        head_width = self.width // self.heads
        for layer in range(self.layers):
            label = f"block{layer}."
            qkv = self.weights[label + "qkv"] @ normalize(hidden)
            q, k, v = qkv.reshape(3, self.heads, head_width)
            self._keys[layer][:, position, :] = k
            self._values[layer][:, position, :] = v
            scores = np.einsum("hd,htd->ht", q, self._keys[layer][:, :position + 1, :]) / np.float32(math.sqrt(head_width))
            attention = np.einsum("ht,htd->hd", softmax(scores), self._values[layer][:, :position + 1, :]).reshape(self.width)
            hidden = hidden + self.weights[label + "attention"] @ attention
            hidden = hidden + self.weights[label + "project"] @ gelu(self.weights[label + "expand"] @ normalize(hidden))
        self._prefix.append(int(token))
        self._logits = self.weights["tokens"] @ normalize(hidden)
        return self._logits

    def _set_prefix(self, tokens: list[int]) -> np.ndarray:
        selected = tokens[-self.context:] or [0]
        if self._prefix != selected[:len(self._prefix)]:
            return self._prefill(selected)
        for token in selected[len(self._prefix):]:
            self._consume(token)
        return self._logits

    def _prefill(self, tokens: list[int]) -> np.ndarray:
        self.reset()
        length = len(tokens)
        hidden = self.weights["tokens"][tokens] + self.weights["positions"][:length]
        triangle = np.triu_indices(length, 1)
        for layer in range(self.layers):
            label = f"block{layer}."
            qkv = normalize(hidden) @ self.weights[label + "qkv"].T
            q, k, v = [part.reshape(length, self.heads, self.width // self.heads).transpose(1, 0, 2) for part in np.split(qkv, 3, axis=-1)]
            self._keys[layer][:, :length, :] = k
            self._values[layer][:, :length, :] = v
            scores = q @ k.transpose(0, 2, 1) / np.float32(math.sqrt(self.width // self.heads))
            scores[:, triangle[0], triangle[1]] = np.float32(-1e9)
            attention = (softmax(scores) @ v).transpose(1, 0, 2).reshape(length, self.width)
            hidden = hidden + attention @ self.weights[label + "attention"].T
            hidden = hidden + gelu(normalize(hidden) @ self.weights[label + "expand"].T) @ self.weights[label + "project"].T
        self._prefix = list(tokens)
        self._logits = self.weights["tokens"] @ normalize(hidden[-1])
        return self._logits

    def logits(self, tokens: list[int]) -> np.ndarray:
        with self._lock:
            return self._set_prefix(tokens).copy()

    def score_tokens(self, history_tokens: list[int], action_tokens: list[int]) -> dict:
        if not action_tokens:
            raise ValueError("Action must contain PAL tokens")
        with self._lock:
            prefix = list(history_tokens) or [0]
            surprises = []
            for token in action_tokens:
                logits = self._set_prefix(prefix)
                logsum = float(np.log(np.exp(logits - logits.max()).sum()) + logits.max())
                surprises.append((logsum - float(logits[token])) / math.log(2))
                prefix.append(token)
            self._set_prefix(prefix)
            return {"surprise_bits": max(surprises), "token_bits": surprises, "tokens": [self.vocabulary[token] for token in action_tokens]}

    def score(self, history: list[str] | str, sentence: str) -> float:
        text = history if isinstance(history, str) else " ".join(history)
        prefix = [0] + self.encode(text)
        return float(self.score_tokens(prefix, self.encode(sentence))["surprise_bits"])

    def full_reference(self, tokens: list[int]) -> np.ndarray:
        tokens = (tokens or [0])[-self.context:]
        width = self.width
        hidden = self.weights["tokens"][tokens] + self.weights["positions"][:len(tokens)]
        for layer in range(self.layers):
            label = f"block{layer}."
            qkv = normalize(hidden) @ self.weights[label + "qkv"].T
            q, k, v = [part.reshape(len(tokens), self.heads, width // self.heads).transpose(1, 0, 2) for part in np.split(qkv, 3, axis=-1)]
            scores = q @ k.transpose(0, 2, 1) / np.float32(math.sqrt(width // self.heads))
            scores[:, np.triu_indices(len(tokens), 1)[0], np.triu_indices(len(tokens), 1)[1]] = np.float32(-1e9)
            attention = (softmax(scores) @ v).transpose(1, 0, 2).reshape(len(tokens), width)
            hidden = hidden + attention @ self.weights[label + "attention"].T
            hidden = hidden + gelu(normalize(hidden) @ self.weights[label + "expand"].T) @ self.weights[label + "project"].T
        return normalize(hidden) @ self.weights["tokens"].T
