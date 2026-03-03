"""
Arbiter - Action Sequence Modeling

Provides an action-sequence anomaly signal.

If PyTorch is available, uses a tiny Transformer to model sequences of tools.
Otherwise, falls back to a fast bigram frequency model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import math


try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F

    TORCH_AVAILABLE = True
except Exception:  # pragma: no cover
    TORCH_AVAILABLE = False


def _clamp01(x: float) -> float:
    return float(max(0.0, min(float(x), 1.0)))


@dataclass
class SequenceScore:
    anomaly: float  # [0, 1]
    confidence: float  # [0, 1]
    model: str


class BigramSequenceModel:
    """
    Lightweight fallback: P(tool_t | tool_{t-1}) bigram model.
    """

    def __init__(self) -> None:
        self._counts: Dict[str, Dict[Tuple[str, str], int]] = {}
        self._prev: Dict[str, Optional[str]] = {}

    def update_and_score(self, agent_id: str, tool_name: str) -> SequenceScore:
        prev = self._prev.get(agent_id)
        self._prev[agent_id] = tool_name

        if prev is None:
            return SequenceScore(anomaly=0.0, confidence=0.0, model="bigram")

        counts = self._counts.setdefault(agent_id, {})
        pair = (prev, tool_name)
        counts[pair] = counts.get(pair, 0) + 1

        # Estimate probability with Laplace smoothing over observed next-tools.
        total_from_prev = sum(v for (p, _), v in counts.items() if p == prev)
        distinct_next = len({n for (p, n) in counts.keys() if p == prev})
        p = (counts[pair] + 1) / (total_from_prev + max(distinct_next, 1))

        # Anomaly = 1 - probability
        anomaly = 1.0 - float(p)
        # Confidence increases as we see more transitions from this prev tool.
        conf = _clamp01(min(1.0, total_from_prev / 10.0))
        return SequenceScore(anomaly=_clamp01(anomaly), confidence=conf, model="bigram")


if TORCH_AVAILABLE:

    class _TinyTransformer(nn.Module):
        def __init__(self, vocab_size: int, d_model: int = 32, nhead: int = 4) -> None:
            super().__init__()
            self.emb = nn.Embedding(vocab_size, d_model)
            enc_layer = nn.TransformerEncoderLayer(
                d_model=d_model, nhead=nhead, dim_feedforward=64, batch_first=True
            )
            self.enc = nn.TransformerEncoder(enc_layer, num_layers=1)
            self.out = nn.Linear(d_model, vocab_size)

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            # x: [B, T]
            h = self.emb(x)
            h = self.enc(h)
            # Predict next token from final position
            return self.out(h[:, -1, :])  # [B, V]

    class _TinyLSTM(nn.Module):
        def __init__(self, vocab_size: int, d_model: int = 32) -> None:
            super().__init__()
            self.emb = nn.Embedding(vocab_size, d_model)
            self.lstm = nn.LSTM(input_size=d_model, hidden_size=d_model, batch_first=True)
            self.out = nn.Linear(d_model, vocab_size)

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            h = self.emb(x)
            h, _ = self.lstm(h)
            return self.out(h[:, -1, :])  # [B, V]


class TransformerSequenceModel:
    """
    Optional: tiny Transformer next-tool predictor.

    Online-ish: trains briefly on recent history when enough data is available.
    """

    def __init__(
        self,
        context_len: int = 6,
        min_history: int = 20,
        train_steps: int = 50,
        lr: float = 1e-2,
    ) -> None:
        self.context_len = int(context_len)
        self.min_history = int(min_history)
        self.train_steps = int(train_steps)
        self.lr = float(lr)

        self._vocab: Dict[str, int] = {"<pad>": 0}
        self._inv_vocab: List[str] = ["<pad>"]

        self._history: Dict[str, List[int]] = {}
        self._models: Dict[str, "_TinyTransformer"] = {}
        self._optims: Dict[str, "torch.optim.Optimizer"] = {}

    def _id(self, tool: str) -> int:
        if tool not in self._vocab:
            self._vocab[tool] = len(self._inv_vocab)
            self._inv_vocab.append(tool)
        return self._vocab[tool]

    def _ensure_agent_model(self, agent_id: str) -> None:
        if agent_id in self._models:
            return
        vocab_size = len(self._inv_vocab)
        if TORCH_AVAILABLE:
            model = _TinyTransformer(vocab_size=vocab_size)
            self._models[agent_id] = model
            self._optims[agent_id] = torch.optim.Adam(model.parameters(), lr=self.lr)

    def _maybe_expand_vocab(self) -> None:
        # If vocab grew, rebuild all models with new output head.
        vocab_size = len(self._inv_vocab)
        for agent_id, model in list(self._models.items()):
            if model.out.out_features == vocab_size:
                continue
            # Recreate model and drop old weights (simple, robust)
            new_model = _TinyTransformer(vocab_size=vocab_size)
            self._models[agent_id] = new_model
            self._optims[agent_id] = torch.optim.Adam(new_model.parameters(), lr=self.lr)

    def update_and_score(self, agent_id: str, tool_name: str) -> SequenceScore:
        tid = self._id(tool_name)
        self._maybe_expand_vocab()
        self._ensure_agent_model(agent_id)

        hist = self._history.setdefault(agent_id, [])
        hist.append(tid)

        # Need enough history to create training examples
        if len(hist) < self.min_history:
            return SequenceScore(anomaly=0.0, confidence=0.0, model="transformer")

        model = self._models[agent_id]
        optim = self._optims[agent_id]

        # Build training data from recent history
        # Each example: context_len tools -> next tool
        seq = hist[-(self.min_history + self.context_len + 1) :]
        xs: List[List[int]] = []
        ys: List[int] = []
        for i in range(self.context_len, len(seq) - 1):
            ctx = seq[i - self.context_len : i]
            xs.append(ctx)
            ys.append(seq[i])

        if not xs:
            return SequenceScore(anomaly=0.0, confidence=0.0, model="transformer")

        x = torch.tensor(xs, dtype=torch.long)
        y = torch.tensor(ys, dtype=torch.long)

        model.train()
        for _ in range(self.train_steps):
            logits = model(x)
            loss = F.cross_entropy(logits, y)
            optim.zero_grad()
            loss.backward()
            optim.step()

        # Score current event: use last context to predict current tool
        # If insufficient context, return low confidence.
        if len(hist) <= self.context_len:
            return SequenceScore(anomaly=0.0, confidence=0.0, model="transformer")

        ctx = torch.tensor([hist[-self.context_len - 1 : -1]], dtype=torch.long)
        model.eval()
        with torch.no_grad():
            logits = model(ctx)
            prob = float(torch.softmax(logits, dim=-1)[0, tid].item())

        anomaly = 1.0 - prob
        # Confidence rises with more history.
        conf = _clamp01(min(1.0, len(hist) / 50.0))
        return SequenceScore(anomaly=_clamp01(anomaly), confidence=conf, model="transformer")


class LSTMSequenceModel:
    """
    Optional: tiny LSTM next-tool predictor.
    """

    def __init__(
        self,
        context_len: int = 6,
        min_history: int = 20,
        train_steps: int = 50,
        lr: float = 1e-2,
    ) -> None:
        self.context_len = int(context_len)
        self.min_history = int(min_history)
        self.train_steps = int(train_steps)
        self.lr = float(lr)

        self._vocab: Dict[str, int] = {"<pad>": 0}
        self._inv_vocab: List[str] = ["<pad>"]

        self._history: Dict[str, List[int]] = {}
        self._models: Dict[str, "_TinyLSTM"] = {}
        self._optims: Dict[str, "torch.optim.Optimizer"] = {}

    def _id(self, tool: str) -> int:
        if tool not in self._vocab:
            self._vocab[tool] = len(self._inv_vocab)
            self._inv_vocab.append(tool)
        return self._vocab[tool]

    def _ensure_agent_model(self, agent_id: str) -> None:
        if agent_id in self._models:
            return
        vocab_size = len(self._inv_vocab)
        model = _TinyLSTM(vocab_size=vocab_size)
        self._models[agent_id] = model
        self._optims[agent_id] = torch.optim.Adam(model.parameters(), lr=self.lr)

    def _maybe_expand_vocab(self) -> None:
        vocab_size = len(self._inv_vocab)
        for agent_id, model in list(self._models.items()):
            if model.out.out_features == vocab_size:
                continue
            new_model = _TinyLSTM(vocab_size=vocab_size)
            self._models[agent_id] = new_model
            self._optims[agent_id] = torch.optim.Adam(new_model.parameters(), lr=self.lr)

    def update_and_score(self, agent_id: str, tool_name: str) -> SequenceScore:
        tid = self._id(tool_name)
        self._maybe_expand_vocab()
        self._ensure_agent_model(agent_id)

        hist = self._history.setdefault(agent_id, [])
        hist.append(tid)

        if len(hist) < self.min_history:
            return SequenceScore(anomaly=0.0, confidence=0.0, model="lstm")

        model = self._models[agent_id]
        optim = self._optims[agent_id]

        seq = hist[-(self.min_history + self.context_len + 1) :]
        xs: List[List[int]] = []
        ys: List[int] = []
        for i in range(self.context_len, len(seq) - 1):
            ctx = seq[i - self.context_len : i]
            xs.append(ctx)
            ys.append(seq[i])

        if not xs:
            return SequenceScore(anomaly=0.0, confidence=0.0, model="lstm")

        x = torch.tensor(xs, dtype=torch.long)
        y = torch.tensor(ys, dtype=torch.long)

        model.train()
        for _ in range(self.train_steps):
            logits = model(x)
            loss = F.cross_entropy(logits, y)
            optim.zero_grad()
            loss.backward()
            optim.step()

        if len(hist) <= self.context_len:
            return SequenceScore(anomaly=0.0, confidence=0.0, model="lstm")

        ctx = torch.tensor([hist[-self.context_len - 1 : -1]], dtype=torch.long)
        model.eval()
        with torch.no_grad():
            logits = model(ctx)
            prob = float(torch.softmax(logits, dim=-1)[0, tid].item())

        anomaly = 1.0 - prob
        conf = _clamp01(min(1.0, len(hist) / 50.0))
        return SequenceScore(anomaly=_clamp01(anomaly), confidence=conf, model="lstm")


class ActionSequenceModel:
    """
    Facade that selects the best available sequence model.
    """

    def __init__(self) -> None:
        # Prefer Transformer when available; keep LSTM as alternative.
        self._transformer = TransformerSequenceModel() if TORCH_AVAILABLE else None
        self._lstm = LSTMSequenceModel() if TORCH_AVAILABLE else None
        self._bigram = BigramSequenceModel()

    def update_and_score(self, agent_id: str, tool_name: str) -> SequenceScore:
        if self._transformer is not None:
            try:
                s = self._transformer.update_and_score(agent_id, tool_name)
                # If transformer isn't confident yet, blend with bigram.
                if s.confidence < 0.2:
                    b = self._bigram.update_and_score(agent_id, tool_name)
                    anomaly = _clamp01(0.5 * s.anomaly + 0.5 * b.anomaly)
                    conf = _clamp01(max(s.confidence, b.confidence))
                    return SequenceScore(anomaly=anomaly, confidence=conf, model="transformer+bigram")
                return s
            except Exception:
                # Try LSTM, then fallback on any runtime issues
                if self._lstm is not None:
                    try:
                        return self._lstm.update_and_score(agent_id, tool_name)
                    except Exception:
                        return self._bigram.update_and_score(agent_id, tool_name)
                return self._bigram.update_and_score(agent_id, tool_name)

        return self._bigram.update_and_score(agent_id, tool_name)

