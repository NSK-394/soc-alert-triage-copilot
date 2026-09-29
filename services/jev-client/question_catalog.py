"""The fixed Jev question catalog and typed request/response models (docs/architecture.md §5).

This module owns two things:

1. `JevStateObject` (+ its nested sections) -- a pydantic model of the Jev state object from
   docs/architecture.md §4, reusing that exact shape (same keys, same types as
   `services/feature-builder/derived_fields.py` actually produces). This is the request payload;
   `client.py` sends `JevStateObject.model_dump(mode="json")` as the `state` argument to
   `typesafe_sdk.TypeSafeClient.system_one`.

2. `QUESTION_CATALOG` -- the six fixed questions from §5's table, expressed as `typesafe_sdk`
   `Choice`/`Noul`/`Score` question objects, plus `JevRawAnswers` -- this module's OWN response
   model (independent of the SDK's answer types) that every question's full probability
   distribution flows through. §5 is explicit that a single bundled confidence value is not
   enough ("don't rely on the single confidence field alone when two options are close"), so every
   choice/score answer here carries `probabilities: dict[str, float]` for every option, not just
   the top pick. Keeping this model independent of `typesafe_sdk`'s own answer types (rather than
   re-exporting them) is deliberate: it is the seam that lets `client.py` swap transports later
   without every caller of this catalog needing to change.

Mapping from §5's type names to `typesafe_sdk` question types:
    Choice      -> `typesafe_sdk.Choice`  (named options, e.g. triage_verdict)
    Probability -> `typesafe_sdk.Noul`    (a single 0-1 probability, e.g. is_false_positive)
    Score       -> `typesafe_sdk.Score`   (an ordered rubric, e.g. severity)
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from typesafe_sdk import Choice, Noul, Score

# ---------------------------------------------------------------------------
# Request side: the Jev state object (docs/architecture.md §4)
# ---------------------------------------------------------------------------


class AlertSection(BaseModel):
    """`state.alert` -- the raw-ish alert metadata (not counted/derived)."""

    model_config = ConfigDict(extra="forbid")

    source: str
    rule_id: str
    rule_description: str
    rule_level: int | None = None
    # Nullable: not every alert source has an equivalent field (e.g. the GUIDE
    # dataset converter has no rule-level analog and sends null -- see
    # data/converters/guide_to_state.py and docs/architecture.md §4).
    mitre_hint: list[str] = Field(default_factory=list)
    timestamp_utc: str


class EntitiesSection(BaseModel):
    """`state.entities` -- the entities involved in the alert."""

    model_config = ConfigDict(extra="forbid")

    src_ip: str | None = None
    user: str | None = None
    host: str | None = None


class DerivedSection(BaseModel):
    """`state.derived` -- everything counted/dated, computed in feature-builder, never left for
    Jev to infer (docs/architecture.md §5, "known failure modes"). Field names and types match
    `services/feature-builder/derived_fields.py::build_derived`'s return value exactly.
    """

    model_config = ConfigDict(extra="forbid")

    failed_auth_10m: int
    successful_auth_after_failures: bool
    off_hours: bool
    src_ip_first_seen_days: int
    src_ip_reputation: str
    host_criticality: str
    rule_historical_fp_rate: float
    similar_alerts_24h: int


class UntrustedEvidenceSection(BaseModel):
    """`state.untrusted_evidence` -- the ONLY place attacker-controlled strings appear.

    Treated as hostile input by both tiers (docs/architecture.md §4, §10). This client's job is
    transport/parsing only: whatever string ends up here is passed through to Jev untouched and
    never used to alter this client's own control flow (no eval, no dynamic dispatch on its
    contents) -- see client.py's module docstring.
    """

    model_config = ConfigDict(extra="forbid")

    raw_log_excerpt: str


class JevStateObject(BaseModel):
    """The full Jev state object sent as `state` in one `POST /v1/systemone` call."""

    model_config = ConfigDict(extra="forbid")

    alert: AlertSection
    entities: EntitiesSection
    derived: DerivedSection
    untrusted_evidence: UntrustedEvidenceSection


# ---------------------------------------------------------------------------
# The fixed question catalog (docs/architecture.md §5, table in §5)
# ---------------------------------------------------------------------------

TRIAGE_VERDICT_OPTIONS: tuple[str, ...] = (
    "true_positive",
    "benign_positive",
    "false_positive",
    "other",
)

# The 14 MITRE ATT&CK tactics named in §5, plus "other".
ATTACK_CATEGORY_OPTIONS: tuple[str, ...] = (
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
    "other",
)

# Ordered low -> high; a Score question's criteria list position IS the level (§5: "4 levels").
SEVERITY_LEVELS: tuple[str, ...] = ("informational", "low", "high", "critical")

# Ordered low -> high (§5: "3 levels").
BUSINESS_IMPACT_LEVELS: tuple[str, ...] = ("low", "medium", "high")

QUESTION_CATALOG: dict[str, Choice | Noul | Score] = {
    "triage_verdict": Choice(
        instructions=(
            "Classify this alert the way a SOC analyst would triage it, matching the Microsoft "
            "GUIDE dataset's own label taxonomy."
        ),
        criteria={
            "true_positive": "A real security incident occurred; the alert is correctly firing.",
            "benign_positive": "The alert correctly detected real activity, but that activity was authorized/expected, not malicious.",
            "false_positive": "The alert fired but the underlying detection logic misfired; no matching activity of concern occurred.",
            "other": "None of the above cleanly applies, or there is not enough information to decide.",
        },
    ),
    "is_false_positive": Noul(
        instructions=(
            "Independent of triage_verdict: what is the probability this alert is a false "
            "positive? Used as a cross-check against triage_verdict, not a restatement of it."
        ),
        criteria={
            "true": "This is very likely a false positive.",
            "false": "This is very likely NOT a false positive.",
        },
    ),
    "severity": Score(
        instructions="Rate this alert's severity for the SOC's auto-close/escalate policy.",
        criteria=[
            "Informational: no action needed even if true.",
            "Low: minor, routine follow-up at most.",
            "High: significant risk; warrants prompt analyst attention.",
            "Critical: severe, active risk; warrants immediate escalation.",
        ],
    ),
    "attack_category": Choice(
        instructions=(
            "Which MITRE ATT&CK tactic best matches this alert's activity? Use 'other' if none of "
            "the 14 tactics clearly applies."
        ),
        criteria={option: None for option in ATTACK_CATEGORY_OPTIONS},
    ),
    "needs_more_context": Noul(
        instructions=(
            "What is the probability that a human analyst (or a deeper Tier-2 investigation) "
            "would need more surrounding context/events to make a confident call on this alert? "
            "This is the primary signal used to trigger Tier-2 escalation."
        ),
        criteria={
            "true": "More context is very likely needed before acting on this alert.",
            "false": "This alert is very likely self-contained enough to decide on directly.",
        },
    ),
    "business_impact_if_true": Score(
        instructions=(
            "IF triage_verdict leans true_positive, how severe would the business impact be? "
            "(Still answer even if you lean false_positive/benign_positive -- the policy engine "
            "only consults this field when true_positive is likely.)"
        ),
        criteria=[
            "Low: limited/contained blast radius even if confirmed.",
            "Medium: moderate blast radius; a non-crown-jewel system or contained data.",
            "High: severe blast radius; crown-jewel system, broad access, or sensitive data.",
        ],
    ),
}


# ---------------------------------------------------------------------------
# Response side: this module's own typed answer models (transport-independent)
# ---------------------------------------------------------------------------


class ChoiceAnswer(BaseModel):
    """A `Choice`-type answer: the top pick plus the FULL probability distribution."""

    model_config = ConfigDict(frozen=True)

    selected: str
    """The option with the highest probability."""
    probabilities: dict[str, float]
    """Every option's probability, keyed by option name; sums to ~1.0."""


class ScoreAnswer(BaseModel):
    """A `Score`-type answer: the top pick plus the FULL probability distribution over levels."""

    model_config = ConfigDict(frozen=True)

    selected: str
    """The rubric level (from the ordered criteria list) with the highest probability."""
    expected_value: float
    """The SDK's probability-weighted average level index; informational only -- policy/margin
    logic should key off `probabilities`/`selected`, not this."""
    probabilities: dict[str, float]
    """Every rubric level's probability, keyed by level name; sums to ~1.0."""


class ProbabilityAnswer(BaseModel):
    """A `Noul`-type answer: a single 0-1 probability. No distribution to speak of (binary)."""

    model_config = ConfigDict(frozen=True)

    probability: float = Field(ge=0.0, le=1.0)


class JevRawAnswers(BaseModel):
    """All six typed answers for one alert, one call (docs/architecture.md §5: "All six answered
    in one call per alert")."""

    model_config = ConfigDict(frozen=True)

    triage_verdict: ChoiceAnswer
    is_false_positive: ProbabilityAnswer
    severity: ScoreAnswer
    attack_category: ChoiceAnswer
    needs_more_context: ProbabilityAnswer
    business_impact_if_true: ScoreAnswer


QuestionKey = Literal[
    "triage_verdict",
    "is_false_positive",
    "severity",
    "attack_category",
    "needs_more_context",
    "business_impact_if_true",
]
