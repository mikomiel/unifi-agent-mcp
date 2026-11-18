"""Typed policy previews and the fixed Integration API policy routes."""

from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    model_validator,
)

from .network_api import UniFiApiError, UniFiNetworkApi

Operation = Literal["create", "update", "delete"]
Rule = dict[str, JsonValue]
Name = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)
]
Reason = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)
]

_WRITE_FIELDS = frozenset(
    {
        "action",
        "connectionStateFilter",
        "description",
        "destination",
        "enabled",
        "ipProtocolScope",
        "ipsecFilter",
        "loggingEnabled",
        "name",
        "reportFlowEnabled",
        "schedule",
        "source",
    }
)
_RESPONSE_FIELDS = {"id", "index", "metadata"}
_EDIT_FIELDS = {"name", "description", "enabled", "loggingEnabled"}
_REQUIRED_FIELDS = {
    "action",
    "destination",
    "enabled",
    "ipProtocolScope",
    "loggingEnabled",
    "name",
    "source",
}


class _TypedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RuleTarget(_TypedModel):
    site_id: UUID
    source_zone: UUID
    destination_zone: UUID


class PolicyScope(_TypedModel):
    targets: list[RuleTarget] = Field(min_length=1)
    protected_policy_ids: set[UUID] = Field(default_factory=set)

    def check(self, target: RuleTarget, policy_id: UUID | None) -> None:
        if target not in self.targets or policy_id in self.protected_policy_ids:
            raise UniFiApiError(
                "UNIFI_TARGET_REFUSED",
                "target is outside the configured firewall scope",
            )


class CreateRule(_TypedModel):
    source_zone: UUID
    destination_zone: UUID
    name: Name
    action: Literal["ALLOW", "BLOCK"]
    description: str = Field(default="", max_length=512)
    logging_enabled: bool = False

    def body(self) -> Rule:
        action: Rule = {"type": self.action}
        if self.action == "ALLOW":
            action["allowReturnTraffic"] = True
        return {
            "name": self.name,
            "description": self.description,
            "source": {"zoneId": str(self.source_zone)},
            "destination": {"zoneId": str(self.destination_zone)},
            "enabled": False,
            "action": action,
            "ipProtocolScope": {"ipVersion": "IPV4"},
            "loggingEnabled": self.logging_enabled,
        }


class EditRule(_TypedModel):
    name: Name | None = None
    description: str | None = Field(default=None, max_length=512)
    enabled: bool | None = None
    logging_enabled: bool | None = Field(
        default=None, serialization_alias="loggingEnabled"
    )


class RuleOrder(_TypedModel):
    beforeSystemDefined: list[UUID] = Field(max_length=2000)
    afterSystemDefined: list[UUID] = Field(max_length=2000)

    @model_validator(mode="after")
    def verify_unique(self) -> RuleOrder:
        scope = self.beforeSystemDefined + self.afterSystemDefined
        if len(scope) != len(set(scope)):
            raise ValueError("firewall ordering contains duplicate rule IDs")
        return self

    def without(self, policy_id: UUID) -> RuleOrder:
        return RuleOrder(
            beforeSystemDefined=[
                item for item in self.beforeSystemDefined if item != policy_id
            ],
            afterSystemDefined=[
                item for item in self.afterSystemDefined if item != policy_id
            ],
        )


class Proposal(_TypedModel):
    operation: Operation
    target: RuleTarget
    policy_id: UUID | None
    before: Rule | None
    after: Rule | None
    order: RuleOrder
    reason: Reason


class FirewallController:
    """Build previews and send one closed policy operation."""

    def __init__(self, api: UniFiNetworkApi, scope: PolicyScope) -> None:
        self.api = api
        self.scope = scope

    @staticmethod
    def _path(site_id: UUID, policy_id: UUID | None = None) -> str:
        path = f"/v1/sites/{site_id}/firewall/policies"
        return path if policy_id is None else f"{path}/{policy_id}"

    def rule(self, site_id: UUID, policy_id: UUID) -> Rule:
        return self.api.get(self._path(site_id, policy_id))

    def order(self, target: RuleTarget) -> RuleOrder:
        response = self.api.get(
            self._path(target.site_id) + "/ordering",
            {
                "sourceFirewallZoneId": str(target.source_zone),
                "destinationFirewallZoneId": str(target.destination_zone),
            },
        )
        return RuleOrder.model_validate(response.get("orderedFirewallPolicyIds"))

    def create_preview(self, site_id: UUID, rule: CreateRule, reason: str) -> Proposal:
        target = RuleTarget(
            site_id=site_id,
            source_zone=rule.source_zone,
            destination_zone=rule.destination_zone,
        )
        self.scope.check(target, None)
        return Proposal(
            operation="create",
            target=target,
            policy_id=None,
            before=None,
            after=rule.body(),
            order=self.order(target),
            reason=reason,
        )

    def change_preview(
        self, site_id: UUID, policy_id: UUID, reason: str, edit: EditRule | None
    ) -> Proposal:
        before = self.rule(site_id, policy_id)
        target = self._user_target(site_id, policy_id, before)
        self.scope.check(target, policy_id)
        order = self.order(target)
        if order.without(policy_id) == order:
            raise UniFiApiError(
                "UNIFI_TARGET_REFUSED",
                "policy is absent from the user-defined ordering",
            )
        if edit is None:
            return Proposal(
                operation="delete",
                target=target,
                policy_id=policy_id,
                before=before,
                after=None,
                order=order,
                reason=reason,
            )
        after = _write_body(before)
        after.update(edit.model_dump(mode="json", by_alias=True, exclude_none=True))
        if after == _write_body(before):
            raise UniFiApiError(
                "UNIFI_INPUT_INVALID", "the edit does not change a supported field"
            )
        return Proposal(
            operation="update",
            target=target,
            policy_id=policy_id,
            before=before,
            after=after,
            order=order,
            reason=reason,
        )

    @staticmethod
    def _user_target(site_id: UUID, policy_id: UUID, rule: Rule) -> RuleTarget:
        metadata = rule.get("metadata")
        source, destination = rule.get("source"), rule.get("destination")
        if (
            rule.get("id") != str(policy_id)
            or not isinstance(metadata, dict)
            or metadata.get("origin") != "USER_DEFINED"
            or rule.get("index") == 2_147_483_647
            or not isinstance(source, dict)
            or not isinstance(destination, dict)
        ):
            raise UniFiApiError(
                "UNIFI_TARGET_REFUSED",
                "only an admitted user-defined policy may change",
            )
        return RuleTarget.model_validate(
            {
                "site_id": site_id,
                "source_zone": source.get("zoneId"),
                "destination_zone": destination.get("zoneId"),
            }
        )

    def recheck(self, proposal: Proposal) -> None:
        """Check operation shape and reject changes since the identical preview."""
        self.scope.check(proposal.target, proposal.policy_id)
        if proposal.operation == "create":
            body = proposal.after or {}
            action = body.get("action")
            if (
                proposal.policy_id is not None
                or proposal.before is not None
                or not isinstance(action, dict)
            ):
                raise UniFiApiError("UNIFI_TARGET_REFUSED", "invalid create proposal")
            rule = CreateRule.model_validate(
                {
                    "source_zone": proposal.target.source_zone,
                    "destination_zone": proposal.target.destination_zone,
                    "action": action.get("type"),
                    "name": body.get("name"),
                    "description": body.get("description"),
                    "logging_enabled": body.get("loggingEnabled"),
                }
            )
            if body != rule.body():
                raise UniFiApiError(
                    "UNIFI_TARGET_REFUSED",
                    "create must match the supported disabled rule profile",
                )
        else:
            if proposal.policy_id is None or proposal.before is None:
                raise UniFiApiError(
                    "UNIFI_TARGET_REFUSED", "a current rule is required"
                )
            current = self.rule(proposal.target.site_id, proposal.policy_id)
            if (
                current != proposal.before
                or self._user_target(
                    proposal.target.site_id,
                    proposal.policy_id,
                    current,
                )
                != proposal.target
            ):
                raise UniFiApiError(
                    "UNIFI_POLICY_CHANGED", "rule changed since the approved preview"
                )
            if proposal.order.without(proposal.policy_id) == proposal.order:
                raise UniFiApiError(
                    "UNIFI_TARGET_REFUSED",
                    "approved ordering does not include the target",
                )
            if proposal.operation == "update":
                before = _write_body(current)
                after = proposal.after or {}
                fixed_fields = {
                    key: val for key, val in before.items() if key not in _EDIT_FIELDS
                }
                if {
                    key: val for key, val in after.items() if key not in _EDIT_FIELDS
                } != fixed_fields:
                    raise UniFiApiError(
                        "UNIFI_TARGET_REFUSED", "edit changes an unsupported field"
                    )
                edit = EditRule.model_validate(
                    {
                        "name": after.get("name"),
                        "description": after.get("description"),
                        "enabled": after.get("enabled"),
                        "logging_enabled": after.get("loggingEnabled"),
                    }
                )
                expected = before | edit.model_dump(
                    mode="json", by_alias=True, exclude_none=True
                )
                if after != expected or after == before:
                    raise UniFiApiError(
                        "UNIFI_TARGET_REFUSED", "edit must match its declared values"
                    )
            elif proposal.after is not None:
                raise UniFiApiError(
                    "UNIFI_TARGET_REFUSED", "delete must describe removal"
                )
        if self.order(proposal.target) != proposal.order:
            raise UniFiApiError(
                "UNIFI_POLICY_CHANGED", "rule order changed since the approved preview"
            )

    def send(self, proposal: Proposal) -> dict[str, Any]:
        method = {"create": "POST", "update": "PUT", "delete": "DELETE"}[
            proposal.operation
        ]
        return self.api._request(
            method,
            self._path(proposal.target.site_id, proposal.policy_id),
            body=proposal.after,
        )


def _write_body(rule: Rule) -> Rule:
    fields = set(rule) - _RESPONSE_FIELDS
    if fields - _WRITE_FIELDS or not _REQUIRED_FIELDS <= fields:
        raise UniFiApiError(
            "UNIFI_RULE_UNSUPPORTED",
            "controller rule is outside the supported replacement profile",
        )
    return {key: rule[key] for key in fields}


def read_back(
    controller: FirewallController,
    proposal: Proposal,
    policy_id: UUID | None,
) -> bool:
    observed_order = controller.order(proposal.target)
    if policy_id is None:
        return False
    if proposal.operation == "delete":
        if observed_order != proposal.order.without(policy_id):
            return False
        try:
            controller.rule(proposal.target.site_id, policy_id)
        except UniFiApiError as error:
            if error.code == "UNIFI_API_UNSUPPORTED":
                return True
            raise
        return False

    if proposal.operation == "create":
        if (
            observed_order.without(policy_id) != proposal.order
            or observed_order == proposal.order
        ):
            return False
    elif observed_order != proposal.order:
        return False
    observed = controller.rule(proposal.target.site_id, policy_id)
    target = controller._user_target(proposal.target.site_id, policy_id, observed)
    if target != proposal.target:
        return False
    if proposal.operation == "update":
        return _write_body(observed) == proposal.after
    return all(
        observed.get(key) == value for key, value in (proposal.after or {}).items()
    )
