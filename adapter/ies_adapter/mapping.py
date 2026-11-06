"""Part-2 mapping: DISCOM source records -> ElectricityCredential v1.2 credentialSubject.

The table below IS the mapping (see IES "Build your Internal-facing Adapter", Task 1).
Rows are data, so a DISCOM re-points columns in the `field_mapping` table without code.

Target grammar for `ies_field`:
    customerProfile.x / customerDetails.x     one value per consumer, from CIS
    consumptionProfiles[].x                   one profile per connection, from CIS
    energyResources[METER].x                  repeated per MDMS meter row
    energyResources[DER].x                    repeated per inspection asset row
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from .sources import SourceRecord

IST_OFFSET = "+05:30"

# Asset-class token used in did:web:<domain>:assets:<token>:<serial>
ASSET_TOKENS = {
    "METER": "meter",
    "SOLAR_PV": "solar",
    "BESS": "bess",
    "EV_CHARGER": "ev-charger",
    "INVERTER": "inverter",
}

# DISCOM tariff code -> code carried in the credential. Kept in one place on purpose.
TARIFF_LOOKUP = {"LT1A": "LT1A", "LT2A": "LT2A", "HT2C": "HT2C"}


@dataclass(frozen=True)
class FieldMapping:
    ies_field: str
    source_system: str
    source_column: str
    transform_rule: str = "passthrough"


DEFAULT_FIELD_MAPPING: tuple[FieldMapping, ...] = (
    FieldMapping("customerProfile.customerNumber", "CIS", "CA_NUMBER"),
    FieldMapping("customerDetails.fullName", "CIS", "CUST_NAME"),
    FieldMapping("customerDetails.installationAddress.geo", "CIS", "LON,LAT", "geo_point"),
    FieldMapping("customerDetails.installationAddress.address.streetAddress", "CIS", "ADDR_LINE"),
    FieldMapping("customerDetails.installationAddress.address.addressLocality", "CIS", "CITY"),
    FieldMapping("customerDetails.installationAddress.address.addressRegion", "CIS", "STATE"),
    FieldMapping("customerDetails.installationAddress.address.postalCode", "CIS", "PINCODE"),
    FieldMapping("customerDetails.installationAddress.address.addressCountry", "CIS", "", "const:IN"),
    FieldMapping("customerDetails.serviceConnectionDate", "CIS", "CONN_DATE", "datetime_ist"),
    FieldMapping("consumptionProfiles[].sanctionedLoad", "CIS", "SANC_LOAD_KW", "qv:kW"),
    FieldMapping("consumptionProfiles[].contractMaxDemand", "CIS", "CONTRACT_DEMAND_KW", "qv:kW"),
    FieldMapping("consumptionProfiles[].sanctionedExportLoad", "CIS", "SANC_EXPORT_KW", "qv:kW"),
    FieldMapping("consumptionProfiles[].tariffCategoryCode", "CIS", "TARIFF_CAT", "tariff"),
    FieldMapping("consumptionProfiles[].premisesType", "CIS", "PREMISES"),
    FieldMapping("consumptionProfiles[].connectionType", "CIS", "PHASE"),
    FieldMapping("consumptionProfiles[].paymentMode", "CIS", "PAY_MODE"),
    FieldMapping("consumptionProfiles[].serviceStatus", "CIS", "CONN_STATUS"),
    FieldMapping("consumptionProfiles[].billingCycleDay", "CIS", "BILL_DAY", "int"),
    FieldMapping("energyResources[METER].attributes.serialNumber", "MDMS", "MET_SLNO"),
    FieldMapping("energyResources[METER].attributes.meterCapability", "MDMS", "MET_CAPABILITY"),
    FieldMapping("energyResources[METER].attributes.energyDirection", "MDMS", "MET_DIRECTION"),
    FieldMapping("energyResources[METER].attributes.functions", "MDMS", "MET_FUNCTIONS", "list:|"),
    FieldMapping("energyResources[METER].attributes.make", "MDMS", "MET_MAKE"),
    FieldMapping("energyResources[METER].attributes.model", "MDMS", "MET_MODEL"),
    FieldMapping("energyResources[METER].attributes.commissioningDate", "MDMS", "MET_INSTALL_DATE", "datetime_ist"),
    FieldMapping("energyResources[DER].attributes.make", "INSPECTION", "MAKE"),
    FieldMapping("energyResources[DER].attributes.model", "INSPECTION", "MODEL"),
    FieldMapping("energyResources[DER].attributes.serialNumber", "INSPECTION", "SERIAL_NO"),
    FieldMapping("energyResources[DER].attributes.maxExport", "INSPECTION", "CAPACITY_KW", "qv:kW"),
    FieldMapping("energyResources[DER].attributes.maxImport", "INSPECTION", "MAX_IMPORT_KW", "qv:kW"),
    FieldMapping("energyResources[DER].attributes.dcArrayCapacity", "INSPECTION", "DC_ARRAY_KW", "qv:kW"),
    FieldMapping("energyResources[DER].attributes.storageCapacity", "INSPECTION", "STORAGE_KWH", "qv:kWh"),
    FieldMapping("energyResources[DER].attributes.ratedApparentPower", "INSPECTION", "RATED_KVA", "qv:kVA"),
    FieldMapping("energyResources[DER].attributes.commissioningDate", "INSPECTION", "COMMISSION_DATE", "datetime_ist"),
    FieldMapping("energyResources[DER].attributes.inspection.date", "INSPECTION", "INSPECTED_ON"),
    FieldMapping("energyResources[DER].attributes.inspection.result", "INSPECTION", "INSPECTION_RESULT"),
    FieldMapping("energyResources[DER].attributes.inspection.inspectorId", "INSPECTION", "INSPECTOR_ID"),
)


def _number(raw: str) -> int | float:
    value = float(raw)
    return int(value) if value.is_integer() else value


def apply_transform(rule: str, row: dict[str, str], columns: str) -> Any:
    """Return the transformed value, or None when the source holds nothing."""
    if rule.startswith("const:"):
        return rule.removeprefix("const:")
    raw = [(row.get(col) or "").strip() for col in columns.split(",")]
    if not all(raw):
        return None
    value = raw[0]
    if rule == "passthrough":
        return value
    if rule == "int":
        return int(value)
    if rule.startswith("qv:"):
        return {"value": _number(value), "unit": rule.removeprefix("qv:")}
    if rule == "datetime_ist":
        return f"{value}T00:00:00{IST_OFFSET}"
    if rule == "tariff":
        return TARIFF_LOOKUP.get(value, value)
    if rule.startswith("list:"):
        return value.split(rule.removeprefix("list:"))
    if rule == "geo_point":
        return {"type": "Point", "coordinates": [float(raw[0]), float(raw[1])]}
    raise ValueError(f"Unknown transform rule: {rule}")


def _set_path(target: dict[str, Any], dotted: str, value: Any) -> None:
    *parents, leaf = dotted.split(".")
    for key in parents:
        target = target.setdefault(key, {})
    target[leaf] = value


def asset_did(domain: str, asset_type: str, serial: str) -> str:
    """did:web:<domain>:assets:<token>:<serial>. The existing serial is reused verbatim."""
    return f"did:web:{domain}:assets:{ASSET_TOKENS[asset_type]}:{serial}"


@dataclass
class QualityFlag:
    code: str
    severity: str  # "blocker" stops issuance, "warning" allows it
    field: str
    message: str


@dataclass
class MappingResult:
    subject: dict[str, Any]
    flags: list[QualityFlag] = field(default_factory=list)

    @property
    def issuable(self) -> bool:
        return not any(flag.severity == "blocker" for flag in self.flags)


def _rows_for(mappings: Iterable[FieldMapping], prefix: str) -> list[tuple[str, FieldMapping]]:
    return [(m.ies_field.removeprefix(prefix), m) for m in mappings if m.ies_field.startswith(prefix)]


def _fill(target: dict[str, Any], rows: list[tuple[str, FieldMapping]], row: dict[str, str]) -> None:
    for path, mapping in rows:
        value = apply_transform(mapping.transform_rule, row, mapping.source_column)
        if value is not None:
            _set_path(target, path, value)


def build_subject(
    record: SourceRecord,
    domain: str,
    mappings: Iterable[FieldMapping] = DEFAULT_FIELD_MAPPING,
    meter_owners: Callable[[str], list[str]] | None = None,
) -> MappingResult:
    """Map one consumer to credentialSubject (without `id` and `idRef`, set at issuance)."""
    mappings = list(mappings)
    profile: dict[str, Any] = {}
    _fill(profile, _rows_for(mappings, "customerProfile."), record.cis)
    customer_details: dict[str, Any] = {}
    _fill(customer_details, _rows_for(mappings, "customerDetails."), record.cis)
    subject: dict[str, Any] = {"customerProfile": profile, "customerDetails": customer_details}

    net_meter_id: str | None = None
    resources: list[dict[str, Any]] = []
    meter_rows = _rows_for(mappings, "energyResources[METER].")
    for meter in sorted(record.meters, key=lambda m: m["MET_ROLE"] != "NET"):
        resource: dict[str, Any] = {"id": asset_did(domain, "METER", meter["MET_SLNO"]), "type": "METER"}
        _fill(resource, meter_rows, meter)
        if meter["MET_ROLE"] == "NET":
            net_meter_id = net_meter_id or resource["id"]
        elif net_meter_id:
            resource["parentResources"] = [net_meter_id]
        resources.append(resource)

    der_rows = _rows_for(mappings, "energyResources[DER].")
    for asset in record.assets:
        asset_type = asset["ASSET_TYPE"]
        resource = {"id": asset_did(domain, asset_type, asset["ASSET_ID"]), "type": asset_type}
        _fill(resource, der_rows, asset)
        parent = asset.get("PARENT_ASSET_ID")
        if parent:
            parent_row = next((a for a in record.assets if a["ASSET_ID"] == parent), None)
            if parent_row:
                resource["parentResources"] = [asset_did(domain, parent_row["ASSET_TYPE"], parent)]
        elif net_meter_id:
            resource["parentResources"] = [net_meter_id]
        resources.append(resource)
    profile["energyResources"] = resources

    consumption: dict[str, Any] = {"meterId": net_meter_id or ""}
    _fill(consumption, _rows_for(mappings, "consumptionProfiles[]."), record.cis)
    profile["consumptionProfiles"] = [consumption]

    return MappingResult(subject=subject, flags=check_quality(record, consumption, meter_owners))


def check_quality(
    record: SourceRecord,
    consumption: dict[str, Any],
    meter_owners: Callable[[str], list[str]] | None,
) -> list[QualityFlag]:
    flags: list[QualityFlag] = []
    if "sanctionedLoad" not in consumption:
        flags.append(
            QualityFlag(
                "MISSING_SANCTIONED_LOAD",
                "blocker",
                "consumptionProfiles[].sanctionedLoad",
                "Sanctioned load is missing in CIS. Correct the source record before issuing.",
            )
        )
    if not any(m["MET_ROLE"] == "NET" for m in record.meters):
        flags.append(
            QualityFlag("NO_NET_METER", "blocker", "energyResources[METER]", "No net meter is on record in MDMS.")
        )
    if consumption.get("serviceStatus") not in (None, "active"):
        flags.append(
            QualityFlag(
                "CONNECTION_NOT_ACTIVE",
                "blocker",
                "consumptionProfiles[].serviceStatus",
                "The connection is not active.",
            )
        )
    if meter_owners:
        for meter in record.meters:
            others = [ca for ca in meter_owners(meter["MET_SLNO"]) if ca != record.cis["CA_NUMBER"]]
            if others:
                flags.append(
                    QualityFlag(
                        "DUPLICATE_METER",
                        "blocker",
                        "energyResources[METER].attributes.serialNumber",
                        f"Meter {meter['MET_SLNO']} is also mapped to another consumer account.",
                    )
                )
    for asset in record.assets:
        if not asset.get("INSPECTED_ON"):
            flags.append(
                QualityFlag(
                    "UNVERIFIED_ASSET",
                    "warning",
                    "energyResources[DER].attributes.inspection",
                    f"{asset['ASSET_TYPE']} {asset['ASSET_ID']} has no inspection record. "
                    "It will be issued without an inspection block.",
                )
            )
        elif asset.get("INSPECTION_RESULT") != "pass":
            flags.append(
                QualityFlag(
                    "ASSET_INSPECTION_NOT_PASSED",
                    "warning",
                    "energyResources[DER].attributes.inspection.result",
                    f"{asset['ASSET_TYPE']} {asset['ASSET_ID']} inspection result is "
                    f"'{asset.get('INSPECTION_RESULT')}'.",
                )
            )
    return flags
