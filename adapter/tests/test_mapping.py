"""The adapter must produce records that hold up against the published schema."""

from __future__ import annotations

import pytest
from ies_adapter import MockFileSource, QualityFlag, SourceRecord, build_subject
from ies_adapter.mapping import DEFAULT_FIELD_MAPPING, FieldMapping, apply_transform

DOMAIN = "ies.discom.example"


@pytest.fixture
def source() -> MockFileSource:
    return MockFileSource()


def codes(flags: list[QualityFlag]) -> set[str]:
    return {flag.code for flag in flags}


def resource(subject: dict, kind: str) -> dict:
    return next(r for r in subject["customerProfile"]["energyResources"] if r["type"] == kind)


def test_visakhapatnam_consumer_from_the_use_case(source):
    result = build_subject(source.fetch("1100000001"), DOMAIN, meter_owners=source.meter_owners)
    assert result.issuable and not result.flags
    subject = result.subject
    assert subject["customerProfile"]["customerNumber"] == "1100000001"
    assert subject["customerDetails"]["serviceConnectionDate"] == "2021-03-15T00:00:00+05:30"
    assert subject["customerDetails"]["installationAddress"]["geo"]["coordinates"] == [83.305, 17.7261]
    consumption = subject["customerProfile"]["consumptionProfiles"][0]
    assert consumption["sanctionedLoad"] == {"value": 8, "unit": "kW"}
    assert consumption["meterId"] == f"did:web:{DOMAIN}:assets:meter:NM-10001"
    solar = resource(subject, "SOLAR_PV")
    assert solar["attributes"]["maxExport"] == {"value": 5, "unit": "kW"}
    assert solar["attributes"]["inspection"]["result"] == "pass"


def test_topology_der_behind_inverter_behind_meter(source):
    subject = build_subject(source.fetch("1100000001"), DOMAIN).subject
    inverter, solar = resource(subject, "INVERTER"), resource(subject, "SOLAR_PV")
    assert solar["parentResources"] == [inverter["id"]]
    assert inverter["parentResources"] == [f"did:web:{DOMAIN}:assets:meter:NM-10001"]


def test_generation_meter_links_to_the_net_meter(source):
    resources = build_subject(source.fetch("1100000001"), DOMAIN).subject["customerProfile"]["energyResources"]
    generation = next(r for r in resources if r["id"].endswith("GM-10001"))
    assert generation["parentResources"] == [f"did:web:{DOMAIN}:assets:meter:NM-10001"]


def test_empty_source_values_are_omitted_not_blank(source):
    subject = build_subject(source.fetch("1100000003"), DOMAIN).subject
    consumption = subject["customerProfile"]["consumptionProfiles"][0]
    assert "contractMaxDemand" not in consumption and "sanctionedExportLoad" not in consumption
    assert "functions" not in resource(subject, "METER")["attributes"]


def test_missing_sanctioned_load_blocks(source):
    result = build_subject(source.fetch("1100000004"), DOMAIN)
    assert "MISSING_SANCTIONED_LOAD" in codes(result.flags) and not result.issuable


def test_duplicate_meter_blocks_both_accounts(source):
    for consumer in ("1100000004", "1100000006"):
        result = build_subject(source.fetch(consumer), DOMAIN, meter_owners=source.meter_owners)
        assert "DUPLICATE_METER" in codes(result.flags) and not result.issuable


def test_uninspected_asset_warns_and_carries_no_inspection_block(source):
    result = build_subject(source.fetch("1100000005"), DOMAIN, meter_owners=source.meter_owners)
    assert codes(result.flags) == {"UNVERIFIED_ASSET"} and result.issuable
    assert "inspection" not in resource(result.subject, "SOLAR_PV")["attributes"]


def test_conditional_inspection_warns(source):
    result = build_subject(source.fetch("1100000002"), DOMAIN, meter_owners=source.meter_owners)
    assert codes(result.flags) == {"ASSET_INSPECTION_NOT_PASSED"} and result.issuable


def test_closed_connection_blocks():
    cis = {"CA_NUMBER": "1", "CONN_STATUS": "closed", "SANC_LOAD_KW": "5"}
    meters = [{"CA_NUMBER": "1", "MET_SLNO": "M", "MET_ROLE": "NET"}]
    result = build_subject(SourceRecord(cis, meters), DOMAIN)
    assert "CONNECTION_NOT_ACTIVE" in codes(result.flags)


def test_mapping_rows_are_data_a_discom_can_repoint(source):
    replacement = FieldMapping("consumptionProfiles[].tariffCategoryCode", "CIS", "PREMISES")
    custom = [replacement if m.source_column == "TARIFF_CAT" else m for m in DEFAULT_FIELD_MAPPING]
    subject = build_subject(source.fetch("1100000001"), DOMAIN, custom).subject
    assert subject["customerProfile"]["consumptionProfiles"][0]["tariffCategoryCode"] == "Commercial"


def test_no_personal_field_outside_customer_details(source):
    subject = build_subject(source.fetch("1100000001"), DOMAIN).subject
    assert "Lakshmi" not in str(subject["customerProfile"])
    assert "9000000001" not in str(subject)  # IES: no mobile number in the credential


@pytest.mark.parametrize(
    ("rule", "row", "columns", "expected"),
    [
        ("qv:kW", {"A": "5"}, "A", {"value": 5, "unit": "kW"}),
        ("qv:kWh", {"A": "5.5"}, "A", {"value": 5.5, "unit": "kWh"}),
        ("int", {"A": "12"}, "A", 12),
        ("list:|", {"A": "x|y"}, "A", ["x", "y"]),
        ("const:IN", {}, "", "IN"),
        ("passthrough", {"A": " "}, "A", None),
        ("geo_point", {"A": "1", "B": ""}, "A,B", None),
    ],
)
def test_transforms(rule, row, columns, expected):
    assert apply_transform(rule, row, columns) == expected


def test_unknown_transform_fails_loudly():
    with pytest.raises(ValueError, match="Unknown transform"):
        apply_transform("rot13", {"A": "x"}, "A")
