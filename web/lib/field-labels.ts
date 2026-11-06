/** Plain names for IES fields. Unknown fields fall back to a readable form of the key. */

const LABELS: Record<string, string> = {
  customerNumber: "Consumer number",
  idRef: "Identity reference",
  fullName: "Full name",
  installationAddress: "Installation address",
  serviceConnectionDate: "Connected since",
  meterId: "Meter reference",
  sanctionedLoad: "Sanctioned load",
  sanctionedExportLoad: "Sanctioned export limit",
  contractMaxDemand: "Contract demand",
  tariffCategoryCode: "Tariff category",
  premisesType: "Premises type",
  connectionType: "Connection type",
  paymentMode: "Payment mode",
  serviceStatus: "Service status",
  billingCycleDay: "Billing day",
  METER: "Meter",
  SOLAR_PV: "Rooftop solar",
  BESS: "Battery",
  EV_CHARGER: "EV charger",
  INVERTER: "Inverter",
  maxExport: "Export capacity",
  maxImport: "Import capacity",
  storageCapacity: "Storage capacity",
  dcArrayCapacity: "Panel capacity",
  ratedApparentPower: "Rated power",
  inspection: "Inspection",
  commissioningDate: "Commissioned on",
  serialNumber: "Serial number",
  make: "Make",
  model: "Model",
  meterCapability: "Meter type",
  energyDirection: "Energy direction",
  functions: "Meter functions",
  parentResources: "Connected to",
};

const ORDER = Object.keys(LABELS);

/** Display order. Signed digests are sorted by hash, which means nothing to a person. */
export function fieldRank(name: string): number {
  const index = ORDER.indexOf(name);
  return index === -1 ? ORDER.length : index;
}

export function fieldLabel(name: string): string {
  return LABELS[name] ?? name.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/^./, (c) => c.toUpperCase());
}
