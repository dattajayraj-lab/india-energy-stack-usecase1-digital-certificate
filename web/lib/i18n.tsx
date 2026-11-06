"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

const en = {
  "app.name": "Energy Passport",
  "app.tagline": "Your connection. Your assets. Proven in seconds.",
  "app.intro":
    "A signed digital certificate of an electricity connection and everything behind the meter. Issued by the DISCOM, held by the consumer, checked by anyone.",
  "nav.signOut": "Sign out",
  "nav.language": "हिन्दी",
  "nav.toggleTheme": "Switch theme",
  "portal.consumer": "Consumer",
  "portal.consumer.body": "Get your Passport, choose what to reveal and share it.",
  "portal.verifier": "Verifier",
  "portal.verifier.body": "Check a Passport someone has shared with you.",
  "portal.admin": "DISCOM staff",
  "portal.admin.body": "Review records, issue and revoke Passports, see the logs.",
  "portal.open": "Open",

  "login.consumer.title": "Sign in with your consumer number",
  "login.consumer.body": "We send a one-time code to the mobile number on your connection.",
  "login.consumerNo": "Consumer number",
  "login.sendCode": "Send code",
  "login.enterCode": "Enter the 6-digit code",
  "login.verify": "Verify",
  "login.devCode": "Development code",
  "login.changeNumber": "Use a different number",
  "login.admin.title": "DISCOM staff sign-in",
  "login.username": "Username",
  "login.password": "Password",
  "login.signIn": "Sign in",

  "wallet.nav.passport": "My Passport",
  "wallet.nav.share": "Share",
  "wallet.nav.history": "Share history",
  "wallet.none.title": "You do not have a Passport yet",
  "wallet.none.body":
    "Your DISCOM will sign a Passport from the records it already holds. It is stored on this device and belongs to you.",
  "wallet.consent": "I agree to my DISCOM issuing this Passport to my wallet.",
  "wallet.get": "Get my Passport",
  "wallet.pending.title": "Your connection details changed",
  "wallet.pending.body": "Your old Passport was cancelled. Collect the updated one to keep sharing.",
  "wallet.collect": "Collect updated Passport",
  "wallet.claim.title": "This Passport is not on this device",
  "wallet.claim.body":
    "Move it here to share it. Your earlier copy is cancelled and a new one is bound to this device.",
  "wallet.claim": "Move to this device",
  "wallet.issued": "Your Passport is ready",
  "wallet.connection": "Connection",
  "wallet.meters": "Meters",
  "wallet.assets": "Assets behind the meter",
  "wallet.noAssets": "No assets on record.",
  "wallet.holder": "Passport holder",
  "wallet.issuedOn": "Issued",
  "wallet.validUntil": "Valid until",
  "wallet.version": "Version",

  "field.serviceConn": "Service connection",
  "field.tariff": "Tariff category",
  "field.load": "Sanctioned load",
  "field.status": "Status",
  "field.capacity": "Capacity",
  "field.inspection": "Inspection",
  "meter.consumption": "Consumption meter",
  "meter.generation": "Generation meter",

  "status.active": "Active",
  "status.revoked": "Revoked",
  "status.none": "None",
  "inspection.pass": "Passed",
  "inspection.fail": "Failed",
  "inspection.conditional": "Conditional",
  "inspection.none": "Not inspected",

  "share.title": "Choose what to share",
  "share.body": "Only the fields you tick leave this device. Everything else stays hidden from the verifier.",
  "share.presets": "Quick choices",
  "share.group.connection": "Connection",
  "share.group.assets": "Meters and assets",
  "share.group.personal": "About you",
  "preset.lender": "Bank or lender",
  "preset.marketplace": "Solar marketplace",
  "preset.subsidy": "Subsidy portal",
  "share.selected": "fields selected",
  "share.clear": "Clear",
  "share.continue": "Continue",
  "share.needPassport": "Get your Passport first.",
  "share.dialog.title": "Share these fields?",
  "share.verifierName": "Who is this for? (optional)",
  "share.challenge": "Verifier's challenge code (optional)",
  "share.expiry": "Link expires after",
  "share.expiry.1h": "1 hour",
  "share.expiry.1d": "1 day",
  "share.expiry.7d": "7 days",
  "share.consent": "I agree to share the fields listed above.",
  "share.create": "Create link",
  "share.ready": "Your share is ready",
  "share.readyBody": "Show this code or send the link. You can withdraw it from Share history.",
  "share.copyLink": "Copy link",
  "share.copyRaw": "Copy presentation",
  "share.rawHint": "Hand the presentation straight to the verifier and your DISCOM will not see the exchange.",
  "share.copied": "Copied",
  "share.done": "Done",

  "history.title": "Share history",
  "history.empty": "You have not shared anything yet.",
  "history.to": "Shared with",
  "history.fields": "Fields",
  "history.expires": "Expires",
  "history.opened": "Opened",
  "history.withdraw": "Withdraw",
  "history.withdrawn": "Withdrawn",
  "history.expired": "Expired",
  "history.live": "Live",
  "history.confirm.title": "Withdraw this share?",
  "history.confirm.body": "The link stops working now. Anyone who already opened it may have kept what they saw.",
  "history.unnamed": "Not named",

  "verify.title": "Verify a Passport",
  "verify.body": "The DISCOM's seal is checked against its public identity. You do not need to contact the DISCOM.",
  "verify.tab.paste": "Paste",
  "verify.tab.upload": "Upload",
  "verify.tab.scan": "Scan QR",
  "verify.pasteLabel": "Passport or share link",
  "verify.uploadLabel": "Choose a Passport file",
  "verify.scanStart": "Start camera",
  "verify.scanStop": "Stop camera",
  "verify.scanImage": "Or read a QR code from an image",
  "verify.check": "Verify",
  "verify.challenge.title": "Prove the presenter holds it",
  "verify.challenge.body":
    "Give this code to the consumer before they share. It shows the presentation was made for you, just now.",
  "verify.challenge.new": "New challenge",
  "verify.pass": "Verified",
  "verify.passNotes": "Verified, with notes",
  "verify.fail": "Not verified",
  "verify.passBody": "Issued by a registered DISCOM, intact and not revoked.",
  "verify.failBody": "Do not rely on this Passport.",
  "verify.disclosed": "What was shared",
  "verify.nothing": "No fields were shared.",
  "verify.checks": "Checks",
  "verify.issuer": "Issuer",
  "verify.linkGone": "This link has expired or was withdrawn.",
  "check.format": "Credential format",
  "check.issuer_did": "Issuer identity",
  "check.issuer_directory": "DeDi directory",
  "check.signature": "Digital seal",
  "check.disclosures": "Shared fields",
  "check.schema": "IES schema",
  "check.revocation": "Revocation",
  "check.validity": "Validity period",
  "check.holder_binding": "Holder proof",
  "checkStatus.pass": "Passed",
  "checkStatus.fail": "Failed",
  "checkStatus.warn": "Note",
  "checkStatus.skip": "Not applicable",

  "admin.nav.dashboard": "Dashboard",
  "admin.nav.consumers": "Consumers",
  "admin.nav.passports": "Passports",
  "admin.nav.logs": "Logs",
  "admin.dash.issued": "Issued",
  "admin.dash.active": "Active",
  "admin.dash.revoked": "Revoked",
  "admin.dash.verified": "Verifications passed",
  "admin.dash.failed": "failed",
  "admin.dash.pending": "awaiting collection",
  "admin.dash.trend": "Last 14 days",
  "admin.dash.chart": "Chart",
  "admin.dash.table": "Table",
  "admin.dash.day": "Day",
  "admin.dash.seriesIssued": "Passports issued",
  "admin.dash.seriesVerified": "Verifications",
  "admin.dash.reasons": "Revocation reasons",
  "admin.dash.noReasons": "Nothing revoked yet.",
  "admin.search": "Search by name, consumer or connection number",
  "admin.noResults": "No matching consumers.",
  "admin.col.consumer": "Consumer",
  "admin.col.name": "Name",
  "admin.col.connection": "Connection",
  "admin.col.tariff": "Tariff",
  "admin.col.passport": "Passport",
  "admin.col.version": "Version",
  "admin.col.binding": "Held in",
  "admin.col.issued": "Issued",
  "admin.col.status": "Status",
  "admin.review": "Review",
  "admin.preview": "Passport preview",
  "admin.preview.clean": "No data-quality issues.",
  "admin.blocker": "Blocks issue",
  "admin.warning": "Warning",
  "admin.issue": "Issue Passport",
  "admin.reissue": "Re-issue",
  "admin.revoke": "Revoke",
  "admin.issue.confirm": "The consumer has asked for this Passport and has given consent.",
  "admin.issue.note":
    "This is a bearer Passport for handover. The consumer can move it into their wallet from the consumer portal.",
  "admin.issue.done": "Passport issued",
  "admin.revoke.title": "Revoke this Passport?",
  "admin.revoke.body": "Every verifier sees this at the next check. This cannot be undone.",
  "admin.revoke.reason": "Reason",
  "admin.revoke.done": "Passport revoked",
  "admin.reissue.title": "Re-issue this Passport?",
  "admin.reissue.body": "The current version is revoked and the next version is signed from today's records.",
  "admin.cancel": "Cancel",
  "reason.meter_swap": "Meter swap",
  "reason.load_change": "Load change",
  "reason.der_change": "Asset change",
  "reason.request": "Consumer request",
  "reason.holder_rebind": "Moved to a new wallet",
  "reason.superseded": "Superseded",
  "binding.wallet": "Wallet",
  "binding.discom-did": "Handover",
  "binding.digilocker": "DigiLocker",
  "admin.filter.all": "All",
  "logs.audit": "Audit log",
  "logs.verifications": "Verification log",
  "logs.actor": "Actor",
  "logs.action": "Action",
  "logs.entity": "Record",
  "logs.time": "Time",
  "logs.ip": "Network",
  "logs.result": "Result",
  "logs.failed": "Failed checks",
  "logs.credential": "Credential",
  "logs.from": "From date",
  "logs.to": "To date",
  "logs.empty": "No entries match.",
  "logs.pass": "Pass",
  "logs.fail": "Fail",
  "logs.forbidden": "Your role cannot view the logs.",
  "pager.previous": "Previous",
  "pager.next": "Next",
  "pager.of": "of",
  "common.loading": "Loading",
} as const;

export type MessageKey = keyof typeof en;

const hi: Partial<Record<MessageKey, string>> = {
  "app.name": "ऊर्जा पासपोर्ट",
  "app.tagline": "आपका कनेक्शन। आपकी संपत्तियाँ। कुछ ही सेकंड में प्रमाणित।",
  "app.intro":
    "बिजली कनेक्शन और मीटर के पीछे की हर चीज़ का हस्ताक्षरित डिजिटल प्रमाणपत्र। डिस्कॉम जारी करता है, उपभोक्ता रखता है, कोई भी जाँच सकता है।",
  "nav.signOut": "साइन आउट",
  "nav.language": "English",
  "nav.toggleTheme": "थीम बदलें",
  "portal.consumer": "उपभोक्ता",
  "portal.consumer.body": "अपना पासपोर्ट लें, चुनें कि क्या दिखाना है और साझा करें।",
  "portal.verifier": "सत्यापनकर्ता",
  "portal.verifier.body": "आपके साथ साझा किया गया पासपोर्ट जाँचें।",
  "portal.admin": "डिस्कॉम कर्मचारी",
  "portal.admin.body": "रिकॉर्ड देखें, पासपोर्ट जारी और रद्द करें, लॉग देखें।",
  "portal.open": "खोलें",
  "login.consumer.title": "अपने उपभोक्ता नंबर से साइन इन करें",
  "login.consumer.body": "हम आपके कनेक्शन के मोबाइल नंबर पर एक बार का कोड भेजते हैं।",
  "login.consumerNo": "उपभोक्ता नंबर",
  "login.sendCode": "कोड भेजें",
  "login.enterCode": "6 अंकों का कोड दर्ज करें",
  "login.verify": "सत्यापित करें",
  "login.changeNumber": "दूसरा नंबर उपयोग करें",
  "wallet.nav.passport": "मेरा पासपोर्ट",
  "wallet.nav.share": "साझा करें",
  "wallet.nav.history": "साझा इतिहास",
  "wallet.none.title": "आपके पास अभी पासपोर्ट नहीं है",
  "wallet.none.body":
    "आपका डिस्कॉम अपने मौजूदा रिकॉर्ड से पासपोर्ट पर हस्ताक्षर करेगा। यह इस डिवाइस पर रहता है और आपका है।",
  "wallet.consent": "मैं अपने डिस्कॉम द्वारा यह पासपोर्ट मेरे वॉलेट में जारी करने के लिए सहमत हूँ।",
  "wallet.get": "मेरा पासपोर्ट प्राप्त करें",
  "wallet.pending.title": "आपके कनेक्शन का विवरण बदल गया है",
  "wallet.pending.body": "आपका पुराना पासपोर्ट रद्द हो गया। साझा करना जारी रखने के लिए नया पासपोर्ट लें।",
  "wallet.collect": "नया पासपोर्ट लें",
  "wallet.issued": "आपका पासपोर्ट तैयार है",
  "wallet.connection": "कनेक्शन",
  "wallet.meters": "मीटर",
  "wallet.assets": "मीटर के पीछे की संपत्तियाँ",
  "wallet.holder": "पासपोर्ट धारक",
  "wallet.issuedOn": "जारी",
  "wallet.validUntil": "मान्य तिथि तक",
  "field.serviceConn": "सेवा कनेक्शन",
  "field.tariff": "टैरिफ श्रेणी",
  "field.load": "स्वीकृत भार",
  "field.status": "स्थिति",
  "field.capacity": "क्षमता",
  "field.inspection": "निरीक्षण",
  "status.active": "सक्रिय",
  "status.revoked": "रद्द",
  "inspection.pass": "उत्तीर्ण",
  "inspection.fail": "अनुत्तीर्ण",
  "inspection.conditional": "सशर्त",
  "inspection.none": "निरीक्षण नहीं हुआ",
  "share.title": "चुनें कि क्या साझा करना है",
  "share.body": "केवल आपके चुने हुए फ़ील्ड इस डिवाइस से बाहर जाते हैं। बाकी सब छिपा रहता है।",
  "share.presets": "त्वरित विकल्प",
  "share.group.connection": "कनेक्शन",
  "share.group.assets": "मीटर और संपत्तियाँ",
  "share.group.personal": "आपके बारे में",
  "preset.lender": "बैंक या ऋणदाता",
  "preset.marketplace": "सोलर मार्केटप्लेस",
  "preset.subsidy": "सब्सिडी पोर्टल",
  "share.continue": "आगे बढ़ें",
  "share.consent": "मैं ऊपर दिए गए फ़ील्ड साझा करने के लिए सहमत हूँ।",
  "share.create": "लिंक बनाएँ",
  "share.ready": "आपका साझाकरण तैयार है",
  "share.copyLink": "लिंक कॉपी करें",
  "share.done": "हो गया",
  "history.title": "साझा इतिहास",
  "history.withdraw": "वापस लें",
  "verify.title": "पासपोर्ट सत्यापित करें",
  "verify.body": "डिस्कॉम की मुहर उसकी सार्वजनिक पहचान से जाँची जाती है। डिस्कॉम से संपर्क की ज़रूरत नहीं।",
  "verify.check": "सत्यापित करें",
  "verify.pass": "सत्यापित",
  "verify.fail": "सत्यापित नहीं",
  "verify.failBody": "इस पासपोर्ट पर भरोसा न करें।",
  "verify.disclosed": "क्या साझा किया गया",
};

type Locale = "en" | "hi";

interface I18n {
  locale: Locale;
  t: (key: MessageKey) => string;
  toggle: () => void;
}

const Context = createContext<I18n | null>(null);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocale] = useState<Locale>("en");

  useEffect(() => {
    try {
      if (localStorage.getItem("cep-locale") === "hi") setLocale("hi");
    } catch {
      // Storage can be blocked; English is a safe default.
    }
  }, []);

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  const toggle = useCallback(() => {
    setLocale((current) => {
      const next = current === "en" ? "hi" : "en";
      try {
        localStorage.setItem("cep-locale", next);
      } catch {
        // The choice just will not persist.
      }
      return next;
    });
  }, []);

  const value = useMemo<I18n>(
    () => ({ locale, toggle, t: (key) => (locale === "hi" ? (hi[key] ?? en[key]) : en[key]) }),
    [locale, toggle],
  );
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useI18n(): I18n {
  const context = useContext(Context);
  if (!context) throw new Error("useI18n must be inside I18nProvider");
  return context;
}

export function formatDate(value: string, locale: Locale): string {
  return new Date(value).toLocaleDateString(locale === "hi" ? "hi-IN" : "en-IN", {
    day: "numeric",
    month: "short",
    year: "numeric",
  });
}
