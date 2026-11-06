import { expect, test, type Page } from "@playwright/test";

const ADMIN_PASSWORD = "ChangeMe-Dev-Only-1";

async function consumerLogin(page: Page, consumerNo: string) {
  await page.goto("/wallet/login");
  await page.getByLabel("Consumer number").fill(consumerNo);
  await page.getByRole("button", { name: "Send code" }).click();
  const hint = await page.getByTestId("dev-otp").textContent();
  const code = hint?.match(/\d{6}/)?.[0] ?? "";
  await page.locator("input[data-input-otp]").fill(code);
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(page).toHaveURL(/\/wallet$/);
}

async function getPassport(page: Page) {
  await page.getByText("I agree to my DISCOM").click();
  await page.getByRole("button", { name: "Get my Passport" }).click();
  await expect(page.getByText("Sanctioned load")).toBeVisible();
}

async function createShare(page: Page, preset: string, verifier = "Example Bank"): Promise<string> {
  await page.getByRole("link", { name: "Share", exact: true }).click();
  await page.getByRole("button", { name: preset }).click();
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("Who is this for?").fill(verifier);
  await page.getByText("I agree to share").click();
  await page.getByRole("button", { name: "Create link" }).click();
  const url = await page.getByTestId("share-url").inputValue();
  await page.getByRole("button", { name: "Done" }).first().click();
  return url;
}

async function adminLogin(page: Page, username = "admin") {
  await page.goto("/admin/login");
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/admin$/);
}

test("a lender sees sanctioned load and nothing else", async ({ page, context }) => {
  await consumerLogin(page, "1100000001");
  await getPassport(page);
  await expect(page.getByText("Rooftop solar")).toBeVisible();
  await expect(page.getByText("Lakshmi Naidu")).toBeVisible();
  const url = await createShare(page, "Bank or lender");

  const bank = await context.newPage();
  await bank.goto(url);
  const result = bank.getByTestId("verify-result");
  await expect(result).toContainText("Verified");
  const disclosed = bank.getByTestId("disclosed");
  await expect(disclosed).toContainText("Sanctioned load");
  await expect(disclosed).toContainText("8 kW");
  await expect(bank.locator("body")).not.toContainText("Lakshmi");
  await expect(bank.locator("body")).not.toContainText("Dwaraka");
  await expect(bank.locator("[data-check=signature]")).toHaveAttribute("data-status", "pass");
  await expect(bank.locator("[data-check=revocation]")).toHaveAttribute("data-status", "pass");
});

test("a marketplace sees solar capacity and inspection only", async ({ page, context }) => {
  await consumerLogin(page, "1100000002");
  await getPassport(page);
  const url = await createShare(page, "Solar marketplace", "Solar Market");
  const market = await context.newPage();
  await market.goto(url);
  const disclosed = market.getByTestId("disclosed");
  await expect(disclosed).toContainText("Rooftop solar: Export capacity");
  await expect(disclosed).toContainText("6 kW");
  await expect(disclosed).not.toContainText("Battery");
  await expect(market.locator("body")).not.toContainText("Rohan");
});

test("a verifier challenge proves the presenter holds the wallet key", async ({ page, context }) => {
  await consumerLogin(page, "1100000005");
  await getPassport(page);
  await page.getByRole("link", { name: "Share", exact: true }).click();

  // Asset details stay folded until the asset is chosen, and an asset alone still counts.
  await expect(page.getByText("Panel capacity")).toBeHidden();
  await page.getByText("Rooftop solar").click();
  await expect(page.getByText("Panel capacity")).toBeVisible();
  await expect(page.getByTestId("selected-count")).toContainText("1 fields");
  await expect(page.getByText("2022-05-30T")).toBeHidden();

  await page.getByRole("button", { name: "Bank or lender" }).click();
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("Verifier's challenge code").fill("chal-123");
  await page.getByText("I agree to share").click();
  await page.getByRole("button", { name: "Create link" }).click();
  const url = await page.getByTestId("share-url").inputValue();

  const bank = await context.newPage();
  await bank.goto("/verifier");
  await bank.getByLabel("Prove the presenter holds it").fill("chal-123");
  await bank.getByLabel("Passport or share link").fill(url);
  await bank.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(bank.locator("[data-check=holder_binding]")).toHaveAttribute("data-status", "pass");
  await expect(bank.getByTestId("verify-result")).toContainText("Verified");
});

test("withdrawing a share kills the link", async ({ page, context }) => {
  await consumerLogin(page, "1100000003");
  await getPassport(page);
  const url = await createShare(page, "Bank or lender", "Withdrawn Bank");
  await page.getByRole("link", { name: "Share history" }).click();
  await expect(page.getByRole("cell", { name: "Withdrawn Bank" })).toBeVisible();
  await page.getByRole("button", { name: "Withdraw" }).click();
  await page.getByRole("alertdialog").getByRole("button", { name: "Withdraw" }).click();
  await expect(page.getByText("Withdrawn", { exact: true }).first()).toBeVisible();

  const bank = await context.newPage();
  await bank.goto(url);
  await expect(bank.getByText("This link has expired or was withdrawn.")).toBeVisible();
});

test("admin sees data-quality blockers, and revocation reaches an open share", async ({ page, context }) => {
  // Lakshmi's Passport was issued to another browser in the first test, so this also covers
  // moving a Passport to a new device, which cancels the earlier copy.
  await consumerLogin(page, "1100000001");
  await page.getByRole("button", { name: "Move to this device" }).click();
  await expect(page.getByText("This Passport is not on this device")).toBeHidden();
  const url = await createShare(page, "Bank or lender", "Revocation Bank");

  const admin = await context.newPage();
  await adminLogin(admin);
  await admin.getByRole("link", { name: "Consumers" }).click();
  await admin.getByRole("button", { name: "Review 1100000004" }).click();
  await expect(admin.locator("[data-flag=MISSING_SANCTIONED_LOAD]")).toBeVisible();
  await expect(admin.locator("[data-flag=DUPLICATE_METER]")).toBeVisible();
  await expect(admin.getByRole("button", { name: "Issue Passport" })).toBeDisabled();

  await admin.getByRole("button", { name: "Review 1100000001" }).click();
  await admin.getByTestId("preview").getByRole("button", { name: "Revoke" }).click();
  await admin.getByRole("alertdialog").getByRole("button", { name: "Revoke" }).click();
  await expect(admin.getByText("Passport revoked")).toBeVisible();

  const bank = await context.newPage();
  await bank.goto(url);
  await expect(bank.getByTestId("verify-result")).toContainText("Not verified");
  await expect(bank.locator("[data-check=revocation]")).toHaveAttribute("data-status", "fail");
});

test("staff can issue, and the dashboard and logs show it", async ({ page }) => {
  await adminLogin(page, "operator");
  await page.getByRole("link", { name: "Consumers" }).click();
  await page.getByPlaceholder("Search by name").fill("Rohan");
  await expect(page.getByRole("button", { name: "Review 1100000005" })).toBeHidden();
  await expect(page.getByRole("button", { name: "Review 1100000002" })).toBeVisible();
  await page.getByPlaceholder("Search by name").fill("");

  await page.getByRole("button", { name: "Review 1100000001" }).click();
  await page.getByTestId("preview").getByRole("button", { name: "Issue Passport" }).click();
  await page.getByText("The consumer has asked for this Passport").click();
  await page.getByRole("dialog").getByRole("button", { name: "Issue Passport" }).click();
  await expect(page.getByText("Passport issued")).toBeVisible();

  await page.getByRole("link", { name: "Dashboard" }).click();
  await expect(page.getByText("Last 14 days")).toBeVisible();
  await expect(page.locator(".recharts-line-curve").first()).toBeVisible();
  await page.getByRole("tab", { name: "Table" }).click();
  await expect(page.getByRole("columnheader", { name: "Passports issued" })).toBeVisible();

  await page.getByRole("link", { name: "Passports" }).click();
  await expect(page.getByRole("cell", { name: "1100000002" }).first()).toBeVisible();

  await page.getByRole("link", { name: "Logs" }).click();
  await expect(page.getByText("Your role cannot view the logs.")).toBeVisible();
});

test("auditor can read the logs", async ({ page }) => {
  await adminLogin(page, "auditor");
  await page.getByRole("link", { name: "Logs" }).click();
  await expect(page.getByRole("cell", { name: "passport.issue" }).first()).toBeVisible();
  await page.getByRole("tab", { name: "Verification log" }).click();
  await expect(page.getByRole("cell", { name: "revocation" }).first()).toBeVisible();
});

test("a tampered presentation is rejected", async ({ page }) => {
  await page.goto("/verifier");
  const garbage = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6d2ViOmV2aWwifQ.AAAA~";
  await page.getByLabel("Passport or share link").fill(garbage);
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(page.getByTestId("verify-result")).toContainText("Not verified");
});

test("Hindi labels and dark mode work", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "हिन्दी" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("आपका कनेक्शन");
  await expect(page.locator("html")).toHaveAttribute("lang", "hi");
  await page.getByRole("button", { name: "थीम बदलें" }).click();
  await expect(page.locator("html")).toHaveClass(/dark/);
});

test("the consumer portal fits a phone", async ({ browser }) => {
  const phone = await browser.newContext({ viewport: { width: 360, height: 740 } });
  const page = await phone.newPage();
  await page.goto("/wallet/login");
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(0);
  await phone.close();
});
