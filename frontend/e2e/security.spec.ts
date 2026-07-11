import { test, expect } from '@playwright/test';

test.describe('DarkShield Security Ops Dashboard E2E', () => {

  // 1. Happy Path Test Case
  test('Happy Path: Should list repositories, register a new repo, navigate to its profile, and display scanned findings', async ({ page }) => {
    // Navigate to Dashboard
    await page.goto('/');
    
    // Check main title
    await expect(page.locator('h1')).toContainText('Security Command');
    
    // Click "Add Repository" button to trigger dialog
    await page.click('button:has-text("Add Repository")');
    
    // Check that modal dialog appeared
    await expect(page.locator('h2')).toContainText('Monitor New Repository');
    
    // Input a real GitHub URL
    await page.fill('input[placeholder*="https://github.com/"]', 'https://github.com/anishxagrawal/6_lab_el');
    
    // Click Register
    await page.click('button[type="submit"]:has-text("Register Repository")');
    
    // Verify redirection to repo details page (url should match /repos/[uuid])
    await page.waitForURL(/\/repos\//);
    
    // Headings on detail page should display owner/repo name
    await expect(page.locator('h1')).toContainText('anishxagrawal/6_lab_el');
    
    // Wait for the findings card or status page
    // Since the repo "anishxagrawal/6_lab_el" was already scanned in DB, it should show score & findings
    await expect(page.locator('h2')).toContainText('Scanned Findings');
  });

  // 2. Failure Case Test Case
  test('Failure Case: Should display inline validation errors when registering an invalid GitHub repository URL', async ({ page }) => {
    // Navigate to Dashboard
    await page.goto('/');
    
    // Trigger dialog
    await page.click('button:has-text("Add Repository")');
    
    // Input a malformed/invalid URL
    await page.fill('input[placeholder*="https://github.com/"]', 'https://not-github.com/invalid/format');
    
    // Click submit
    await page.click('button[type="submit"]:has-text("Register Repository")');
    
    // Check for validation error indicator
    const errorBox = page.locator('text=Must be a valid GitHub URL');
    await expect(errorBox).toBeVisible();
  });

  // 3. Edge Case Test Case
  test('Edge Case: Standalone Verifier should flag altered/tampered payloads as invalid', async ({ page }) => {
    // Navigate to verification tool
    await page.goto('/verify');
    
    // Click Load Template to pre-populate JSON
    await page.click('button:has-text("Load Template")');
    
    // Ensure JSON payload text editor is filled
    const payloadTextarea = page.locator('textarea[placeholder*="repo_id"]');
    await expect(payloadTextarea).not.toBeEmpty();
    
    // Modify critical_findings count to simulate tampering
    const originalText = await payloadTextarea.inputValue();
    const parsed = JSON.parse(originalText);
    parsed.critical_findings = 0; // Alter findings metric
    
    await payloadTextarea.fill(JSON.stringify(parsed, null, 2));
    
    // Enter a dummy signature (since the loaded signature was empty/instructional)
    await page.fill('input[placeholder*="signature"]', '8d92a01bc93ef7d6ba8290efbc92a8301beecdf928a8d0c2eef0cd9a');
    
    // Trigger verification
    await page.click('button:has-text("Verify Report Integrity")');
    
    // Check for Tamper Detected warning alert
    const errorStatus = page.locator('p:has-text("TAMPER DETECTED")');
    await expect(errorStatus).toBeVisible();
  });
});
