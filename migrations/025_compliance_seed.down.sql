-- migrations/025_compliance_seed.down.sql
-- Removes the built-in catalog seed data inserted by 025.
-- The control_catalogs delete cascades to control_items; control_mappings
-- with org_id IS NULL are removed explicitly first to keep the operation
-- explicit (a tenant may have built mappings against the same items).

DELETE FROM governance.control_mappings
WHERE org_id IS NULL
  AND source_version IN ('OWASP Top 10 2021', 'PCI DSS 4.0', 'NIST SP 800-53 Rev. 5');

DELETE FROM governance.control_catalogs
WHERE org_id IS NULL
  AND code IN ('OWASP_TOP10_2021','PCI_DSS_4_0','NIST_800_53_R5');
