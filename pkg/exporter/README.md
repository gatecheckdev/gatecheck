# Defect Dojo API Test


## Writing a file

```shell
curl --location --request POST 'https://defectdojo.batcave.internal.cms.gov/api/v2/import-scan/' \
--header 'Authorization: Token 6dbd46fb21e8e5262e92d817d34cd7127d3854bb' \
--form 'scan_date="2022-08-23"' \
--form 'file=@"/Users/bacchus/Code/gatecheckdev/gatecheck/test/grype_python.json"' \
--form 'engagement="10"' \
--form 'scan_type="Anchore Grype"' \
--form 'auto_create_context="True"' -m 180
```

```shell
curl --location --request POST 'https://defectdojo.batcave.internal.cms.gov/api/v2/import-scan/' \
--header 'Authorization: Token 6dbd46fb21e8e5262e92d817d34cd7127d3854bb' \
--form 'product_name="Knight Light test"' \
--form 'scan_date="2022-08-23"' \
--form 'commit_hash="abc-hash-123"' \
--form 'file=@"/Users/bacchus/Code/gatecheckdev/gatecheck/test/grype_python.json"' \
--form 'engagement_name="engagement-test-1"' \
--form 'scan_type="Anchore Grype"' \
--form 'auto_create_context="True"' -m 180
```