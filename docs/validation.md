# Validation

## Rules Order of Precedence

1. **CVE Limit**: Any Matching vulnerabilities will fail validation
2. **CVE Allowance**: Any Matching vulnerabilities will remove the CVE from subsequent rules, risk accepted
3. **KEV**: Any Matching vulnerabilities will fail validation 
4. **EPSS Allowance**: Any matching vulnerabilities that are below the risk acceptance will be removed from subsequent rules, risk accepted
5. **EPSS Limit**: Any matching vulnerabilities that exceed the limit will fail validation
6. **Severity Limit**: A count of severities that exceed the limit in any severity category will fail validation
