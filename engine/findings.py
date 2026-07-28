"""Finding extraction helpers for scanner module outputs.

This module translates structured plugin results into persisted Finding rows.
Keeping this outside the worker/scan engine preserves a clean separation between
orchestration and module-specific interpretation.
"""

_HEADER_SEVERITY = {
    "Content-Security-Policy": "medium",
    "Strict-Transport-Security": "medium",
    "X-Frame-Options": "low",
    "X-Content-Type-Options": "low",
    "Referrer-Policy": "low",
    "Permissions-Policy": "low",
    "Cross-Origin-Opener-Policy": "low",
    "Cross-Origin-Resource-Policy": "low",
}

_HEADER_RECOMMENDATION = {
    "Content-Security-Policy": "Define a CSP to restrict which sources of scripts, styles, and other resources the browser may load.",
    "Strict-Transport-Security": "Set an HSTS header so browsers only ever connect over HTTPS.",
    "X-Frame-Options": "Set X-Frame-Options (or a CSP frame-ancestors directive) to prevent clickjacking via iframes.",
    "X-Content-Type-Options": "Set X-Content-Type-Options: nosniff to stop MIME-type sniffing.",
    "Referrer-Policy": "Set a Referrer-Policy to control how much referrer data leaks to other sites.",
    "Permissions-Policy": "Set a Permissions-Policy to disable browser features the app doesn't use.",
    "Cross-Origin-Opener-Policy": "Set Cross-Origin-Opener-Policy: same-origin to isolate the browsing context from cross-origin windows.",
    "Cross-Origin-Resource-Policy": "Set Cross-Origin-Resource-Policy to control which sites can embed this resource.",
}


def _add(db, Finding, assessment_id, title, severity, description, recommendation, source):
    db.session.add(
        Finding(
            assessment_id=assessment_id,
            title=title,
            severity=severity,
            description=description,
            recommendation=recommendation,
            source_modules=source,
        )
    )


def _record_findings(db, Finding, assessment_id: int, module_name: str, output: dict) -> int:
    """v1: per-module finding extraction. Move to ai/correlation.py once more modules exist.
    Returns the number of Finding rows added, so the caller can log it."""
    before = len(db.session.new)

    if module_name == "recon":
        if output.get("server"):
            _add(db, Finding, assessment_id,
                 f"Server Version Disclosure: {output['server']}", "low",
                 f"The 'Server' header discloses: {output['server']}",
                 "Suppress or generalize the Server header in the web server config.", "recon")

        https_redirect = output.get("https_redirect") or {}
        if https_redirect.get("redirects_to_https") is False:
            _add(db, Finding, assessment_id,
                 "HTTP Not Redirected to HTTPS", "medium",
                 "The site was reachable over plain HTTP and did not redirect to HTTPS, "
                 "so traffic (including any credentials) can be sent unencrypted.",
                 "Redirect all HTTP traffic to HTTPS and consider adding HSTS.", "recon")

        tls = output.get("tls") or {}
        if tls.get("valid") and tls.get("days_remaining") is not None:
            if tls["days_remaining"] < 0:
                _add(db, Finding, assessment_id,
                     "TLS Certificate Expired", "critical",
                     f"The TLS certificate expired {abs(tls['days_remaining'])} day(s) ago "
                     f"(issuer: {tls.get('issuer', 'unknown')}).",
                     "Renew the TLS certificate immediately.", "recon")
            elif tls["days_remaining"] < 30:
                _add(db, Finding, assessment_id,
                     "TLS Certificate Expiring Soon", "medium",
                     f"The TLS certificate expires in {tls['days_remaining']} day(s) "
                     f"(issuer: {tls.get('issuer', 'unknown')}).",
                     "Renew the TLS certificate before it expires.", "recon")
        if tls.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            _add(db, Finding, assessment_id,
                 f"Outdated TLS Protocol: {tls['protocol']}", "high",
                 f"The server negotiated {tls['protocol']}, which is deprecated and has known weaknesses.",
                 "Disable TLS versions below 1.2 on the server.", "recon")

    if module_name == "headers":
        for header_name in output.get("missing", []):
            _add(db, Finding, assessment_id,
                 f"Missing Security Header: {header_name}", _HEADER_SEVERITY.get(header_name, "low"),
                 f"The response did not include a '{header_name}' header.",
                 _HEADER_RECOMMENDATION.get(header_name, f"Set the '{header_name}' header."), "headers")

        for issue in output.get("cookie_issues", []):
            _add(db, Finding, assessment_id,
                 f"Cookie Missing Security Flags: {issue['name']}", "low",
                 f"Cookie '{issue['name']}' is missing: {', '.join(issue['missing'])}.",
                 "Set HttpOnly, Secure, and SameSite on all session/auth cookies.", "headers")

        if output.get("cors_issue"):
            _add(db, Finding, assessment_id,
                 "CORS Misconfiguration", "high", output["cors_issue"],
                 "Never combine a wildcard CORS origin with Allow-Credentials: true; use an explicit origin allowlist instead.",
                 "headers")

        if output.get("csp_issues"):
            _add(db, Finding, assessment_id,
                 "Weak Content-Security-Policy", "medium",
                 "CSP is present but weakened by:\n" + "\n".join(f"- {i}" for i in output["csp_issues"]),
                 "Tighten the CSP: avoid unsafe-inline/unsafe-eval and wildcard sources; use nonces or hashes for inline scripts.",
                 "headers")

        if output.get("hsts_issues"):
            _add(db, Finding, assessment_id,
                 "Weak HSTS Policy", "low",
                 "HSTS is present but:\n" + "\n".join(f"- {i}" for i in output["hsts_issues"]),
                 "Set a long max-age (>= 6 months) and include includeSubDomains.", "headers")

    if module_name == "endpoints":
        for entry in output.get("sensitive_paths_found", []):
            _add(db, Finding, assessment_id,
                 f"Sensitive File Exposed: /{entry['path']}", "high",
                 f"'/{entry['path']}' returned a 200 response ({entry['size']} bytes) -- it should not be publicly accessible.",
                 "Remove the file from the web root or block access to it at the server/proxy level.", "endpoints")

        if output.get("api_surfaces_found"):
            _add(db, Finding, assessment_id,
                 f"API/Docs Surface Exposed: {', '.join(output['api_surfaces_found'])}", "info",
                 "Found publicly reachable API documentation or schema endpoints:\n" +
                 "\n".join(f"- /{p}" for p in output["api_surfaces_found"]),
                 "Confirm these are meant to be public; if not, restrict access. If public, ensure they don't leak internal-only operations.",
                 "endpoints")

        if output.get("directory_listing"):
            _add(db, Finding, assessment_id,
                 "Directory Listing Enabled", "medium",
                 "The server returned a directory index instead of a normal page or a 403/404.",
                 "Disable directory listing in the web server configuration.", "endpoints")

        login_forms = [f for f in output.get("forms", []) if f.get("has_password_field")]
        if login_forms:
            for f in login_forms:
                if not f.get("has_csrf_token"):
                    _add(db, Finding, assessment_id,
                         f"Missing CSRF Protection: {f['action']}", "high",
                         f"The {f.get('form_type', 'form')} at '{f['action']}' has no hidden CSRF-token-like field.",
                         "Add a per-session CSRF token to all state-changing forms and validate it server-side.",
                         "endpoints")
            auth_summary_lines = []
            for f in login_forms:
                markers = []
                if f.get("has_mfa_field"):
                    markers.append("MFA/OTP field present")
                if f.get("has_captcha"):
                    markers.append("CAPTCHA present")
                if not markers:
                    markers.append("no MFA/CAPTCHA markers detected in the HTML")
                auth_summary_lines.append(f"- {f.get('form_type', 'login')} at {f['action']}: {', '.join(markers)}")
            _add(db, Finding, assessment_id,
                 "Authentication Form(s) Detected", "info",
                 "Found {} form(s) with a password field:\n{}".format(len(login_forms), "\n".join(auth_summary_lines)),
                 "Confirm these endpoints enforce rate limiting, lockout, HTTPS-only submission, and (if absent) consider adding MFA. "
                 "Note: presence of MFA/CAPTCHA markers is inferred from static HTML only, not verified by attempting logins.",
                 "endpoints")

        if output.get("external_auth_providers"):
            _add(db, Finding, assessment_id,
                 f"Third-Party Authentication Used: {', '.join(output['external_auth_providers'])}", "info",
                 "The site delegates login to an external identity provider. CSRF/MFA on that login form "
                 "is the provider's responsibility, not this application's, so it isn't flagged as a finding here.",
                 "Confirm the OAuth 'state' parameter is validated on callback to prevent CSRF on the login flow itself.",
                 "endpoints")

        if output.get("links"):
            _add(db, Finding, assessment_id,
                 f"Application Surface Mapped: {len(output['links'])} page(s) discovered", "info",
                 "Discovered via crawl + common-path guessing:\n" + "\n".join(f"- {l}" for l in output["links"][:25]),
                 "Review the discovered surface for anything that should require authentication but doesn't.", "endpoints")

    if module_name == "fingerprint":
        technologies = output.get("technologies", [])
        if technologies:
            names = ", ".join(t["name"] for t in technologies)
            detail_lines = [
                f"- {t['name']} ({t['category']}, {t.get('confidence', 'likely')}): {'; '.join(t['evidence'])}"
                for t in technologies
            ]
            _add(db, Finding, assessment_id,
                 f"Technology Stack Identified: {names}", "info",
                 "Detected technologies:\n" + "\n".join(detail_lines),
                 "Review whether version numbers of any identified technology are outdated or publicly disclosed.",
                 "fingerprint")

    if module_name == "javascript":
        for s in output.get("secrets_found", []):
            _add(db, Finding, assessment_id,
                 f"Hardcoded Secret in Client JS: {s['type']}", s["severity"],
                 f"Found in {s['source']}: {s['masked_value']} (value masked in this report).",
                 "Remove the secret from client-side code, rotate it immediately, and move it to a server-side "
                 "environment variable or secrets manager.", "javascript")

        if output.get("exposed_source_maps"):
            _add(db, Finding, assessment_id,
                 f"Source Maps Exposed: {len(output['exposed_source_maps'])} file(s)", "low",
                 "Publicly accessible .js.map files let anyone reconstruct readable source from minified JS:\n" +
                 "\n".join(f"- {u}" for u in output["exposed_source_maps"][:10]),
                 "Exclude .map files from the production build output, or block them at the web server/CDN.",
                 "javascript")

        if output.get("internal_urls_found"):
            _add(db, Finding, assessment_id,
                 f"Internal/Staging URLs Leaked in Client JS: {len(output['internal_urls_found'])}", "medium",
                 "Client-side code references internal-looking hosts:\n" +
                 "\n".join(f"- {u}" for u in output["internal_urls_found"][:10]),
                 "Remove internal/staging URLs from code shipped to the browser; use environment-specific config injected at build/deploy time instead.",
                 "javascript")

        if output.get("risky_sinks"):
            sinks = sorted({s["sink"] for s in output["risky_sinks"]})
            _add(db, Finding, assessment_id,
                 f"Risky JS Sink(s) In Use: {', '.join(sinks)}", "info",
                 "Static analysis found calls to: " + ", ".join(sinks) +
                 ". These are legitimate sometimes, but are also common injection sinks when fed untrusted input.",
                 "Audit each call site to confirm the input isn't attacker-influenced.", "javascript")

        for lib in output.get("outdated_libraries", []):
            _add(db, Finding, assessment_id,
                 f"Outdated Library: {lib['name']} {lib['version']}", "medium",
                 f"Found in {lib['source']}. {lib['note']}",
                 f"Upgrade {lib['name']} to a current release.", "javascript")

    if module_name == "vulnerabilities":
        if output.get("dangerous_methods"):
            _add(db, Finding, assessment_id,
                 f"Dangerous HTTP Methods Enabled: {', '.join(output['dangerous_methods'])}", "medium",
                 "The OPTIONS response advertises support for these methods on the target URL.",
                 "Disable HTTP methods the application doesn't need (PUT/DELETE/TRACE/CONNECT) at the web server level.",
                 "vulnerabilities")

        for r in output.get("reflected_params", []):
            _add(db, Finding, assessment_id,
                 f"Reflected Parameter (Possible XSS): {r['param']}", "high",
                 f"Requesting {r['url']} with '{r['param']}' set to a probe value containing "
                 f"quotes/angle-brackets reflected it back unescaped in the response body.",
                 "Context-appropriately encode/escape all user input before rendering it in HTML, and consider a CSP as defense-in-depth.",
                 "vulnerabilities")

        for s in output.get("sqli_indicators", []):
            _add(db, Finding, assessment_id,
                 f"Possible SQL Injection: {s['param']}", "critical",
                 f"Appending a single quote to '{s['param']}' on {s['url']} produced a response matching "
                 f"a known database error signature.",
                 "Use parameterized queries/prepared statements everywhere; never build SQL via string concatenation.",
                 "vulnerabilities")

        for o in output.get("open_redirects", []):
            _add(db, Finding, assessment_id,
                 f"Open Redirect: {o['param']}", "medium",
                 f"Setting '{o['param']}' on {o['url']} to an external test URL caused the server to redirect there "
                 f"(Location: {o['location']}).",
                 "Validate redirect targets against an allowlist of same-site paths before issuing a redirect.",
                 "vulnerabilities")

    if module_name == "cve":
        for m in output.get("matches", []):
            _add(db, Finding, assessment_id,
                 f"Known Vulnerability: {m['id']} in {m['package']} {m['version']}", m["severity"],
                 (m.get("summary") or f"{m['package']} {m['version']} matches a known advisory ({m['id']}).")
                 + f"\n\nDetected via: {m['source_field']}",
                 f"Upgrade {m['package']} past the version(s) affected by {m['id']}.", "cve")

    if module_name == "active_scan":
        for f in output.get("nuclei_findings", []):
            _add(db, Finding, assessment_id,
                 f"[Nuclei] {f.get('name') or f.get('template_id')}", f.get("severity", "info"),
                 (f.get("description") or "") + f"\n\nTemplate: {f.get('template_id')}\nMatched at: {f.get('matched_at')}",
                 "Review the matched template's remediation guidance in Nuclei's template repository.",
                 "active_scan:nuclei")
        for f in output.get("sqlmap_findings", []):
            _add(db, Finding, assessment_id,
                 f"[sqlmap] Possible SQL Injection: {f['param']}", "critical",
                 f"sqlmap flagged parameter '{f['param']}' ({f['location']}) as injectable -- type: {f['injection_type']}.",
                 "Use parameterized queries/prepared statements everywhere; never build SQL via string concatenation.",
                 "active_scan:sqlmap")

    return len(db.session.new) - before
