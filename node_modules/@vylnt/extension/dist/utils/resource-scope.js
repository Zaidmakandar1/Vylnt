function parseUrl(value) {
    try {
        return new URL(value);
    }
    catch {
        return null;
    }
}
export function isDeveloperOwnedResource(pageUrl, resourceUrl) {
    if (typeof resourceUrl !== "string" || !resourceUrl.trim())
        return false;
    if (resourceUrl.startsWith("inline:"))
        return true;
    if (resourceUrl.startsWith("data:") || resourceUrl.startsWith("blob:"))
        return true;
    const page = parseUrl(pageUrl);
    if (!page)
        return false;
    const resolved = parseUrl(resourceUrl) ?? parseUrl(new URL(resourceUrl, pageUrl).toString());
    if (!resolved)
        return false;
    return resolved.hostname === page.hostname;
}
export function filterDeveloperOwnedFindings(pageUrl, findings) {
    if (!Array.isArray(findings))
        return [];
    return findings.filter((finding) => isDeveloperOwnedResource(pageUrl, finding.affectedResource));
}
//# sourceMappingURL=resource-scope.js.map