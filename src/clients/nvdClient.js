// Single responsibility: query the NVD CVE API with rate-limit-aware defensive behavior.

/**
 * Input: package name and version.
 * Output: CveRecord[] simplified from NVD response data.
 */
export async function lookupCves(packageName, version) {
  // TODO: Query NVD REST API v2.0 with timeout, backoff, API-key support, and response normalization.
  void packageName;
  void version;
  return [];
}
