/**
 * NVD Client — queries the National Vulnerability Database for CVEs
 * associated with detected third-party JavaScript libraries.
 * Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
 */
import type { Finding } from "../types/index.js";
export interface DetectedLibrary {
    name: string;
    version: string | null;
    sourceUrl: string;
}
export interface CveEntry {
    cveId: string;
    cvssScore: number;
    description: string;
    detailUrl: string;
}
export interface NvdCache {
    get(key: string): {
        entries: CveEntry[];
        timestamp: number;
    } | undefined;
    set(key: string, value: {
        entries: CveEntry[];
        timestamp: number;
    }): void;
}
export declare class NvdClient {
    private readonly cache;
    private readonly fetchFn;
    private readonly cacheMaxAgeMs;
    constructor(cache: NvdCache, fetchFn?: typeof fetch, cacheMaxAgeMs?: number);
    checkLibrary(library: DetectedLibrary): Promise<Finding[]>;
}
export declare function detectLibraries(scripts: Array<{
    sourceUrl: string;
    content: string;
}>): DetectedLibrary[];
//# sourceMappingURL=nvd-client.d.ts.map