export interface PackageTransportSummary {
    requestCount: number;
    responseBytes: number;
    policyDigest: string;
}

export interface PackageSetupSummary {
    manager: 'pip' | 'npm' | 'bun';
    requestedSpec: string;
    installedVersion: string;
    artifactDigest?: string;
    durationMs: number;
    outcome: 'success' | 'failed';
    gatewayRequestCount: number;
    gatewayResponseBytes: number;
    policyDigest: string;
}
