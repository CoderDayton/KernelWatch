/**
 * Sidecar bridge - communicates with Python CLI backend
 */
import { Command } from '@tauri-apps/plugin-shell';

export interface DriverHash {
  sha256: string;
  sha1?: string;
  md5?: string;
  authentihash_sha256?: string;
}

export interface DriverInfo {
  name: string;
  hashes: DriverHash;
  vendor?: string;
  version?: string;
  description?: string;
  signer?: string;
  compile_time?: string;
}

export interface Vulnerability {
  vuln_type: string;
  description: string;
  cve_id?: string;
  confidence: number;
}

export interface AnalysisResult {
  driver: DriverInfo;
  vulnerabilities: Vulnerability[];
  risk_level: 'critical' | 'high' | 'medium' | 'low' | 'info';
  risk_score: number;
  in_loldrivers: boolean;
  in_ms_blocklist: boolean;
  vt_detections?: number;
  vt_total?: number;
  dangerous_imports: string[];
  notes: string[];
}

export interface DashboardStats {
  drivers: number;
  analyses: number;
  vulnerabilities: number;
  loldrivers_hashes: number;
  critical_risk: number;
}

export interface CVEEntry {
  cve_id: string;
  description: string;
  published: string;
  cvss_score?: number;
  cvss_vector?: string;
}

/**
 * Execute a kernel-watch CLI command via sidecar
 */
async function runCommand(args: string[]): Promise<string> {
  const command = Command.sidecar('binaries/kernel-watch', args);
  const output = await command.execute();
  
  if (output.code !== 0) {
    throw new Error(output.stderr || `Command failed with code ${output.code}`);
  }
  
  return output.stdout;
}

/**
 * Execute command and parse JSON output
 */
async function runJsonCommand<T>(args: string[]): Promise<T> {
  // Add --json flag for machine-readable output
  const output = await runCommand([...args, '--json']);
  return JSON.parse(output) as T;
}

/**
 * Get dashboard statistics
 */
export async function getDashboardStats(): Promise<DashboardStats> {
  try {
    return await runJsonCommand<DashboardStats>(['dashboard']);
  } catch {
    // Return zeros if not initialized
    return {
      drivers: 0,
      analyses: 0,
      vulnerabilities: 0,
      loldrivers_hashes: 0,
      critical_risk: 0,
    };
  }
}

/**
 * Analyze a driver file
 */
export async function analyzeDriver(filePath: string): Promise<AnalysisResult> {
  return await runJsonCommand<AnalysisResult>(['analyze', filePath]);
}

/**
 * Search NVD for CVEs
 */
export async function searchNVD(query: string, since?: string): Promise<CVEEntry[]> {
  const args = ['search-nvd', query];
  if (since) {
    args.push('--since', since);
  }
  return await runJsonCommand<CVEEntry[]>(args);
}

/**
 * Sync LOLDrivers database
 */
export async function syncLOLDrivers(): Promise<{ count: number }> {
  return await runJsonCommand<{ count: number }>(['sync-loldrivers']);
}

/**
 * Start monitoring sources
 */
export async function startMonitor(
  sources: string[],
  once: boolean = false
): Promise<void> {
  const args = ['monitor', '--sources', sources.join(',')];
  if (once) {
    args.push('--once');
  }
  await runCommand(args);
}

/**
 * Export driver as LOLDrivers YAML
 */
export async function exportLOLDriversYAML(hash: string): Promise<string> {
  return await runCommand(['export', 'loldrivers', '--hash', hash]);
}
