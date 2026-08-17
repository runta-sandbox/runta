import { randomUUID } from "node:crypto";

const accountIdPattern = /^[a-zA-Z0-9][a-zA-Z0-9_-]*$/;

export interface ExportAccountRequest {
  accountId: string;
  format: "tar.gz";
}

export interface ExportAuditEvent {
  accountId: string;
  archiveId?: string;
  outcome: "denied" | "failed" | "succeeded";
  subject: string;
}

export interface AuthenticatedPrincipal {
  subject: string;
}

export interface AccountExporterDependencies {
  getAuthenticatedPrincipal(): Promise<AuthenticatedPrincipal>;
  authorizeAccountExport(principal: AuthenticatedPrincipal, accountId: string): Promise<boolean>;
  createArchive(accountId: string, archiveId: string): Promise<void>;
  recordAuditEvent(event: ExportAuditEvent): Promise<void>;
  reportOperationalError(operation: "archive" | "audit" | "authorize", error: unknown): void;
}

export function createAccountExporter(dependencies: AccountExporterDependencies) {
  const {
    getAuthenticatedPrincipal,
    authorizeAccountExport,
    createArchive,
    recordAuditEvent,
    reportOperationalError,
  } = dependencies;

  async function audit(event: ExportAuditEvent) {
    try {
      await recordAuditEvent(event);
    } catch (error) {
      reportOperationalError("audit", error);
    }
  }

  return async function exportAccount(request: ExportAccountRequest) {
    const { accountId, format } = request;

    if (!accountIdPattern.test(accountId)) {
      throw new Error("Invalid account identifier");
    }
    if (format !== "tar.gz") {
      throw new Error("Unsupported export format");
    }
    let principal: AuthenticatedPrincipal;
    let authorized: boolean;
    try {
      principal = await getAuthenticatedPrincipal();
      authorized = await authorizeAccountExport(principal, accountId);
    } catch (error) {
      reportOperationalError("authorize", error);
      throw new Error("Account export could not be completed");
    }

    if (!authorized) {
      await audit({ accountId, outcome: "denied", subject: principal.subject });
      throw new Error("Account export is not authorized");
    }

    const archiveId = randomUUID();

    try {
      await createArchive(accountId, archiveId);
      await audit({ accountId, archiveId, outcome: "succeeded", subject: principal.subject });
      return { accountId, archiveId };
    } catch (error) {
      reportOperationalError("archive", error);
      await audit({ accountId, archiveId, outcome: "failed", subject: principal.subject });
      throw new Error("Account export could not be completed");
    }
  };
}
