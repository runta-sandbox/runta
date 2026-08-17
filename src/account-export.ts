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
}

export interface AccountExporterDependencies {
  authorizeAccountExport(accountId: string): Promise<boolean>;
  createArchive(accountId: string, archiveId: string): Promise<void>;
  recordAuditEvent(event: ExportAuditEvent): Promise<void>;
  reportOperationalError(operation: "archive" | "audit" | "authorize", error: unknown): void;
}

export function createAccountExporter(dependencies: AccountExporterDependencies) {
  const { authorizeAccountExport, createArchive, recordAuditEvent, reportOperationalError } = dependencies;

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
    let authorized: boolean;
    try {
      authorized = await authorizeAccountExport(accountId);
    } catch (error) {
      reportOperationalError("authorize", error);
      await audit({ accountId, outcome: "failed" });
      throw new Error("Account export could not be completed");
    }

    if (!authorized) {
      await audit({ accountId, outcome: "denied" });
      throw new Error("Account export is not authorized");
    }

    const archiveId = randomUUID();

    try {
      await createArchive(accountId, archiveId);
      await audit({ accountId, archiveId, outcome: "succeeded" });
      return { accountId, archiveId };
    } catch (error) {
      reportOperationalError("archive", error);
      await audit({ accountId, archiveId, outcome: "failed" });
      throw new Error("Account export could not be completed");
    }
  };
}
