/* tslint:disable */
/* eslint-disable */

export class FortressCli {
  constructor();
  execute(args: string[]): Promise<string>;
  createDatabase(name: string, template?: string, dataDir?: string): Promise<string>;
  startServer(port?: number, host?: string, dataDir?: string): Promise<string>;
  getStatus(detailed?: boolean): Promise<string>;
  listDatabases(): Promise<string>;
  getDatabaseInfo(name: string): Promise<string>;
  deleteDatabase(name: string, confirm?: boolean): Promise<string>;
  createBackup(database: string, path: string): Promise<string>;
  restoreBackup(backupPath: string, databaseName?: string): Promise<string>;
  version(): Promise<string>;
  help(command?: string): Promise<string>;
}

export function executeFortressCommand(args: string[]): Promise<string>;
export function getFortressVersion(): string;
