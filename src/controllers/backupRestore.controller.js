import * as backupRestoreService from "../services/backupRestore.service.js";
import { success, error } from "../utils/response.js";

/**
 * Create a database backup
 * POST /api/backup-restore/backup
 */
export const createBackup = async (req, res, next) => {
  try {
    const backup = await backupRestoreService.createBackup();
    return success(res, "Backup created successfully", backup, 201);
  } catch (err) {
    next(err);
  }
};

/**
 * List all available backups
 * GET /api/backup-restore/list
 */
export const listBackups = async (req, res, next) => {
  try {
    const backups = await backupRestoreService.listBackups();
    return success(res, "Backups fetched successfully", { backups });
  } catch (err) {
    next(err);
  }
};

/**
 * Download backup file
 * GET /api/backup-restore/download/:filename
 */
export const downloadBackup = async (req, res, next) => {
  try {
    const { filename } = req.params;
    const backupPath = await backupRestoreService.getBackupFilePath(filename);
    res.download(backupPath, filename, (err) => {
      if (err) {
        console.error("Download error:", err);
      }
    });
  } catch (err) {
    next(err);
  }
};

/**
 * Restore database from uploaded backup file
 * POST /api/backup-restore/restore
 */
export const restoreBackup = async (req, res, next) => {
  try {
    if (!req.file) {
      return error(res, "No backup file provided", null, 400);
    }

    await backupRestoreService.restoreFromUploadedFile(req.file.path);
    return success(res, "Database restored successfully from backup");
  } catch (err) {
    next(err);
  }
};

/**
 * Restore database from existing backup file
 * POST /api/backup-restore/restore-from-file
 */
export const restoreFromBackupFile = async (req, res, next) => {
  try {
    const { filename } = req.body;
    const result = await backupRestoreService.restoreFromBackupFile(filename);
    return success(res, "Database restored successfully from backup", result);
  } catch (err) {
    next(err);
  }
};

/**
 * Delete a specific backup file
 * DELETE /api/backup-restore/:filename
 */
export const deleteBackup = async (req, res, next) => {
  try {
    const { filename } = req.params;
    await backupRestoreService.deleteBackup(filename);
    return success(res, "Backup deleted successfully");
  } catch (err) {
    next(err);
  }
};
