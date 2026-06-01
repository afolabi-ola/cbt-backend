import Joi from "joi";

/**
 * Schema for restoring from an existing backup file
 * POST /api/backup-restore/restore-from-file
 */
export const restoreFromBackupFileSchema = Joi.object({
  filename: Joi.string()
    .required()
    .pattern(/^backup_[\w\-\.]+\.sql$/)
    .messages({
      "string.pattern.base":
        "Filename must be a valid backup file name (e.g., backup_2026-06-01T12-30-45-123Z.sql)",
      "any.required": "Filename is required",
    }),
});
